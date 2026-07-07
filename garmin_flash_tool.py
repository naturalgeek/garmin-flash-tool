#!/usr/bin/env python3
"""
garmin-flash-tool -- native Linux recovery flasher for soft-bricked Garmin handhelds.

Reflashes the MAIN firmware region over Garmin's USB protocol (GUSB) via the device's
PREBOOT programming interface (VID 0x091E, PID 0x0003 -- the loader that comes up when you
power on holding D-pad Up with USB connected). Also backs up on-device user data (GPX) from
the normal mass-storage volume. No Windows / no Updater.exe needed.

  ####################################################################################
  #  MUST BE RUN AS ROOT (sudo) for the USB/flash operations -- raw USB needs it.     #
  #  READ-ONLY / DRY-RUN by default; sends NO write/erase unless --CONFIRM-FLASH.     #
  #  Only ever writes the MAIN region; BOOT/ramloader/u-boot/x-loader are refused.    #
  ####################################################################################

Tested ONLY on the GPSMAP 276Cx (HWID 2479). Other models are untested (see DEVICE_PROFILES
and --allow-unknown-device). No USB reboot exists on these loaders -- after a flash you must
power-cycle the unit manually (battery pull).

  sudo python garmin_flash_tool.py                      # read-only self-test + dry-run
  sudo python garmin_flash_tool.py --CONFIRM-FLASH      # write MAIN (human-gated)
  python garmin_flash_tool.py --backup-userdata ./bak   # copy /Garmin/GPX from mass storage (no root/preboot)
"""
import argparse, struct, sys, time, hashlib, os, math

# ------------------------------------------------------------------ USB / protocol constants
VID          = 0x091E
PID_PREBOOT  = 0x0003

LAYER_APP        = 20
LAYER_TRANSPORT  = 0

PID_DATA_AVAIL      = 0x02
PID_START_SESSION   = 0x05
PID_SESSION_STARTED = 0x06
PID_PRODUCT_RQST    = 0xfe
PID_PRODUCT_DATA    = 0xff

PID_ANNOUNCE = 0x4b
PID_STATUS   = 0x4a
PID_DATA     = 0x24
PID_COMMIT   = 0x2d
PID_CRC_RQST = 0x3a4
PID_CRC_REPL = 0x3a9

CHUNK = 250

MAIN_REGION_DEFAULT = 0x000E   # 14 = fw_all.bin (MAIN). The ONLY region kind this tool writes.
FORBIDDEN_REGIONS = {0x0008, 8, 12, 5, 43}   # BOOT/ramloader/u-boot/x-loader: NEVER touch.

DEVICE_PROFILES = {
    2479: {   # 0x09AF
        "name": "GPSMAP 276Cx",
        "main_region": 0x000E,   # 14
        "main_size": 18322432,
        "sha1_prefix": "d2d0f35f75d3",   # stock 5.90 MAIN
        "tested": True,
    },
}

# ------------------------------------------------------------------ framing helpers
def build_header(pid, size, layer=LAYER_APP):
    return struct.pack("<B3xH2xI", layer, pid, size)

def build_frame(pid, payload=b"", layer=LAYER_APP):
    return build_header(pid, len(payload), layer) + payload

def parse_header(buf):
    layer, pid, size = struct.unpack_from("<B3xH2xI", buf, 0)
    return layer, pid, size

def hexs(b):
    return " ".join("%02x" % x for x in b)

# ------------------------------------------------------------------ safety guard
def assert_main_only(region_id):
    if region_id in FORBIDDEN_REGIONS:
        sys.exit("REFUSING: region id %r is BOOT/ramloader/u-boot/x-loader class. HARD RULE: MAIN only." % (region_id,))
    if region_id != MAIN_REGION_DEFAULT:
        sys.exit("REFUSING: region id 0x%04x is not MAIN (0x%04x)." % (region_id, MAIN_REGION_DEFAULT))

# ------------------------------------------------------------------ image
def load_and_check_image(path, profile, skip_hash):
    if not path or not os.path.exists(path):
        return None, ["image file not found: %r" % path]
    data = open(path, "rb").read()
    sha1 = hashlib.sha1(data).hexdigest()
    problems = []
    if (sum(data) % 256) != 0:
        problems.append("region checksum invalid: sum(bytes)%%256=%d (Garmin MAIN must be 0)" % (sum(data) % 256))
    if profile:
        if len(data) != profile["main_size"]:
            problems.append("size %d != %s MAIN size %d" % (len(data), profile["name"], profile["main_size"]))
        if (not skip_hash) and profile.get("sha1_prefix") and not sha1.startswith(profile["sha1_prefix"]):
            problems.append("sha1 %s... != known %s image (%s...); pass --skip-image-hash to override"
                            % (sha1[:12], profile["name"], profile["sha1_prefix"]))
    print("[image] %s" % path)
    print("        length=%d  sum%%256=%d  sha1=%s" % (len(data), sum(data) % 256, sha1[:16]))
    return data, problems

# ------------------------------------------------------------------ USB layer
class Link:
    def __init__(self):
        import usb.core, usb.util
        self.usb = usb.core
        self.util = usb.util
        self.dev = None
        self.ep_in = None
        self.ep_int_in = None
        self.ep_bulk_in = None
        self.ep_out = None
        self.intf = None
        self._detached = False

    def open(self):
        self.dev = self.usb.find(idVendor=VID, idProduct=PID_PREBOOT)
        if self.dev is None:
            return False
        try:
            self.dev.set_configuration()
        except Exception as e:
            print("[usb] set_configuration warning: %s" % e)
        cfg = self.dev.get_active_configuration()
        self.intf = cfg[(0, 0)]
        ino = self.intf.bInterfaceNumber
        try:
            if self.dev.is_kernel_driver_active(ino):
                self.dev.detach_kernel_driver(ino)
                self._detached = True
                print("[usb] detached kernel driver on interface %d" % ino)
        except Exception as e:
            print("[usb] kernel-driver check: %s" % e)
        try:
            self.util.claim_interface(self.dev, ino)
        except Exception as e:
            print("[usb] claim_interface warning: %s" % e)
        for ep in self.intf:
            etype = self.util.endpoint_type(ep.bmAttributes)
            edir = self.util.endpoint_direction(ep.bEndpointAddress)
            if edir == self.util.ENDPOINT_OUT:
                self.ep_out = ep
            elif etype == self.util.ENDPOINT_TYPE_INTR:
                self.ep_int_in = ep
            elif etype == self.util.ENDPOINT_TYPE_BULK:
                self.ep_bulk_in = ep
        self.ep_in = self.ep_int_in or self.ep_bulk_in
        print("[usb] interface %d: OUT=0x%02x  INT-IN=0x%02x  BULK-IN=0x%02x" % (
            ino,
            self.ep_out.bEndpointAddress if self.ep_out else 0,
            self.ep_int_in.bEndpointAddress if self.ep_int_in else 0,
            self.ep_bulk_in.bEndpointAddress if self.ep_bulk_in else 0))
        return self.ep_in is not None and self.ep_out is not None

    def wait_open(self, timeout=0):
        """Poll for the preboot device (091e:0003) until it appears, then open it.
        timeout <= 0 waits indefinitely (Ctrl-C to abort)."""
        t0 = time.time()
        last = 0.0
        while True:
            if self.usb.find(idVendor=VID, idProduct=PID_PREBOOT) is not None:
                print("[wait] device present at 091e:0003 — opening.")
                return self.open()
            now = time.time()
            if now - last > 10:
                print("[wait] waiting for device at 091e:0003 — enter preboot: power off, "
                      "connect USB, hold D-pad Up ... (%ds)" % int(now - t0))
                last = now
            if timeout > 0 and (now - t0) >= timeout:
                return False
            time.sleep(0.5)

    def _read_frame_ep(self, ep, timeout_ms):
        deadline = time.time() + (timeout_ms / 1000.0)
        raw = b""
        while time.time() < deadline:
            try:
                chunk = bytes(ep.read(ep.wMaxPacketSize or 64, timeout=1500))
            except Exception as e:
                if "timed out" in str(e).lower() or "110" in str(e):
                    continue
                raise
            if len(chunk) == 0:
                continue
            raw = chunk
            break
        if len(raw) < 12:
            return None, None, raw
        layer, pid, size = parse_header(raw)
        payload = raw[12:12 + size]
        while len(payload) < size and time.time() < deadline:
            try:
                more = bytes(ep.read(ep.wMaxPacketSize or 64, timeout=1500))
            except Exception:
                break
            if not more:
                continue
            payload += more
        return layer, pid, payload

    def read_reply(self, timeout_ms):
        layer, pid, payload = self._read_frame_ep(self.ep_int_in, timeout_ms)
        if pid == PID_DATA_AVAIL:
            layer, pid, payload = self._read_frame_ep(self.ep_bulk_in, timeout_ms)
        return layer, pid, payload

    def start_session(self, tries=3):
        for t in range(tries):
            print("[session] TX Start_Session (attempt %d)" % (t + 1))
            try:
                self.ep_out.write(build_frame(PID_START_SESSION, b"", layer=LAYER_TRANSPORT), timeout=3000)
            except Exception as e:
                print("[session] write failed: %s" % e)
            for _ in range(8):
                try:
                    layer, pid, payload = self._read_frame_ep(self.ep_int_in, 3000)
                except Exception as e:
                    print("[session] (no reply: %s)" % e)
                    break
                if pid is None:
                    continue
                if pid == PID_SESSION_STARTED:
                    uid = struct.unpack_from("<I", payload, 0)[0] if len(payload) >= 4 else None
                    print("[session] SESSION STARTED. unit id = %s" % (uid,))
                    return uid if uid is not None else True
        return None

    def product_request(self):
        print("[product] TX Product_Rqst")
        try:
            self.ep_out.write(build_frame(PID_PRODUCT_RQST, b"", layer=LAYER_APP), timeout=3000)
            layer, pid, payload = self.read_reply(4000)
            if pid is not None and len(payload) >= 4:
                prod, ver = struct.unpack_from("<HH", payload, 0)
                name = payload[4:].split(b"\x00")[0].decode("latin-1", "replace") if len(payload) > 4 else ""
                print("[product] HWID=%d (0x%04x)  sw_version=%d (%.2f)  %s" % (prod, prod, ver, ver / 100.0, name))
                return prod, ver, name
        except Exception as e:
            print("[product] no product reply: %s" % e)
        return None, None, None

    def send(self, pid, payload=b"", layer=LAYER_APP):
        print("[TX] id=0x%02x layer=%d size=%d" % (pid, layer, len(payload)))
        self.ep_out.write(build_frame(pid, payload, layer), timeout=5000)

    def recv(self, timeout=6000):
        try:
            layer, pid, payload = self.read_reply(timeout)
        except Exception as e:
            print("[RX] error: %s" % e)
            return None, None, None
        if pid is None:
            return None, None, payload
        print("[RX] id=0x%02x layer=%s size=%d payload=%s" % (
            pid, layer, len(payload), hexs(payload[:32]) + (" ..." if len(payload) > 32 else "")))
        return pid, layer, payload

    def close(self):
        try:
            if self.intf is not None:
                self.util.release_interface(self.dev, self.intf.bInterfaceNumber)
        except Exception:
            pass
        try:
            if self._detached:
                self.dev.attach_kernel_driver(self.intf.bInterfaceNumber)
        except Exception:
            pass

# ------------------------------------------------------------------ dry-run plan
def dry_run_plan(region, size):
    nchunks = math.ceil(size / CHUNK)
    last = size - (nchunks - 1) * CHUNK
    ann = struct.pack("<HI", region, size)
    print("\n===== DRY-RUN PLAN =====")
    print("region id (MAIN)  : 0x%04x (%d)" % (region, region))
    print("image size        : %d bytes" % size)
    print("0x24 data chunks  : %d  (last %d B, each body = [u32 offset][<=250 data])" % (nchunks, last))
    print("0x4b announce      : header %s  payload %s" % (hexs(build_header(PID_ANNOUNCE, len(ann))), hexs(ann)))
    print("========================\n")
    return nchunks

# ------------------------------------------------------------------ flash / erase
def do_flash(link, region, data):
    assert_main_only(region)
    size = len(data)
    if not link.start_session():
        sys.exit("REFUSING: could not Start Session before flash.")
    link.send(PID_ANNOUNCE, struct.pack("<HI", region, size))
    print("[flash] announced region 0x%04x; waiting for erase-ready status (10-90s)..." % region)
    link.send(PID_STATUS, struct.pack("<H", region))
    pid, layer, st = link.recv(timeout=90000)
    rstat = struct.unpack_from("<H", st, 0)[0] if st and len(st) >= 2 else None
    print("[flash] erase-ready: id=%r status=%r" % (pid, rstat))
    if pid is None or not st:
        sys.exit("REFUSING to stream: no erase-ready reply. Re-run to retry.")
    if rstat != 0:
        sys.exit("ABORTING before stream: erase-ready status=%r (nonzero = loader rejected region "
                 "0x%04x). Nothing streamed." % (rstat, region))
    print("[flash] erase-ready OK. streaming...")
    off = 0
    idx = 0
    t0 = time.time()
    while off < size:
        chunk = data[off:off + CHUNK]
        link.ep_out.write(build_frame(PID_DATA, struct.pack("<I", off) + chunk), timeout=5000)
        off += len(chunk)
        idx += 1
        if idx % 5000 == 0 or off >= size:
            print("[flash] %d bytes / %d" % (off, size))
    link.send(PID_COMMIT, struct.pack("<H", region))
    print("[flash] commit sent. streamed+committed in %.1fs" % (time.time() - t0))
    print("\n===== FLASH COMPLETE — MAIN region 0x%04x written =====" % region)
    print("  >>> NOW POWER-CYCLE THE DEVICE to boot the new firmware. <<<")
    print("  There is NO USB reboot on this loader. If the power button is unresponsive in the")
    print("  loader, briefly remove the battery, then power on normally (no keys).")
    return True

def do_erase(link, region, size):
    assert_main_only(region)
    if not link.start_session():
        sys.exit("REFUSING: could not Start Session before erase.")
    print("[erase] announcing region 0x%04x with size %d -- this ERASES the region..." % (region, size))
    link.send(PID_ANNOUNCE, struct.pack("<HI", region, size))
    link.send(PID_STATUS, struct.pack("<H", region))
    pid, layer, st = link.recv(timeout=90000)
    rstat = struct.unpack_from("<H", st, 0)[0] if st and len(st) >= 2 else None
    print("[erase] erase-ready status: id=%r status=%r" % (pid, rstat))
    if pid is None or rstat != 0:
        sys.exit("erase NOT confirmed (status=%r). Region may be unchanged." % rstat)
    print("\n===== MAIN REGION 0x%04x ERASED (no data written) =====" % region)
    print("  The device will NOT boot now -- expect 'System Software Missing'. RECOVER with:")
    print("      sudo python garmin_flash_tool.py --CONFIRM-FLASH")
    return True

# ------------------------------------------------------------------ user-data backup (mass storage; no root/preboot)
def find_garmin_volume(explicit):
    import glob
    if explicit:
        return explicit if os.path.isdir(os.path.join(explicit, "Garmin")) else None
    user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "*"
    pats = ["/media/%s/*" % user, "/media/*/*", "/run/media/%s/*" % user, "/run/media/*/*",
            "/mnt/*", "/Volumes/*"]
    seen = []
    for p in pats:
        for c in glob.glob(p):
            if c not in seen:
                seen.append(c)
    for c in seen:
        if os.path.isdir(os.path.join(c, "Garmin", "GPX")) or os.path.isdir(os.path.join(c, "Garmin")):
            return c
    return None

def do_backup_userdata(dest, volume):
    import shutil
    vol = find_garmin_volume(volume)
    if not vol:
        sys.exit("Could not find a mounted Garmin volume with a /Garmin folder.\n"
                 "Boot the device normally, connect USB so it mounts as mass storage, then re-run\n"
                 "(or pass --volume /path/to/GARMIN).")
    src = os.path.join(vol, "Garmin")
    print("[backup] Garmin volume: %s" % vol)
    os.makedirs(dest, exist_ok=True)
    copied = []
    gpx = os.path.join(src, "GPX")
    if os.path.isdir(gpx):
        shutil.copytree(gpx, os.path.join(dest, "GPX"), dirs_exist_ok=True)
        copied.append("GPX (waypoints/routes/tracks/contacts)")
    for f in ("GarminDevice.xml", "Device.fit"):
        p = os.path.join(src, f)
        if os.path.isfile(p):
            shutil.copy2(p, dest)
            copied.append(f)
    if not copied:
        sys.exit("[backup] nothing to copy -- no /Garmin/GPX found under %s" % src)
    print("[backup] copied to %s:" % dest)
    for c in copied:
        print("   - %s" % c)
    print("[backup] done. (Settings/calibration live in NFM flash, not on this volume -- not backed up.)")

# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description="garmin-flash-tool: MAIN-region USB recovery flasher (read-only by default)")
    ap.add_argument("--image", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "main_0x02BD.bin"),
                    help="MAIN region image to flash (extract from YOUR device's stock .gcd/.rgn)")
    ap.add_argument("--CONFIRM-FLASH", dest="confirm", action="store_true",
                    help="actually write MAIN (human-gated). Without this: read-only + dry-run.")
    ap.add_argument("--allow-unknown-device", action="store_true",
                    help="permit flashing a HWID with no built-in profile (region 14, generic checks only)")
    ap.add_argument("--skip-image-hash", action="store_true",
                    help="skip the known-image SHA-1 match (still enforces size + checksum)")
    ap.add_argument("--ERASE-ONLY", dest="erase_only", action="store_true",
                    help="DESTRUCTIVE TEST: erase MAIN and stop (no write). Requires --CONFIRM-FLASH.")
    ap.add_argument("--wait-timeout", type=int, default=0, metavar="SEC",
                    help="seconds to wait for the device in preboot (0 = wait forever, default)")
    ap.add_argument("--backup-userdata", metavar="DIR",
                    help="copy /Garmin/GPX (waypoints/routes/tracks) from the mounted mass-storage "
                         "volume to DIR. Does NOT need root or preboot; device booted normally.")
    ap.add_argument("--volume", metavar="PATH", help="explicit path to the mounted GARMIN volume (for --backup-userdata)")
    args = ap.parse_args()

    # user-data backup is a plain filesystem copy from the mass-storage volume -> no root/preboot.
    if args.backup_userdata is not None:
        do_backup_userdata(args.backup_userdata, args.volume)
        return

    # everything below talks raw USB to the preboot loader -> must be root.
    if os.geteuid() != 0:
        sys.exit("[perm] this must be run as root. Re-run with sudo, e.g.:\n"
                 "    sudo %s %s" % (sys.executable, " ".join(sys.argv)))

    print("=== garmin-flash-tool ===")
    print("mode: %s" % ("LIVE FLASH (--CONFIRM-FLASH)" if args.confirm else "READ-ONLY / DRY-RUN"))

    try:
        link = Link()
    except Exception as e:
        sys.exit("[usb] pyusb unavailable: %s" % e)
    try:
        opened = link.wait_open(args.wait_timeout)
    except KeyboardInterrupt:
        sys.exit("\n[wait] cancelled.")
    except Exception as e:
        opened = False
        print("[usb] open failed: %s" % e)
    if not opened:
        sys.exit("[device] not found at 091e:0003 within %ds." % args.wait_timeout)

    try:
        if not link.start_session():
            sys.exit("Start Session failed -> comms not established (are you in preboot?).")
        hwid, ver, name = link.product_request()

        profile = DEVICE_PROFILES.get(hwid)
        if profile:
            region = profile["main_region"]
            print("[device] recognized HWID %d = %s (%s)" % (hwid, profile["name"], "TESTED" if profile.get("tested") else "UNTESTED"))
        else:
            region = MAIN_REGION_DEFAULT
            print("[device] HWID %r has NO built-in profile. MAIN=region 14 assumed (UNCONFIRMED for this model)." % hwid)

        if args.erase_only:
            if not args.confirm:
                sys.exit("REFUSING: --ERASE-ONLY is destructive; also pass --CONFIRM-FLASH.")
            size = profile["main_size"] if profile else None
            if size is None:
                sys.exit("--ERASE-ONLY needs a known device profile for the region size (HWID %r unknown)." % hwid)
            do_erase(link, region, size)
            return

        data, problems = load_and_check_image(args.image, profile, args.skip_image_hash)
        for p in problems:
            print("[image] PROBLEM: %s" % p)

        if not args.confirm:
            if data is not None:
                dry_run_plan(region, len(data))
            print("[selftest] comms OK. Read-only complete — no data written.")
            print("[selftest] to flash: sudo python garmin_flash_tool.py --CONFIRM-FLASH"
                  + ("" if profile else " --allow-unknown-device"))
            return

        if data is None:
            sys.exit("REFUSING: image could not be loaded/verified.")
        if problems:
            sys.exit("REFUSING to flash: image checks failed (see above).")
        if not profile and not args.allow_unknown_device:
            sys.exit("REFUSING: HWID %r has no tested profile. Re-run with --allow-unknown-device "
                     "ONLY if you are sure region 14 = MAIN for your model." % hwid)
        assert_main_only(region)
        do_flash(link, region, data)
    finally:
        link.close()

if __name__ == "__main__":
    main()
