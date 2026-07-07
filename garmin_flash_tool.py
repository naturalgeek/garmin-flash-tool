#!/usr/bin/env python3
"""
garmin-flash-tool -- multi-function native-Linux recovery tool for Garmin handhelds.

Talks Garmin's USB protocol (GUSB) to the device's PREBOOT programming interface
(VID 0x091E, PID 0x0003 -- the loader that comes up when you power on holding D-pad Up
with USB connected). No Windows / no Updater.exe needed.

  ####################################################################################
  #  MUST BE RUN AS ROOT (sudo) -- raw USB needs it.  Default action is read-only.    #
  #  Writes only the MAIN region; BOOT/ramloader/u-boot/x-loader are refused (except  #
  #  in the raw --cli console, which is gated behind --i-accept-the-risk).            #
  ####################################################################################

Actions (choose one; default --info):
  --info                identify the device + show a dry-run plan (read-only)
  --flash-main          write the MAIN firmware region (the recovery flash)
  --erase-main          erase MAIN and stop (destructive test; device won't boot)
  --cli                 open the raw bootloader console (DANGEROUS; needs --i-accept-the-risk)

Flash source (for --flash-main / --info dry-run) -- give EITHER:
  --image main.bin      a raw MAIN-region image, OR
  --gcd firmware.gcd    a full .gcd (the MAIN region is auto-detected + extracted; the tool
                        refuses if that region is encrypted, as on newer Garmin devices)

Examples:
  sudo python garmin_flash_tool.py --info
  sudo python garmin_flash_tool.py --flash-main --gcd GPSMAP276Cx_590.gcd
  sudo python garmin_flash_tool.py --flash-main --image main_0x02BD.bin
  sudo python garmin_flash_tool.py --erase-main
  sudo python garmin_flash_tool.py --cli --i-accept-the-risk

Tested ONLY on the GPSMAP 276Cx (HWID 2479). No USB reboot exists on these loaders --
after a flash you must power-cycle the unit manually (battery pull).
"""
import argparse, struct, sys, time, hashlib, os, math, shlex

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

MAIN_REGION_DEFAULT = 0x000E   # 14 = fw_all.bin (MAIN). The only region --flash-main writes.
FORBIDDEN_REGIONS = {0x0008, 8, 12, 5, 43}   # BOOT/ramloader/u-boot/x-loader: never via --flash-main.
GCD_MAIN_RECORD = 0x02BD       # GCD record type for the MAIN region.

DEVICE_PROFILES = {
    2479: {   # 0x09AF
        "name": "GPSMAP 276Cx",
        "main_region": 0x000E,   # 14
        "main_size": 18322432,
        "sha1_prefix": "d2d0f35f75d3",   # stock 5.90 MAIN
        "tested": True,
    },
}

# region names/danger for the --cli console
REGION_NAMES = {5: "u-boot bootloader", 8: "GCD-BOOT record type", 12: "BOOT / boot.bin ramloader",
                14: "MAIN (fw_all.bin)", 41: "nonvol / settings (NFM)", 43: "x-loader", 127: "second main-data"}
DANGER_REGIONS = {5: "u-boot -- ERASE = PERMANENT BRICK", 43: "x-loader -- ERASE = PERMANENT BRICK",
                  12: "BOOT/ramloader -- recovery escape hatch (do NOT flash)", 8: "GCD-BOOT record type"}

# ------------------------------------------------------------------ framing helpers
def build_header(pid, size, layer=LAYER_APP):
    return struct.pack("<B3xH2xI", layer, pid, size)

def build_frame(pid, payload=b"", layer=LAYER_APP):
    return build_header(pid, len(payload), layer) + payload

def parse_header(buf):
    return struct.unpack_from("<B3xH2xI", buf, 0)  # (layer, pid, size)

def hexs(b):
    return " ".join("%02x" % x for x in b)

# ------------------------------------------------------------------ safety guard
def assert_main_only(region_id):
    if region_id in FORBIDDEN_REGIONS:
        sys.exit("REFUSING: region id %r is BOOT/ramloader/u-boot/x-loader class. --flash-main is MAIN only." % (region_id,))
    if region_id != MAIN_REGION_DEFAULT:
        sys.exit("REFUSING: region id 0x%04x is not MAIN (0x%04x)." % (region_id, MAIN_REGION_DEFAULT))

# ------------------------------------------------------------------ image source (bin or gcd) + checks
def _shannon_entropy(blob, sample=1 << 20):
    """Bits/byte over a sample. Plaintext ARM+strings ~6-6.5; encrypted/compressed ~7.9-8.0."""
    b = blob[:sample] if len(blob) > sample else blob
    if not b:
        return 0.0
    n = len(b)
    ent = 0.0
    for c in (b.count(i) for i in range(256)):
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent

def extract_main_from_gcd(path, allow_unverified=False):
    """Extract the MAIN firmware region from ANY Garmin .gcd -- the MAIN record type is NOT
    hardcoded. Pick the record type with the largest total body size (that's the app region),
    then PROVE it's plaintext firmware via the UTF-16LE 'Software Version' marker. If the region
    is encrypted/compressed (newer devices) the proof fails: exit with an informative error --
    UNLESS allow_unverified (--force-gcd-region), in which case return the size-guessed largest
    region anyway (it is still byte-for-byte flashable; the device decrypts at boot)."""
    d = open(path, "rb").read()
    if d[:8] != b"GARMINd\x00":
        sys.exit("[gcd] not a GARMINd GCD file: %s" % path)
    off, n, groups = 8, len(d), {}   # type -> [count, size, bytearray(bodies)]
    while off + 4 <= n:
        typ, ln = struct.unpack_from("<HH", d, off)
        off += 4
        if typ == 0xFFFF:
            break
        g = groups.setdefault(typ, [0, 0, bytearray()])
        g[0] += 1; g[1] += ln; g[2] += d[off:off + ln]
        off += ln
    if not groups:
        sys.exit("[gcd] no records found in %s" % path)
    ranked = sorted(groups.items(), key=lambda kv: kv[1][1], reverse=True)
    print("[gcd] region types: " + "  ".join("0x%04X(x%d,%dB)" % (t, g[0], g[1]) for t, g in ranked))
    rtype, g = ranked[0]
    blob = bytes(g[2])
    print("[gcd] MAIN candidate: type 0x%04X  x%d records = %d bytes" % (rtype, g[0], len(blob)))
    # proof: plaintext firmware carries a UTF-16LE "Software Version" marker, preceded by {hwid,ver}
    i = blob.find("Software Version".encode("utf-16-le"))
    if i >= 4:
        hwid, ver = struct.unpack_from("<HH", blob, i - 4)
        print("[gcd] verified plaintext firmware: HWID %d (0x%04x) version %d (%.2f), sum%%256=%d"
              % (hwid, hwid, ver, ver / 100.0, sum(blob) % 256))
        return blob
    # no plaintext marker -> can't verify. Encrypted/compressed vs unknown-format, told apart by entropy.
    ent = _shannon_entropy(blob)
    enc = ent >= 7.5
    kind = "appears ENCRYPTED/COMPRESSED" if enc else "is an UNRECOGNIZED format"
    if allow_unverified:
        print("[gcd] WARNING: largest region 0x%04X %s (entropy %.2f, no 'Software Version' marker,\n"
              "  sum%%256=%d) -- CANNOT verify it is MAIN. Using it anyway (--force-gcd-region):\n"
              "  it is MAIN by SIZE ONLY. An encrypted region is still byte-for-byte flashable (the\n"
              "  device decrypts at boot), BUT if this is not the 276Cx family the loader region index\n"
              "  (%d) may be WRONG for your device -- verify it before flashing."
              % (rtype, kind, ent, sum(blob) % 256, MAIN_REGION_DEFAULT))
        return blob
    if enc:
        sys.exit("[gcd] REFUSING: the MAIN region in this .gcd is NOT plaintext firmware -- it %s\n"
                 "  (entropy %.2f bits/byte, no 'Software Version' marker, sum%%256=%d). Newer Garmin\n"
                 "  devices (e.g. Montana 7x0) encrypt firmware regions. It is still byte-for-byte\n"
                 "  flashable to the correct device+region; if you know what you are doing, re-run with\n"
                 "  --force-gcd-region to use the largest region by size. Otherwise aborting." % (kind, ent, sum(blob) % 256))
    sys.exit("[gcd] REFUSING: could not verify a MAIN firmware region (no 'Software Version' marker in\n"
             "  the largest region 0x%04X; entropy %.2f bits/byte). Re-run with --force-gcd-region to\n"
             "  use the largest region by size regardless." % (rtype, ent))

def check_image(data, profile, skip_hash, allow_unverified=False):
    problems = []
    if (sum(data) % 256) != 0:
        msg = "region checksum invalid: sum(bytes)%%256=%d (plaintext Garmin MAIN must be 0)" % (sum(data) % 256)
        if allow_unverified:
            print("[image] NOTE: %s -- ignored (--force-gcd-region; expected for encrypted firmware)" % msg)
        else:
            problems.append(msg)
    if profile and not allow_unverified:
        if len(data) != profile["main_size"]:
            problems.append("size %d != %s MAIN size %d" % (len(data), profile["name"], profile["main_size"]))
        sha1 = hashlib.sha1(data).hexdigest()
        if (not skip_hash) and profile.get("sha1_prefix") and not sha1.startswith(profile["sha1_prefix"]):
            problems.append("sha1 %s... != known %s image (%s...); pass --skip-image-hash to override"
                            % (sha1[:12], profile["name"], profile["sha1_prefix"]))
    return problems

def image_version(data):
    """Read the {u16 hwid}{u16 version} blob baked into a MAIN image -- it sits immediately
    before the UTF-16 'Software Version' string. Returns (hwid, version) or (None, None)."""
    marker = "Software Version".encode("utf-16-le")
    i = data.find(marker)
    if i >= 4:
        try:
            return struct.unpack_from("<HH", data, i - 4)
        except Exception:
            pass
    return None, None

def load_flash_source(args, profile):
    """Return (data_bytes, problems). Source is --gcd (extract MAIN) or --image (raw bin)."""
    if args.gcd:
        if not os.path.exists(args.gcd):
            return None, ["gcd file not found: %r" % args.gcd]
        print("[src] extracting MAIN region from GCD (auto-detected): %s" % args.gcd)
        data = extract_main_from_gcd(args.gcd, allow_unverified=args.force_gcd_region)
    else:
        if not args.image or not os.path.exists(args.image):
            return None, ["MAIN image not found: %r  (or pass --gcd FILE.gcd)" % args.image]
        print("[src] MAIN image: %s" % args.image)
        data = open(args.image, "rb").read()
    print("[src] length=%d  sum%%256=%d  sha1=%s" % (len(data), sum(data) % 256, hashlib.sha1(data).hexdigest()[:16]))
    return data, check_image(data, profile, args.skip_image_hash, allow_unverified=args.force_gcd_region)

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
        t0, last = time.time(), 0.0
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
                print("[product] HWID=%d (0x%04x)  loader_version=%d (%.2f)  %s  "
                      "[note: this is the BOOT loader's baked version, not the flashed MAIN]"
                      % (prod, prod, ver, ver / 100.0, name))
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
    off, idx, t0 = 0, 0, time.time()
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
    print("      sudo python garmin_flash_tool.py --flash-main --gcd <stock.gcd>")
    return True

# ------------------------------------------------------------------ raw bootloader console (--cli)
CLI_HELP = """commands (region/size/offset accept 0x.. or decimal):
  info                         device endpoints + open state
  session                      Start Session -> unit id
  product                      product request -> HWID, loader version, name
  regions                      list known region ids + roles
  status <region>              0x4a status {u16 region} -> {u16 status}  (0 = ready/erased)
  announce <region> <size>     0x4b announce {u16 region,u32 size}   *** ERASES the region ***
  data <offset> <hex|@file>    0x24 one data packet body = [u32 offset][bytes]
  write <region> <file>        full write: announce -> wait status 0 -> stream 250B+offset -> commit
  commit <region>              0x2d commit {u16 region}
  checksum <region> <size>     0x3a4 GetRgnChecksum (preboot loader usually doesn't implement)
  send <layer> <id> [hex]      send an arbitrary GUSB packet (layer 0=transport, 20=app)
  recv [timeout_ms]            read one reply frame
  reset                        libusb bus reset (re-enumerate; does NOT reboot the device)
  help / quit
DANGER: announce/erase/write to regions 5/8/12/43 require an extra typed confirmation.
MAIN = region 14. There is no USB reboot -- power-cycle (battery pull) after a write."""

def _rgn(tok): return int(tok, 0)

def _parse_bytes(tok):
    return open(tok[1:], "rb").read() if tok.startswith("@") else bytes.fromhex(tok.replace(" ", ""))

def _confirm_danger(region, action):
    if region in DANGER_REGIONS:
        print("  !! region %d (0x%02x) = %s" % (region, region, DANGER_REGIONS[region]))
        want = "CONFIRM-%d" % region
        if input("  %s a DANGER region. Type '%s' to proceed: " % (action, want)).strip() != want:
            print("  aborted.")
            return False
    return True

def _cli_write(link, region, path):
    data = open(path, "rb").read()
    size = len(data)
    if not _confirm_danger(region, "WRITE"):
        return
    print("[write] announce region %d size %d (erases it)" % (region, size))
    link.send(PID_ANNOUNCE, struct.pack("<HI", region, size))
    link.send(PID_STATUS, struct.pack("<H", region))
    pid, layer, st = link.recv(timeout=90000)
    rstat = struct.unpack_from("<H", st, 0)[0] if st and len(st) >= 2 else None
    print("[write] erase-ready status=%r" % rstat)
    if rstat != 0:
        print("[write] not ready -> abort")
        return
    off, idx, t0 = 0, 0, time.time()
    while off < size:
        chunk = data[off:off + CHUNK]
        link.ep_out.write(build_frame(PID_DATA, struct.pack("<I", off) + chunk), timeout=5000)
        off += len(chunk)
        idx += 1
        if idx % 5000 == 0 or off >= size:
            print("[write] %d / %d" % (off, size))
    link.send(PID_COMMIT, struct.pack("<H", region))
    print("[write] commit sent (%.1fs). Power-cycle the device to boot." % (time.time() - t0))

def cli_repl(link):
    print(CLI_HELP)
    while True:
        try:
            line = input("gbl> ").strip()
        except EOFError:
            print()
            break
        if not line:
            continue
        try:
            parts = shlex.split(line)
        except ValueError as e:
            print("parse error: %s" % e)
            continue
        cmd, a = parts[0].lower(), parts[1:]
        try:
            if cmd in ("quit", "exit"):
                break
            elif cmd == "help":
                print(CLI_HELP)
            elif cmd == "info":
                print("open: OUT=0x%02x  INT-IN=0x%02x  BULK-IN=0x%02x" % (
                    link.ep_out.bEndpointAddress if link.ep_out else 0,
                    link.ep_int_in.bEndpointAddress if link.ep_int_in else 0,
                    link.ep_bulk_in.bEndpointAddress if link.ep_bulk_in else 0))
            elif cmd == "regions":
                for r, n in sorted(REGION_NAMES.items()):
                    print("  %3d (0x%02x)  %s%s" % (r, r, n, "   [DANGER]" if r in DANGER_REGIONS else ""))
            elif cmd == "session":
                link.start_session()
            elif cmd == "product":
                link.product_request()
            elif cmd == "status":
                link.send(PID_STATUS, struct.pack("<H", _rgn(a[0])))
                pid, layer, st = link.recv()
                print("status=%r" % (struct.unpack_from("<H", st, 0)[0] if st and len(st) >= 2 else None))
            elif cmd == "announce":
                region, size = _rgn(a[0]), int(a[1], 0)
                if not _confirm_danger(region, "ANNOUNCE/ERASE"):
                    continue
                print("(announce ERASES region %d)" % region)
                link.send(PID_ANNOUNCE, struct.pack("<HI", region, size))
            elif cmd == "data":
                off, payload = int(a[0], 0), _parse_bytes(a[1])
                link.ep_out.write(build_frame(PID_DATA, struct.pack("<I", off) + payload), timeout=5000)
                print("sent 0x24 offset=%d len=%d" % (off, len(payload)))
            elif cmd == "write":
                _cli_write(link, _rgn(a[0]), a[1])
            elif cmd == "commit":
                link.send(PID_COMMIT, struct.pack("<H", _rgn(a[0])))
            elif cmd == "checksum":
                link.send(PID_CRC_RQST, struct.pack("<HI", _rgn(a[0]), int(a[1], 0)))
                link.recv(timeout=6000)
            elif cmd == "send":
                layer, pid = int(a[0], 0), int(a[1], 0)
                payload = _parse_bytes(a[2]) if len(a) > 2 else b""
                link.ep_out.write(build_frame(pid, payload, layer), timeout=5000)
                print("sent layer=%d id=0x%02x len=%d" % (layer, pid, len(payload)))
            elif cmd == "recv":
                link.recv(timeout=int(a[0], 0) if a else 6000)
            elif cmd == "reset":
                link.dev.reset()
                print("dev.reset() issued (re-enumerates; does NOT reboot the device).")
            else:
                print("unknown command: %s  (type 'help')" % cmd)
        except IndexError:
            print("missing argument(s) -- type 'help'")
        except Exception as e:
            print("error: %s" % e)

# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(
        description="garmin-flash-tool: multi-function Garmin recovery tool. Read-only by default; "
                    "run as root (sudo).")
    action = ap.add_mutually_exclusive_group()
    action.add_argument("--info", action="store_true",
                        help="read-only: identify the device + dry-run plan (default if no action)")
    action.add_argument("--flash-main", "--CONFIRM-FLASH", dest="flash_main", action="store_true",
                        help="write the MAIN firmware region (the recovery flash; destructive)")
    action.add_argument("--erase-main", dest="erase_main", action="store_true",
                        help="DESTRUCTIVE TEST: erase MAIN and stop (device won't boot until re-flashed)")
    action.add_argument("--cli", action="store_true",
                        help="open the RAW bootloader console (DANGEROUS; requires --i-accept-the-risk)")
    # flash source (exactly one required for --flash-main; no default)
    ap.add_argument("--image", help="raw MAIN-region image for --flash-main (mutually exclusive with --gcd)")
    ap.add_argument("--gcd", help="a full .gcd for --flash-main; the MAIN region is auto-detected and "
                                  "extracted (refuses if that region is encrypted)")
    # modifiers
    ap.add_argument("--allow-unknown-device", action="store_true",
                    help="permit flashing a HWID with no built-in profile (region 14, generic checks only)")
    ap.add_argument("--skip-image-hash", action="store_true",
                    help="skip the known-image SHA-1 match (still enforces size + checksum)")
    ap.add_argument("--force-version", action="store_true",
                    help="allow --flash-main even if the MAIN image version differs from the device's "
                         "bootloader version (normally refused, since a mismatch can cause issues)")
    ap.add_argument("--force-gcd-region", action="store_true",
                    help="with --gcd: flash the LARGEST region even if it can't be verified as plaintext "
                         "MAIN (e.g. encrypted firmware). DANGEROUS: identified by SIZE only, and the "
                         "loader region index may be wrong on non-276Cx devices. Relaxes checksum/hash checks.")
    ap.add_argument("--wait-timeout", type=int, default=0, metavar="SEC",
                    help="seconds to wait for the device in preboot (0 = wait forever, default)")
    ap.add_argument("--i-accept-the-risk", dest="accept_risk", action="store_true",
                    help="required for --cli: acknowledge it can permanently brick the device")
    args = ap.parse_args()

    # all actions here talk raw USB to the preboot loader -> must be root.
    if os.geteuid() != 0:
        sys.exit("[perm] this must be run as root. Re-run with sudo, e.g.:\n"
                 "    sudo %s %s" % (sys.executable, " ".join(sys.argv)))

    if args.cli and not args.accept_risk:
        sys.exit("REFUSING: --cli opens a RAW bootloader console that can PERMANENTLY brick the\n"
                 "device (erasing region 5/43 is unrecoverable; region 12 is BOOT). Re-run with:\n"
                 "    sudo %s %s --i-accept-the-risk" % (sys.executable, " ".join(sys.argv)))

    # --image and --gcd are mutually exclusive, and exactly one is REQUIRED to flash.
    if args.image and args.gcd:
        sys.exit("REFUSING: pass EITHER --image OR --gcd, not both.")
    if args.flash_main and not (args.image or args.gcd):
        sys.exit("REFUSING: --flash-main needs a flash source. Pass one (no default):\n"
                 "    --gcd FILE.gcd     (extract the MAIN region from a full .gcd), or\n"
                 "    --image main.bin   (a raw MAIN-region image)")

    print("=== garmin-flash-tool ===")
    action_name = ("cli (RAW CONSOLE)" if args.cli else "flash-main (WRITE)" if args.flash_main
                   else "erase-main (ERASE)" if args.erase_main else "info (read-only)")
    print("action: %s" % action_name)
    if args.cli:
        print("!!! DANGER: raw loader access. Erasing region 5/43 = PERMANENT brick; never flash 12=BOOT.")

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
        if args.cli:
            cli_repl(link)
            return

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

        if args.erase_main:
            size = profile["main_size"] if profile else None
            if size is None:
                sys.exit("--erase-main needs a known device profile for the region size (HWID %r unknown)." % hwid)
            do_erase(link, region, size)
            return

        data, problems = (None, [])
        if args.image or args.gcd:
            data, problems = load_flash_source(args, profile)
            for p in problems:
                print("[image] PROBLEM: %s" % p)

        if not args.flash_main:   # info / default (read-only)
            if data is not None:
                dry_run_plan(region, len(data))
            else:
                print("[info] no flash source given (--gcd/--image) — skipping dry-run plan.")
            print("[info] comms OK. Read-only — no data written.")
            print("[info] to flash: sudo python garmin_flash_tool.py --flash-main --gcd <stock.gcd>"
                  + ("" if profile else " --allow-unknown-device"))
            return

        # --flash-main
        if data is None:
            sys.exit("REFUSING: flash source could not be loaded (see above). Use --image or --gcd.")
        if problems:
            sys.exit("REFUSING to flash: image checks failed (see above).")
        if not profile and not args.allow_unknown_device:
            sys.exit("REFUSING: HWID %r has no tested profile. Re-run with --allow-unknown-device "
                     "ONLY if you are sure region 14 = MAIN for your model." % hwid)
        # version safety: the MAIN image should match the device's bootloader version. Garmin
        # flashes BOOT+MAIN together; a MAIN-only flash of a different version can cause issues.
        img_hwid, img_ver = image_version(data)
        if img_ver is not None and ver is not None:
            if img_ver != ver:
                m = ("MAIN image version %d (%.2f) != device bootloader version %d (%.2f)"
                     % (img_ver, img_ver / 100.0, ver, ver / 100.0))
                if not args.force_version:
                    sys.exit("REFUSING: %s.\n  A MAIN-only flash whose version differs from the "
                             "bootloader can cause issues (they are normally flashed together).\n"
                             "  Re-run with --force-version to override." % m)
                print("[flash] WARNING: %s — proceeding due to --force-version." % m)
            else:
                print("[flash] version check OK: MAIN %d matches bootloader %d." % (img_ver, ver))
        else:
            print("[flash] version check skipped (no version readable from image and/or loader).")
        assert_main_only(region)
        do_flash(link, region, data)
    finally:
        link.close()

if __name__ == "__main__":
    main()
