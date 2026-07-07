#!/usr/bin/env python3
"""
bootloader-cli -- interactive console for the Garmin preboot loader (USB 091e:0003).

Manually issue the raw GUSB bootloader commands that flash_main.py automates: Start Session,
product query, region announce/erase, data chunks, commit, checksum, arbitrary packets, and a
bus reset. For low-level experimentation and recovery work.

  ###############################################################################
  #  DANGER: RAW bootloader access. Wrong commands can PERMANENTLY brick the     #
  #  device. Erasing region 5 (u-boot) or 43 (x-loader) is UNRECOVERABLE; region #
  #  12 is BOOT, your recovery escape hatch. Startup REQUIRES --i-accept-the-risk#
  ###############################################################################

  python bootloader_cli.py --i-accept-the-risk       # auto-elevates via sudo (no udev rule)
  sudo python bootloader_cli.py --i-accept-the-risk --no-sudo

Reuses the protocol layer from flash_main.py (must sit alongside it).
"""
import argparse, os, sys, struct, shlex, time

import garmin_flash_tool as fm   # reuse the proven Link + GUSB protocol constants/helpers

REGION_NAMES = {
    5:  "u-boot bootloader",
    8:  "GCD-BOOT record type",
    12: "BOOT / boot.bin ramloader",
    14: "MAIN (fw_all.bin)",
    41: "nonvol / settings (XOR)",
    43: "x-loader",
    127: "second main-data",
}
# Regions where a write/erase is catastrophic or violates the never-flash-BOOT rule.
DANGER_REGIONS = {
    5:  "u-boot -- ERASE = PERMANENT BRICK",
    43: "x-loader -- ERASE = PERMANENT BRICK",
    12: "BOOT/ramloader -- your recovery escape hatch (do NOT flash)",
    8:  "GCD-BOOT record type",
}

HELP = """commands (region/size/offset accept 0x.. or decimal):
  info                         device endpoints + open state
  session                      Start Session (transport L0) -> unit id
  product                      product request -> HWID, sw version, name
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
notes: MAIN = region 14. announce/erase/write to 5/8/12/43 require an extra typed confirmation.
       There is no USB reboot -- power-cycle (battery pull) after a write to boot new firmware.
"""


def rgn(tok):
    return int(tok, 0)


def parse_bytes(tok):
    if tok.startswith("@"):
        return open(tok[1:], "rb").read()
    return bytes.fromhex(tok.replace(" ", ""))


def confirm_danger(region, action):
    if region in DANGER_REGIONS:
        print("  !! region %d (0x%02x) = %s" % (region, region, DANGER_REGIONS[region]))
        want = "CONFIRM-%d" % region
        got = input("  %s a DANGER region. Type '%s' to proceed (anything else aborts): "
                    % (action, want)).strip()
        if got != want:
            print("  aborted.")
            return False
    return True


def do_write(link, region, path):
    data = open(path, "rb").read()
    size = len(data)
    if not confirm_danger(region, "WRITE"):
        return
    print("[write] announce region %d (0x%02x) size %d -- this erases it" % (region, region, size))
    link.send(fm.PID_ANNOUNCE, struct.pack("<HI", region, size))
    link.send(fm.PID_STATUS, struct.pack("<H", region))
    pid, layer, st = link.recv(timeout=90000)
    rstat = struct.unpack_from("<H", st, 0)[0] if st and len(st) >= 2 else None
    print("[write] erase-ready status=%r" % rstat)
    if rstat != 0:
        print("[write] not ready (status %r) -> aborting stream." % rstat)
        return
    off = 0
    idx = 0
    t0 = time.time()
    while off < size:
        chunk = data[off:off + fm.CHUNK]
        link.ep_out.write(fm.build_frame(fm.PID_DATA, struct.pack("<I", off) + chunk), timeout=5000)
        off += len(chunk)
        idx += 1
        if idx % 5000 == 0 or off >= size:
            print("[write] %d / %d bytes" % (off, size))
    link.send(fm.PID_COMMIT, struct.pack("<H", region))
    print("[write] commit sent (%.1fs). POWER-CYCLE the device (battery pull) to boot." % (time.time() - t0))


def repl(link):
    print(HELP)
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
                print(HELP)
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
                region = rgn(a[0])
                link.send(fm.PID_STATUS, struct.pack("<H", region))
                pid, layer, st = link.recv()
                print("status=%r" % (struct.unpack_from("<H", st, 0)[0] if st and len(st) >= 2 else None))
            elif cmd == "announce":
                region, size = rgn(a[0]), int(a[1], 0)
                if not confirm_danger(region, "ANNOUNCE/ERASE"):
                    continue
                print("(announce ERASES region %d)" % region)
                link.send(fm.PID_ANNOUNCE, struct.pack("<HI", region, size))
            elif cmd == "data":
                off, payload = int(a[0], 0), parse_bytes(a[1])
                link.ep_out.write(fm.build_frame(fm.PID_DATA, struct.pack("<I", off) + payload), timeout=5000)
                print("sent 0x24 offset=%d len=%d" % (off, len(payload)))
            elif cmd == "write":
                do_write(link, rgn(a[0]), a[1])
            elif cmd == "commit":
                link.send(fm.PID_COMMIT, struct.pack("<H", rgn(a[0])))
            elif cmd == "checksum":
                region, size = rgn(a[0]), int(a[1], 0)
                link.send(fm.PID_CRC_RQST, struct.pack("<HI", region, size))
                link.recv(timeout=6000)
            elif cmd == "send":
                layer, pid = int(a[0], 0), int(a[1], 0)
                payload = parse_bytes(a[2]) if len(a) > 2 else b""
                link.ep_out.write(fm.build_frame(pid, payload, layer), timeout=5000)
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


def main():
    ap = argparse.ArgumentParser(description="Interactive Garmin preboot bootloader console (DANGEROUS)")
    ap.add_argument("--i-accept-the-risk", dest="accept", action="store_true",
                    help="REQUIRED to start; you acknowledge this can permanently brick the device")
    ap.add_argument("--wait-timeout", type=int, default=0, metavar="SEC",
                    help="seconds to wait for the device in preboot (0 = wait forever, default)")
    args = ap.parse_args()

    if not args.accept:
        sys.exit("REFUSING TO START.\n"
                 "bootloader-cli is a RAW loader console that can PERMANENTLY brick the device\n"
                 "(erasing region 5/43 is unrecoverable). Re-run with --i-accept-the-risk if you\n"
                 "understand and accept the risk.")

    if os.geteuid() != 0:
        sys.exit("[perm] this must be run as root. Re-run with sudo, e.g.:\n"
                 "    sudo %s %s" % (sys.executable, " ".join(sys.argv)))

    print("=== Garmin preboot bootloader console ===")
    print("!!! DANGER: raw loader access. Erasing region 5/43 = PERMANENT brick; never flash 12=BOOT.")
    try:
        link = fm.Link()
    except Exception as e:
        sys.exit("pyusb unavailable: %s" % e)
    try:
        ok = link.wait_open(args.wait_timeout)
    except KeyboardInterrupt:
        sys.exit("\n[wait] cancelled.")
    if not ok:
        sys.exit("device not found at 091e:0003 within %ds." % args.wait_timeout)
    try:
        repl(link)
    finally:
        link.close()


if __name__ == "__main__":
    main()
