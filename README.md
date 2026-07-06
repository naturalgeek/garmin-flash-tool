# garmin-flasher

A native **Linux** tool to reflash the **MAIN firmware region** of a soft-bricked
Garmin handheld over Garmin's USB protocol (GUSB), using the device's **preboot
programming interface** (`091e:0003`) — the low-level loader that comes up when the
device will no longer boot its normal firmware. **No Windows and no Garmin `Updater.exe`
required.**

When a device only enumerates in loader/preboot mode (because a previous flash left a
bad MAIN region), this tool streams a known-good MAIN image back onto it over USB.

> ✅ **Confirmed working:** used to recover a real GPSMAP 276Cx that had been
> soft-bricked by a bad MAIN write — from Linux, over USB, without touching the BOOT
> region. See "Field notes" below.

---

> ## ⚠️ SCOPE / TESTED-ON — READ THIS FIRST
>
> **Only the Garmin GPSMAP 276Cx (HWID 2479) is TESTED.** The tool auto-detects the
> device HWID and looks it up in a small profile table; other models can be added, but
> are **untested**. The GUSB protocol and the `MAIN = region 14` convention are believed
> to be common across **proprietary-OS, unencrypted** Garmin handhelds (GPSMAP
> 62/64/66/78/276, Astro, Montana, eTrex 10, Rino, older nüvi), **not** encrypted units
> (Fenix 5+/MARQ) or Android/Linux-based devices.
>
> Flashing the wrong image, or assuming region 14 = MAIN on an unverified model, can
> **brick your device**. **Use entirely at your own risk.** See the disclaimer.

---

## Two region numbers — don't confuse them

Recovery uses **two different numbering schemes** for the same MAIN firmware:

| Context | MAIN identifier | Used for |
|---|---|---|
| **GCD file** record type | `0x02BD` | **Extracting** the MAIN bytes from a stock `.gcd` |
| **Preboot loader protocol** region id | **`14` (`0x000E`)** | The `0x4b` **announce** sent over USB |

You *extract* the image using GCD record type `0x02BD`, but the flasher *announces* it to
the loader as region **14**. Announcing `0x02BD` (701) to the preboot loader is rejected
as an invalid region (status `11`). The tool uses region **14**.

## What it does and does not touch

- ✅ Flashes **only** the MAIN application region — loader region id **`14` (`0x000E`)**,
  a.k.a. `fw_all.bin`.
- ⛔ **Hard-refuses** the BOOT / ramloader and low-level loader regions: `12`
  (`boot.bin` ramloader), `8` / `0x0008` (GCD BOOT record type), `5` (u-boot), `43`
  (x-loader). BOOT is the device's recovery escape hatch — if it is intact you can
  always re-enter preboot mode. This tool will **never** write those, by design.

### Safety design

- **Read-only by default.** With no arguments, `flash_main.py` opens the device, runs a
  read-only self-test (Start Session + product query), prints the detected model and a
  dry-run plan, and **sends no write or erase frames.** Only `--CONFIRM-FLASH` writes.
- **MAIN only.** The write path aborts unless the region id is exactly `14`, and rejects
  the BOOT-class ids above.
- **Auto-detects the device** via the product-request reply (HWID + firmware version)
  and looks it up in `DEVICE_PROFILES`. A **recognized, tested** HWID (currently only
  2479) flashes normally. An **unrecognized** HWID requires the explicit
  `--allow-unknown-device` flag (and only generic checks apply).
- **Aborts before streaming if the loader rejects the region.** After the `0x4b`
  announce it waits for an **erase-ready status `0`**; any non-zero status → abort before
  a single data byte is sent (so a wrong region never half-writes/hangs the device).
- **Image verification before any write:**
  - **additive checksum** `sum(bytes) % 256 == 0` (Garmin MAIN region invariant) — always;
  - for a **known profile**, the exact **size** and a **SHA-1 prefix** of the known-good
    image (276Cx: 18322432 bytes, sha1 `d2d0f35f75d3…`). `--skip-image-hash` overrides the
    hash check but still enforces size + checksum.

## How the protocol works

- **Preboot interface**: `091e:0003` (vendor `0x091E`, product `0x0003`).
- **Three endpoints**: bulk **OUT `0x01`** (host→device), interrupt **IN `0x82`**
  (device→host protocol replies/ACKs), bulk **IN `0x83`** (device→host bulk data).
- **GUSB packet header** (12 bytes, little-endian):

  ```
  [u8 layer][3 pad][u16 packetId][2 pad][u32 dataSize]  then dataSize payload bytes
  ```

  - **layer 0** = transport: `Start Session` (id `5`) → `Session Started` (id `6`, payload
    = u32 unit id).
  - **layer 20** = application: product query (`0xfe`→`0xff`, payload `{u16 hwid}{u16 ver}
    {ascii name}`) and the flash commands.
- **Reply routing.** Application-layer replies arrive as a small `Pid_Data_Available`
  (`0x02`) frame on **interrupt IN**, telling the host to read the real packet from
  **bulk IN**. Small transport replies and the flash status come on **interrupt IN**
  directly. The tool handles both and **skips zero-length keep-alives** on the interrupt
  endpoint (mistaking one for a reply caused streaming before erase — a bug we hit).
- **Flash sequence** (application layer):

  1. `0x4b` **announce** `{u16 regionId, u32 size}`.
  2. `0x4a` **status** `{u16 region}` — **wait for status `0`** (region erased / ready)
     **before streaming.** Non-zero → the region was rejected → abort.
  3. `0x24` **data** — stream in **250-byte** chunks; **each packet body is
     `[u32 offset_LE][data]`** (offset = running byte position, starts at 0). **Omitting
     the 4-byte offset prefix corrupts the staged image** (the loader reads your first 4
     bytes as the write address) → commit rejected with **status 11**.
  4. `0x2d` **commit** `{u16 region}` — **fire-and-forget.** Per Garmin's own `Updater.exe`
     (decompiled), there is **no post-commit status read on success** and **no reboot
     packet** — Updater just closes the handle. See "Rebooting" below.

## Rebooting the device — IMPORTANT (manual power-cycle required)

**There is no USB command that reboots these loaders.** This was confirmed by decompiling
Garmin's own `Updater.exe`: at end-of-transfer it sends the `0x2d` commit, then simply
`CloseHandle`s and shows "Update Complete" — no reset IOCTL, no PnP re-enumerate, no
reboot packet. The official flow relies on the *device* auto-rebooting after commit.

**The 276Cx preboot loader does NOT auto-reboot** — and a USB bus reset
(`libusb dev.reset()` / sysfs `authorized`/`unbind`) only re-enumerates it back into the
loader. So after a successful flash you must **power-cycle the unit manually**:

- The power button is usually **unresponsive while in the loader**, so **briefly remove
  the battery**, reinsert, then power on normally (no keys).
- It should boot straight into the freshly-written firmware (you may see
  "Software Loading" briefly on the very first boot).

This is a hardware behavior, not a limitation of this tool — Garmin's own tools require
the same manual restart.

## Requirements

- **Linux**, **Python 3**, **`pyusb`** (`pip install -r requirements.txt`) + **libusb-1.0**
  (`sudo apt install libusb-1.0-0`).
- A **udev rule** so a non-root user can open the device (install once):

  ```bash
  sudo ./install_udev.sh      # writes /etc/udev/rules.d/99-garmin.rules for VID 091e, reloads udev
  ```

## Preparing the MAIN image (you supply it)

**No firmware ships with this tool** — Garmin firmware is copyrighted. Supply the MAIN
region extracted from **your own stock firmware `.gcd`** for **your** device. Default
image path is `main_0x02BD.bin` (override with `--image`).

A `.gcd` is a flat record stream from offset 8: `[u16 type][u16 length][body]` … until
`type == 0xFFFF`. Concatenate the bodies of every **`0x02BD`** record. Helper:

```bash
python extract_main_region.py YOUR_STOCK_FIRMWARE.gcd -o main_0x02BD.bin
```

For the 276Cx the result must be **18322432 bytes** with `sum(bytes) % 256 == 0`.

## Usage

1. **Enter preboot**: power off, connect USB, **hold D-pad `Up`** until loader mode. The
   `091e:0003` interface is live ~33 s for first contact (it stays up once the tool is
   talking to it).

2. **Read-only self-test** (safe):

   ```bash
   python flash_main.py
   ```

   Opens `091e:0003`, prints endpoints, `Start Session` → `Session Started` (unit id),
   the **detected HWID + firmware version**, whether the model is a known/tested profile,
   the image-verification result, and a dry-run plan. **No data written.**

3. **Flash** (writes MAIN — only after the self-test looks right):

   ```bash
   python flash_main.py --CONFIRM-FLASH                        # known device (e.g. 276Cx)
   python flash_main.py --CONFIRM-FLASH --allow-unknown-device # untested model (at your risk)
   ```

   Announce region 14 → wait for erase-ready `0` → stream `0x24` data (with offset
   prefix) → `0x2d` commit. Then **power-cycle the device** (see "Rebooting").

   > A commit that returns **status 11** means the staged image was rejected (bad `0x24`
   > framing or wrong region). The `GetRgnChecksum` (`0x3a4`) verify command is **not
   > implemented** by the preboot loader; skipping it is normal.

## Supporting other Garmin models

The USB protocol and `MAIN = region 14` are believed common across proprietary-OS,
unencrypted Garmin handhelds — but **only the 276Cx is verified.** To try another model:

1. Get that device's **stock `.gcd`** and extract its MAIN with `extract_main_region.py`.
2. Add a profile in `flash_main.py` → `DEVICE_PROFILES`:

   ```python
   <HWID>: {"name": "<model>", "main_region": 0x000E, "main_size": <bytes>,
            "sha1_prefix": "<optional>", "tested": False},
   ```

   (Get the HWID from the read-only self-test output.) Or skip the profile and use
   `--allow-unknown-device`, which flashes region 14 with generic checks only.
3. **Verify region 14 is really MAIN for that model before flashing** (e.g. cross-check
   its RGN region map). If unsure, don't.

Out of scope: encrypted firmware (Fenix 5+/MARQ) and Android/Linux-based Garmin devices —
this approach does not apply.

## Field notes (the sequence that recovered a 276Cx)

1. Device bricked → only enters preboot (`091e:0003`), stable.
2. `sudo ./install_udev.sh` once.
3. Enter preboot; `python flash_main.py` → `Session Started` + HWID 2479 / 5.80.
4. `python flash_main.py --CONFIRM-FLASH` → announce region 14 → erase-ready `0` →
   stream 18 MB (~73k `0x24` packets, each `[u32 offset][250 data]`) → commit.
5. **Battery-pull power-cycle** → boots the new firmware.

Bugs fixed while developing this (each cost a flash attempt): announcing GCD type
`0x02BD` instead of loader region `14`; reading replies from bulk IN instead of interrupt
IN (`0x82`); mistaking a zero-length interrupt keep-alive for the erase-ready reply; and
**sending `0x24` data without the `[u32 offset]` prefix** (→ status 11). All handled now.
The "auto-reboot" we initially expected does **not** happen on this loader — power-cycle
is required (see "Rebooting").

## Troubleshooting

- **Shows up as USB mass storage, not `091e:0003`.** Preboot window expired / it booted.
  Re-enter preboot (hold `Up` while connecting USB) and run immediately.
- **`ABORTING before stream: erase-ready status=11`.** Loader rejected the region. Re-enter
  preboot and retry; the tool aborts here instead of hanging the device.
- **`Access denied` / permission errors.** udev rule missing — `sudo ./install_udev.sh`,
  replug (or run once with `sudo`).
- **`pyusb unavailable` / no backend.** Install libusb-1.0 and `pip install -r requirements.txt`.
- **`Start Session` gets no reply.** Not in preboot / window expired. Re-enter and retry.
- **Flashed but it won't boot on its own.** Expected — **power-cycle** it (battery pull).
- **Image verification fails.** Wrong length/checksum/hash — re-extract from a known-good
  stock `.gcd` for your model.

## License

Copyright (C) 2026 the garmin-flasher contributors.

Free software under the **GNU General Public License version 3 (GPLv3)** — see
[LICENSE](LICENSE). Distributed **WITHOUT ANY WARRANTY**.

## Disclaimer

Unofficial community tool, not affiliated with Garmin. Flashing firmware over a low-level
loader is risky and can render a device unusable. Only tested on the GPSMAP 276Cx. No
warranty of any kind (GPLv3). **You are solely responsible for anything you do to your
device.**
