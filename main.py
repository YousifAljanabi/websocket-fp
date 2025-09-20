import os
import time
import ctypes
import requests
from datetime import datetime
from ctypes import byref, c_int, c_uint, c_ubyte, c_char_p, c_void_p

# ===== User config =====
DLL_NAME = "SynoAPIEx.dll"
DEFAULT_ADDR = 0xFFFFFFFF
TIMEOUT_SECONDS = 5
OUTPUT_DIR = "captured_images"
# API_ENDPOINT = "https://api.yousified.xyz/match"  # Endpoint to send scanned image
API_ENDPOINT = "http://localhost:5116/match"  # Endpoint to send scanned image


# ===== Load library (same as before) =====
def load_vendor_dll(name: str) -> ctypes.CDLL:
    try:
        here = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
        candidate = os.path.join(here, name)
        if os.path.isfile(candidate):
            return ctypes.CDLL(candidate)
        return ctypes.CDLL(name)
    except OSError as e:
        raise SystemExit(f"Failed to load {name}: {e}")


dll = load_vendor_dll(DLL_NAME)

# ===== Types & constants =====
HANDLE = c_void_p
DEVICE_USB, DEVICE_COM, DEVICE_UDISK = 0, 1, 2
PS_OK, PS_COMM_ERR, PS_NO_FINGER = 0x00, 0x01, 0x02
IMAGE_X, IMAGE_Y = 256, 288
IMAGE_BYTES = IMAGE_X * IMAGE_Y

# ===== Function signatures =====
dll.PSOpenDeviceEx.argtypes = [ctypes.POINTER(HANDLE), c_int, c_int, c_int, c_int, c_int]
dll.PSOpenDeviceEx.restype = c_int
dll.PSAutoOpen.argtypes = [ctypes.POINTER(HANDLE), ctypes.POINTER(c_int), c_int, c_uint, c_int]
dll.PSAutoOpen.restype = c_int
dll.PSGetUSBDevNum.argtypes = [ctypes.POINTER(c_int)]
dll.PSGetUSBDevNum.restype = c_int
dll.PSGetUDiskNum.argtypes = [ctypes.POINTER(c_int)]
dll.PSGetUDiskNum.restype = c_int
dll.PSCloseDeviceEx.argtypes = [HANDLE]
dll.PSCloseDeviceEx.restype = c_int
dll.PSGetImage.argtypes = [HANDLE, c_int]
dll.PSGetImage.restype = c_int
dll.PSUpImage.argtypes = [HANDLE, c_int, ctypes.POINTER(c_ubyte), ctypes.POINTER(c_int)]
dll.PSUpImage.restype = c_int
dll.PSImgData2BMP.argtypes = [ctypes.POINTER(c_ubyte), c_char_p]
dll.PSImgData2BMP.restype = c_int
dll.PSErr2Str.argtypes = [c_int]
dll.PSErr2Str.restype = ctypes.c_char_p


def err_text(code: int) -> str:
    s = dll.PSErr2Str(code)
    return s.decode(errors="ignore") if s else f"Error 0x{code:02X}"


def close_device(h: HANDLE):
    if h:
        dll.PSCloseDeviceEx(h)


# ===== Device open helpers (same as your code) =====
# ===== Open helpers =====
def try_PSAutoOpen() -> tuple[HANDLE, int]:
    """Let the DLL auto-detect device type (USB/COM)."""
    h = HANDLE()
    dtype = c_int(-1)
    rc = dll.PSAutoOpen(byref(h), byref(dtype), DEFAULT_ADDR, 0, 1)  # bVfy=1
    if rc == PS_OK and h:
        return h, dtype.value
    raise RuntimeError(f"PSAutoOpen failed: {err_text(rc)}")


def try_USB_explicit() -> HANDLE:
    """
    Try USB explicitly with different nPackageSize values.
    The DLL's default is '2', but some devices accept 0/1/2/3 only.
    """
    tried = []
    for nPackageSize in (2, 3, 1, 0, 4):
        h = HANDLE()
        rc = dll.PSOpenDeviceEx(byref(h), DEVICE_USB, 1, 1, nPackageSize, 0)
        tried.append((nPackageSize, rc))
        if rc == PS_OK and h:
            print(f"[USB] Open OK with nPackageSize={nPackageSize}")
            return h
        else:
            print(f"[USB] Open failed (nPackageSize={nPackageSize}) → {err_text(rc)}")
    raise RuntimeError("USB open attempts failed: " + ", ".join(
        f"ps={ps}:{err_text(rc)}" for ps, rc in tried))


def try_COM_scan() -> HANDLE:
    """
    Scan COM1..COM30. iBaud is a multiple of 9600 per manual note (6 -> 57600).
    Many modules default to 57600 or 115200; we try both.
    """
    for com in range(1, 31):
        for ibaud in (6, 12):  # 6*9600=57600, 12*9600=115200
            h = HANDLE()
            rc = dll.PSOpenDeviceEx(byref(h), DEVICE_COM, com, ibaud, 2, 0)
            if rc == PS_OK and h:
                print(f"[COM] Open OK on COM{com} @ {ibaud * 9600} bps")
                return h
            else:
                # Reduce noise—only show likely ports (under 15) or last tried
                if com <= 15 or (com == 30 and ibaud == 12):
                    print(f"[COM] COM{com} @ {ibaud * 9600} → {err_text(rc)}")
    raise RuntimeError("COM open attempts failed.")


def open_device_resilient() -> tuple[HANDLE, str]:
    """
    Try the best sequence: check USB count → PSAutoOpen → USB explicit → COM scan.
    Returns (handle, mode_str).
    """
    # Quick visibility: how many USB/UDisk devices the DLL sees
    usb_n = c_int(0)
    if dll.PSGetUSBDevNum(byref(usb_n)) == PS_OK:
        print(f"DLL reports USB devices: {usb_n.value}")
    udisks = c_int(0)
    if dll.PSGetUDiskNum(byref(udisks)) == PS_OK:
        print(f"DLL reports UDISK devices: {udisks.value}")

    # 1) PSAutoOpen (preferred)
    try:
        h, dtype = try_PSAutoOpen()
        mode = "USB" if dtype == DEVICE_USB else ("COM" if dtype == DEVICE_COM else f"type={dtype}")
        print(f"PSAutoOpen succeeded. Mode: {mode}")
        return h, mode
    except Exception as e:
        print(str(e))

    # 2) USB explicit with packet-size variants
    try:
        h = try_USB_explicit()
        return h, "USB"
    except Exception as e:
        print(str(e))

    # 3) COM scan
    h = try_COM_scan()
    return h, "COM"


# ===== Capture helpers =====
def wait_for_finger_and_capture(h: HANDLE, addr: int, timeout_s: int) -> bytes:
    t0 = time.time()
    while True:
        rc = dll.PSGetImage(h, addr)
        if rc == PS_OK:
            break
        if rc == PS_NO_FINGER:
            if time.time() - t0 > timeout_s:
                raise TimeoutError("No finger detected within timeout.")
            time.sleep(0.15)
            continue
        raise RuntimeError(f"PSGetImage failed: {err_text(rc)}")

    img_buf = (c_ubyte * IMAGE_BYTES)()
    img_len = c_int(IMAGE_BYTES)
    rc = dll.PSUpImage(h, addr, img_buf, byref(img_len))
    if rc != PS_OK:
        raise RuntimeError(f"PSUpImage failed: {err_text(rc)}")
    return bytes(bytearray(img_buf)[:img_len.value])


def save_bmp_via_dll(img_bytes: bytes, out_path: str):
    buf = (c_ubyte * len(img_bytes)).from_buffer_copy(img_bytes)
    rc = dll.PSImgData2BMP(buf, out_path.encode("utf-8"))
    if rc != PS_OK:
        raise RuntimeError(f"PSImgData2BMP failed: {err_text(rc)}")


def create_output_directory():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)


def generate_timestamp_filename():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(OUTPUT_DIR, f"fingerprint_{timestamp}.bmp")


# ===== API Upload =====
def upload_to_endpoint(file_path: str):
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f, "image/bmp")}
        try:
            headers = {"User-Agent": "FingerprintScanner/1.0"}
            resp = requests.post(API_ENDPOINT, files=files, headers=headers, timeout=100, verify=False)

            resp.raise_for_status()
            data = resp.json()
            # Expected format: { "username": "string", "score": 1, "certainty": 1, "matchingTime": "string" }
            print("=== Match Result ===")
            print(f"Username: {data.get('username')}")
            print(f"Score: {data.get('score')}")
            print(f"Certainty: {data.get('certainty')}")
            print(f"Matching Time: {data.get('matchingTime')}")
            print("=" * 30)
        except Exception as e:
            print(f"Failed to upload or parse response: {e}")


# ===== Main scan loop =====
def continuous_scan():
    create_output_directory()
    h = None
    scan_count = 0
    try:
        h, mode = open_device_resilient()
        print(f"Device opened in {mode} mode")
        while True:
            try:
                print(f"Scan #{scan_count + 1}: Waiting for finger...", end=" ", flush=True)
                img = wait_for_finger_and_capture(h, DEFAULT_ADDR, TIMEOUT_SECONDS)
                filename = generate_timestamp_filename()
                save_bmp_via_dll(img, filename)
                print(f"Captured! Saved as: {filename} (size={len(img)} bytes)")

                # Upload captured image to endpoint
                upload_to_endpoint(filename)

                scan_count += 1
                time.sleep(1)
            except TimeoutError:
                print("(no finger detected)")
                time.sleep(0.5)
                continue
            except KeyboardInterrupt:
                print("\nExiting scanner...")
                break
            except Exception as e:
                print(f"Error: {e}. Retrying in 2s...")
                time.sleep(2)
                continue
    finally:
        if h:
            close_device(h)
            print("Device closed.")


def main():
    try:
        continuous_scan()
    except KeyboardInterrupt:
        print("\nScanner stopped by user.")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()