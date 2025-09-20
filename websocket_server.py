import asyncio
import websockets
import json
import base64
import os
import time
import ctypes
from datetime import datetime
from ctypes import byref, c_int, c_uint, c_ubyte, c_char_p, c_void_p
from typing import Set, Optional
import threading

# Import the existing DLL configuration from main.py
DLL_NAME = "SynoAPIEx.dll"
DEFAULT_ADDR = 0xFFFFFFFF
TIMEOUT_SECONDS = 5
OUTPUT_DIR = "captured_images"

# Load library (same as main.py)
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

# Types & constants (same as main.py)
HANDLE = c_void_p
DEVICE_USB, DEVICE_COM, DEVICE_UDISK = 0, 1, 2
PS_OK, PS_COMM_ERR, PS_NO_FINGER = 0x00, 0x01, 0x02
IMAGE_X, IMAGE_Y = 256, 288
IMAGE_BYTES = IMAGE_X * IMAGE_Y

# Function signatures (same as main.py)
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

# Device open helpers (from main.py)
def try_PSAutoOpen() -> tuple[HANDLE, int]:
    h = HANDLE()
    dtype = c_int(-1)
    rc = dll.PSAutoOpen(byref(h), byref(dtype), DEFAULT_ADDR, 0, 1)
    if rc == PS_OK and h:
        return h, dtype.value
    raise RuntimeError(f"PSAutoOpen failed: {err_text(rc)}")

def try_USB_explicit() -> HANDLE:
    tried = []
    for nPackageSize in (2, 3, 1, 0, 4):
        h = HANDLE()
        rc = dll.PSOpenDeviceEx(byref(h), DEVICE_USB, 1, 1, nPackageSize, 0)
        tried.append((nPackageSize, rc))
        if rc == PS_OK and h:
            return h
        if nPackageSize == 2:  # Only print for default attempt
            print(f"[USB] Open failed (nPackageSize={nPackageSize}) → {err_text(rc)}")
    raise RuntimeError("USB open attempts failed")

def try_COM_scan() -> HANDLE:
    for com in range(1, 31):
        for ibaud in (6, 12):
            h = HANDLE()
            rc = dll.PSOpenDeviceEx(byref(h), DEVICE_COM, com, ibaud, 2, 0)
            if rc == PS_OK and h:
                return h
    raise RuntimeError("COM open attempts failed")

def open_device_resilient() -> tuple[HANDLE, str]:
    try:
        h, dtype = try_PSAutoOpen()
        mode = "USB" if dtype == DEVICE_USB else ("COM" if dtype == DEVICE_COM else f"type={dtype}")
        return h, mode
    except Exception:
        pass

    try:
        h = try_USB_explicit()
        return h, "USB"
    except Exception:
        pass

    h = try_COM_scan()
    return h, "COM"

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

# WebSocket server implementation
class FingerprintWebSocketServer:
    def __init__(self):
        self.connected_clients: Set[websockets.WebSocketServerProtocol] = set()
        self.device_handle: Optional[HANDLE] = None
        self.device_mode: str = ""
        self.is_running = False

    async def register_client(self, websocket):
        self.connected_clients.add(websocket)
        print(f"Client connected. Total clients: {len(self.connected_clients)}")

    async def unregister_client(self, websocket):
        self.connected_clients.discard(websocket)
        print(f"Client disconnected. Total clients: {len(self.connected_clients)}")

    async def broadcast_status(self, status: str, data: dict = None):
        if not self.connected_clients:
            return

        message = {
            "status": status,
            "timestamp": datetime.now().isoformat(),
            **(data or {})
        }

        disconnected = set()
        for client in self.connected_clients:
            try:
                await client.send(json.dumps(message))
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(client)

        # Remove disconnected clients
        for client in disconnected:
            self.connected_clients.discard(client)

    async def handle_client(self, websocket):
        await self.register_client(websocket)
        try:
            await websocket.wait_closed()
        finally:
            await self.unregister_client(websocket)

    def initialize_device(self):
        try:
            create_output_directory()
            self.device_handle, self.device_mode = open_device_resilient()
            return True
        except Exception as e:
            print(f"Failed to initialize device: {e}")
            return False

    async def fingerprint_scanner_loop(self):
        scan_count = 0

        while self.is_running:
            try:
                # Broadcast "Waiting for finger" status
                await self.broadcast_status("Waiting for finger", {
                    "scan_count": scan_count + 1
                })

                # Wait for finger and capture (this blocks, so we run in executor)
                loop = asyncio.get_event_loop()
                img_bytes = await loop.run_in_executor(
                    None,
                    wait_for_finger_and_capture,
                    self.device_handle,
                    DEFAULT_ADDR,
                    TIMEOUT_SECONDS
                )

                # Broadcast "Captured" status
                await self.broadcast_status("Captured", {
                    "scan_count": scan_count + 1,
                    "image_size": len(img_bytes)
                })

                # Save the image
                filename = generate_timestamp_filename()
                await loop.run_in_executor(None, save_bmp_via_dll, img_bytes, filename)

                # Read the saved image file and encode to base64
                with open(filename, 'rb') as f:
                    image_data = f.read()
                    image_base64 = base64.b64encode(image_data).decode('utf-8')

                # Send the captured image
                await self.broadcast_status("Image Ready", {
                    "scan_count": scan_count + 1,
                    "filename": os.path.basename(filename),
                    "image": image_base64,
                    "image_format": "bmp"
                })

                scan_count += 1
                await asyncio.sleep(1)  # Brief pause before next scan

            except TimeoutError:
                # No finger detected within timeout, continue waiting
                await asyncio.sleep(0.5)
                continue
            except Exception as e:
                await self.broadcast_status("Error", {
                    "error": str(e),
                    "scan_count": scan_count + 1
                })
                await asyncio.sleep(2)
                continue

    async def start_server(self, host="192.168.0.127", port=8765):
        if not self.initialize_device():
            print("Failed to initialize fingerprint device")
            return

        # Broadcast "Device opened" status
        await self.broadcast_status("Device opened", {
            "mode": self.device_mode
        })

        self.is_running = True

        # Start the WebSocket server
        server = await websockets.serve(self.handle_client, host, port)
        print(f"WebSocket server started on ws://{host}:{port}")

        # Start the fingerprint scanner loop
        scanner_task = asyncio.create_task(self.fingerprint_scanner_loop())

        try:
            await server.wait_closed()
        except KeyboardInterrupt:
            print("\nShutting down server...")
        finally:
            self.is_running = False
            scanner_task.cancel()
            if self.device_handle:
                close_device(self.device_handle)
                print("Device closed.")

async def main():
    server = FingerprintWebSocketServer()
    await server.start_server()

if __name__ == "__main__":
    asyncio.run(main())