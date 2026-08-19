"""
Lightweight TCP connect-scan for a curated list of commonly-used ports.

IMPORTANT: This performs a simple TCP connect() scan (no SYN/stealth scanning,
no third-party binaries like nmap/masscan). Only scan hosts you own or are
explicitly authorized to test. The API layer should require an explicit
authorization flag before running this.
"""
import socket
import ssl as ssl_lib
import concurrent.futures

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def _grab_banner(ip: str, port: int, timeout: float = 1.5) -> str | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            if port in (443, 8443):
                ctx = ssl_lib.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl_lib.CERT_NONE
                with ctx.wrap_socket(sock) as ssock:
                    return f"TLS ({ssock.version()})"
            sock.settimeout(timeout)
            try:
                banner = sock.recv(128)
                return banner.decode(errors="ignore").strip() or None
            except socket.timeout:
                return None
    except Exception:
        return None


def _check_port(ip: str, port: int, timeout: float = 1.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            banner = _grab_banner(ip, port)
            return {
                "port": port,
                "service": COMMON_PORTS.get(port, "unknown"),
                "state": "open",
                "banner": banner,
            }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan_ports(ip: str, ports: list[int] | None = None, max_workers: int = 20) -> list[dict]:
    targets = ports or list(COMMON_PORTS.keys())
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check_port, ip, p): p for p in targets}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports, key=lambda x: x["port"])
