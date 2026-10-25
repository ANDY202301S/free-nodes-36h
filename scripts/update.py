#!/usr/bin/env python3
"""收集公开免费节点，测过能连上再写成订阅。"""

from __future__ import annotations

import atexit
import base64
import gzip
import json
import os
import platform
import queue
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(os.environ.get("OUTPUT_DIR", str(ROOT)))

MAX_TEST = int(os.environ.get("MAX_TEST", "64"))
MAX_EXTRA = int(os.environ.get("MAX_EXTRA", "24"))
MAX_KEEP = int(os.environ.get("MAX_KEEP", "30"))
MIN_PREFERRED = int(os.environ.get("MIN_PREFERRED", "8"))
WORKERS = int(os.environ.get("WORKERS", "4"))
PROBE_TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "12"))
PER_HOST = int(os.environ.get("PER_HOST", "2"))
MAX_BYTES = 3_000_000
SLOW_LIMIT = 6.0

MIHOMO_VERSION = "v1.19.33"
COUNTRY_CSV = (
    "https://raw.githubusercontent.com/sapics/ip-location-db/"
    "main/dbip-country/dbip-country-ipv4.csv"
)
TEST_URL = "https://www.gstatic.com/generate_204"

SOURCES = [
    ("peasoft", "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt"),
    ("freefq", "https://raw.githubusercontent.com/freefq/free/master/v2"),
    ("pawdroid", "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub"),
    ("mfuu", "https://raw.githubusercontent.com/mfuu/FreeProxies/master/sub"),
    ("ermaozi", "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt"),
    ("ripao", "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub"),
    ("freeSub", "https://raw.githubusercontent.com/Ruk1ng001/freeSub/main/v2ray"),
]

PREFERRED_PORTS = {
    80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096,
    8080, 8443, 8444, 8880, 9443,
}
BAD_PORTS = {0, 22, 23, 25, 53, 123, 135, 137, 139, 445, 1433, 3306, 3389, 5432, 6379, 11211, 27017}
SS_CIPHERS = {
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}
FINGERPRINTS = {"chrome", "firefox", "safari", "ios", "android", "edge", "random", "qq"}
NETWORKS = {"tcp", "ws", "grpc", "h2"}

REGIONS = {
    "HK": ("🇭🇰", "香港", 1),
    "MO": ("🇲🇴", "澳门", 1),
    "TW": ("🇹🇼", "台湾", 1),
    "JP": ("🇯🇵", "日本", 1),
    "KR": ("🇰🇷", "韩国", 1),
    "SG": ("🇸🇬", "新加坡", 1),
    "PH": ("🇵🇭", "菲律宾", 2),
    "TH": ("🇹🇭", "泰国", 2),
    "VN": ("🇻🇳", "越南", 2),
    "MY": ("🇲🇾", "马来西亚", 2),
    "ID": ("🇮🇩", "印尼", 2),
    "KH": ("🇰🇭", "柬埔寨", 2),
    "MM": ("🇲🇲", "缅甸", 2),
    "US": ("🇺🇸", "美国", 3),
    "CA": ("🇨🇦", "加拿大", 3),
    "AU": ("🇦🇺", "澳大利亚", 3),
    "NZ": ("🇳🇿", "新西兰", 3),
    "GB": ("🇬🇧", "英国", 3),
    "DE": ("🇩🇪", "德国", 3),
    "FR": ("🇫🇷", "法国", 3),
    "NL": ("🇳🇱", "荷兰", 3),
    "IE": ("🇮🇪", "爱尔兰", 3),
    "PT": ("🇵🇹", "葡萄牙", 3),
    "AT": ("🇦🇹", "奥地利", 3),
    "BE": ("🇧🇪", "比利时", 3),
    "CZ": ("🇨🇿", "捷克", 3),
    "DK": ("🇩🇰", "丹麦", 3),
    "LU": ("🇱🇺", "卢森堡", 3),
    "RU": ("🇷🇺", "俄罗斯", 4),
    "HU": ("🇭🇺", "匈牙利", 4),
    "RO": ("🇷🇴", "罗马尼亚", 4),
    "BG": ("🇧🇬", "保加利亚", 4),
    "GR": ("🇬🇷", "希腊", 4),
    "KZ": ("🇰🇿", "哈萨克斯坦", 4),
    "IN": ("🇮🇳", "印度", 4),
    "TR": ("🇹🇷", "土耳其", 4),
    "AE": ("🇦🇪", "阿联酋", 4),
    "BR": ("🇧🇷", "巴西", 4),
    "AR": ("🇦🇷", "阿根廷", 4),
    "UA": ("🇺🇦", "乌克兰", 4),
    "PL": ("🇵🇱", "波兰", 4),
    "SE": ("🇸🇪", "瑞典", 4),
    "CH": ("🇨🇭", "瑞士", 4),
    "IT": ("🇮🇹", "意大利", 4),
    "ES": ("🇪🇸", "西班牙", 4),
    "FI": ("🇫🇮", "芬兰", 4),
    "NO": ("🇳🇴", "挪威", 4),
    "IL": ("🇮🇱", "以色列", 4),
    "ZA": ("🇿🇦", "南非", 4),
    "MX": ("🇲🇽", "墨西哥", 4),
}

NAME_RULES = [
    (re.compile(r"香港|Hong\s*Kong|🇭🇰", re.I), "HK"),
    (re.compile(r"澳门|澳門|Macau|Macao|🇲🇴", re.I), "MO"),
    (re.compile(r"台湾|台灣|Taiwan|🇹🇼", re.I), "TW"),
    (re.compile(r"日本|Japan|东京|東京|大阪|🇯🇵", re.I), "JP"),
    (re.compile(r"新加坡|狮城|獅城|Singapore|🇸🇬", re.I), "SG"),
    (re.compile(r"韩国|韓國|首尔|首爾|Korea|🇰🇷", re.I), "KR"),
    (re.compile(r"美国|美國|洛杉矶|洛杉磯|圣何塞|聖何塞|硅谷|矽谷|🇺🇸", re.I), "US"),
    (re.compile(r"加拿大|Canada|🇨🇦", re.I), "CA"),
    (re.compile(r"澳大利亚|澳洲|Australia|🇦🇺", re.I), "AU"),
    (re.compile(r"英国|英國|伦敦|倫敦|United\s*Kingdom|🇬🇧", re.I), "GB"),
    (re.compile(r"德国|德國|法兰克福|法蘭克福|Germany|🇩🇪", re.I), "DE"),
    (re.compile(r"法国|法國|巴黎|France|🇫🇷", re.I), "FR"),
    (re.compile(r"荷兰|荷蘭|阿姆斯特丹|Netherlands|🇳🇱", re.I), "NL"),
    (re.compile(r"俄罗斯|俄羅斯|莫斯科|Russia|🇷🇺", re.I), "RU"),
    (re.compile(r"印尼|印度尼西亚|印度尼西亞|Indonesia|🇮🇩", re.I), "ID"),
    (re.compile(r"印度|India|🇮🇳", re.I), "IN"),
    (re.compile(r"土耳其|Turkey|🇹🇷", re.I), "TR"),
    (re.compile(r"泰国|泰國|曼谷|Thailand|🇹🇭", re.I), "TH"),
    (re.compile(r"马来|馬來|Malaysia|🇲🇾", re.I), "MY"),
    (re.compile(r"越南|Vietnam|🇻🇳", re.I), "VN"),
    (re.compile(r"菲律宾|菲律賓|Philippines|🇵🇭", re.I), "PH"),
    (re.compile(r"阿联酋|阿聯酋|迪拜|Dubai|🇦🇪", re.I), "AE"),
    (re.compile(r"巴西|Brazil|🇧🇷", re.I), "BR"),
    (re.compile(r"乌克兰|烏克蘭|Ukraine|🇺🇦", re.I), "UA"),
    (re.compile(r"爱尔兰|愛爾蘭|Ireland|🇮🇪", re.I), "IE"),
    (re.compile(r"瑞士|Switzerland|🇨🇭", re.I), "CH"),
    (re.compile(r"瑞典|Sweden|🇸🇪", re.I), "SE"),
    (re.compile(r"意大利|Italy|🇮🇹", re.I), "IT"),
    (re.compile(r"西班牙|Spain|🇪🇸", re.I), "ES"),
    (re.compile(r"葡萄牙|Portugal|🇵🇹", re.I), "PT"),
    (re.compile(r"奥地利|奧地利|Austria|🇦🇹", re.I), "AT"),
    (re.compile(r"比利时|比利時|Belgium|🇧🇪", re.I), "BE"),
    (re.compile(r"捷克|Czech|🇨🇿", re.I), "CZ"),
]

LINK_RE = re.compile(r"(?:vmess|vless|trojan|ss|hysteria2|hy2)://[^\s'\"<>]+", re.I)
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
ACTIVE_PIDS: set[int] = set()


def log(msg: str) -> None:
    print(msg, flush=True)


def _cleanup_children() -> None:
    for pid in list(ACTIVE_PIDS):
        try:
            os.killpg(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


atexit.register(_cleanup_children)


def b64decode(data: str) -> bytes:
    s = data.strip().replace("-", "+").replace("_", "/")
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s)


def try_b64_text(data: str) -> str:
    s = re.sub(r"\s+", "", data)
    if len(s) < 16 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", s):
        return ""
    try:
        text = b64decode(s).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return ""
    if "://" not in text:
        return ""
    return text


def ip_to_int(ip: str) -> int | None:
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    n = 0
    for part in parts:
        if not part.isdigit():
            return None
        value = int(part)
        if value > 255:
            return None
        n = (n << 8) + value
    return n


def is_ipv4(host: str) -> bool:
    return ip_to_int(host) is not None


def is_private_ip(ip: str) -> bool:
    n = ip_to_int(ip)
    if n is None:
        return False
    a = (n >> 24) & 255
    b = (n >> 16) & 255
    if a in (0, 10, 127):
        return True
    if a == 100 and 64 <= b <= 127:
        return True
    if a == 169 and b == 254:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 192 and b == 0:
        return True
    if a == 198 and b in (18, 19, 51):
        return True
    if a >= 224:
        return True
    return False


class RangeTable:
    def __init__(self, ranges: list[tuple[int, int, str]]):
        self.ranges = ranges

    def lookup(self, ip: str) -> str:
        n = ip_to_int(ip)
        if n is None:
            return ""
        lo, hi = 0, len(self.ranges)
        while lo < hi:
            mid = (lo + hi) // 2
            if self.ranges[mid][0] <= n:
                lo = mid + 1
            else:
                hi = mid
        if lo == 0:
            return ""
        start, end, code = self.ranges[lo - 1]
        if start <= n <= end:
            return code
        return ""


def guess_country(name: str) -> str:
    for pattern, code in NAME_RULES:
        if pattern.search(name or ""):
            return code
    return ""


def region_of(code: str) -> tuple[str, str, int]:
    if code in REGIONS:
        return REGIONS[code]
    return "🌐", "其他", 4


@dataclass
class Node:
    kind: str
    server: str
    port: int
    password: str = ""
    uuid: str = ""
    cipher: str = ""
    alter_id: int = 0
    network: str = "tcp"
    tls: bool = False
    reality: bool = False
    sni: str = ""
    path: str = ""
    host: str = ""
    fp: str = ""
    flow: str = ""
    pbk: str = ""
    sid: str = ""
    alpn: str = ""
    insecure: bool = False
    obfs: str = ""
    obfs_password: str = ""
    origin_name: str = ""
    country: str = ""
    latency: float = 99.0
    score: int = 0

    def identity(self) -> tuple:
        return (
            self.kind,
            self.server.lower(),
            self.port,
            self.uuid.lower(),
            self.password,
            self.network,
            self.path,
            self.sni.lower(),
            self.pbk,
        )


def split_host_port(hostport: str) -> tuple[str, int]:
    hostport = hostport.strip()
    if hostport.startswith("["):
        host, _, rest = hostport[1:].partition("]")
        port = rest.lstrip(":")
        return host, int(port)
    host, _, port = hostport.rpartition(":")
    if not host or not port:
        raise ValueError("host")
    return host, int(port)


def first_query(params: dict[str, list[str]], *keys: str) -> str:
    for key in keys:
        values = params.get(key)
        if values and values[0] != "":
            return values[0]
    return ""


def normalize_network(value: str, tls: bool) -> str:
    network = (value or "tcp").lower()
    if network in {"http", "h2"}:
        network = "h2"
    if network == "none":
        network = "tcp"
    return network


def normalize_fp(value: str) -> str:
    fp = (value or "").strip().lower()
    if fp in FINGERPRINTS:
        return fp
    return ""


def valid_server(host: str) -> bool:
    if not host or len(host) > 253 or re.search(r"\s", host):
        return False
    lowered = host.lower().rstrip(".")
    if lowered in {"localhost", "0.0.0.0"} or lowered.endswith(".local") or lowered.endswith(".cn"):
        return False
    if is_ipv4(host):
        return not is_private_ip(host)
    if ":" in host:
        return True
    return bool(re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z0-9.-]+", host))


def parse_vmess(link: str) -> Node | None:
    try:
        raw = json.loads(b64decode(link.split("://", 1)[1]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, IndexError):
        return None
    if not isinstance(raw, dict):
        return None
    server = str(raw.get("add") or "").strip()
    try:
        port = int(raw.get("port") or 0)
    except (TypeError, ValueError):
        return None
    uuid = str(raw.get("id") or "").strip()
    network = normalize_network(str(raw.get("net") or "tcp"), False)
    tls_flag = str(raw.get("tls") or "").lower()
    tls = tls_flag in {"tls", "true", "1"}
    sni = str(raw.get("sni") or raw.get("peer") or "").strip()
    host = str(raw.get("host") or "").strip()
    path = str(raw.get("path") or "").strip()
    if network == "grpc" and not path:
        path = str(raw.get("serviceName") or raw.get("path") or "").strip()
    fp = normalize_fp(str(raw.get("fp") or ""))
    try:
        alter_id = int(raw.get("aid") or 0)
    except (TypeError, ValueError):
        alter_id = 0
    cipher = str(raw.get("scy") or "auto").strip() or "auto"
    return Node(
        kind="vmess",
        server=server,
        port=port,
        uuid=uuid,
        cipher=cipher,
        alter_id=alter_id,
        network=network,
        tls=tls,
        sni=sni,
        path=path,
        host=host,
        fp=fp,
        origin_name=str(raw.get("ps") or ""),
    )


def parse_userinfo(userinfo: str) -> tuple[str, str]:
    userinfo = urllib.parse.unquote(userinfo)
    if ":" in userinfo and not re.fullmatch(r"[A-Za-z0-9+/=_-]+", userinfo):
        method, password = userinfo.split(":", 1)
        return method, password
    try:
        decoded = b64decode(userinfo).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        decoded = ""
    if decoded and ":" in decoded:
        method, password = decoded.split(":", 1)
        return method, password
    if ":" in userinfo:
        method, password = userinfo.split(":", 1)
        return method, password
    raise ValueError("userinfo")


def parse_ss(link: str) -> Node | None:
    body = link.split("://", 1)[1]
    name = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        name = urllib.parse.unquote(frag)
    if "?" in body:
        body = body.split("?", 1)[0]
    try:
        if "@" in body:
            userinfo, hostport = body.rsplit("@", 1)
            method, password = parse_userinfo(userinfo)
            server, port = split_host_port(hostport)
        else:
            decoded = b64decode(urllib.parse.unquote(body)).decode("utf-8")
            method_pass, hostport = decoded.rsplit("@", 1)
            method, password = method_pass.split(":", 1)
            server, port = split_host_port(hostport)
    except (ValueError, UnicodeDecodeError, IndexError):
        return None
    return Node(
        kind="ss",
        server=server,
        port=port,
        password=password,
        cipher=method.lower().strip(),
        origin_name=name,
    )


def parse_share(link: str) -> Node | None:
    scheme = link.split("://", 1)[0].lower()
    if scheme == "vmess":
        return parse_vmess(link)
    if scheme == "ss":
        return parse_ss(link)
    if scheme not in {"vless", "trojan", "hysteria2", "hy2"}:
        return None
    try:
        parts = urllib.parse.urlsplit(link)
    except ValueError:
        return None
    server = parts.hostname or ""
    port = parts.port or 0
    secret = urllib.parse.unquote(parts.username or "")
    name = urllib.parse.unquote(parts.fragment or "")
    params = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
    security = first_query(params, "security").lower()
    network = normalize_network(first_query(params, "type", "net", "network") or "tcp", False)
    if scheme == "trojan" and first_query(params, "ws").lower() in {"1", "true", "yes"}:
        network = "ws"
    if scheme in {"hysteria2", "hy2"}:
        network = "tcp"
    sni = first_query(params, "sni", "peer", "servername")
    host = first_query(params, "host", "authority")
    path = first_query(params, "path", "wspath", "serviceName", "servicename")
    path = urllib.parse.unquote(path)
    fp = normalize_fp(first_query(params, "fp", "fingerprint"))
    flow = first_query(params, "flow")
    pbk = first_query(params, "pbk", "publicKey", "public-key")
    sid = first_query(params, "sid", "shortId", "short-id")
    alpn = first_query(params, "alpn")
    insecure_text = first_query(params, "allowInsecure", "insecure", "skip-cert-verify").lower()
    insecure = insecure_text in {"1", "true", "yes"}
    obfs = first_query(params, "obfs")
    obfs_password = first_query(params, "obfs-password", "obfsPassword")
    reality = security == "reality" or bool(pbk)
    tls = security in {"tls", "reality"} or scheme in {"trojan", "hysteria2", "hy2"} or reality
    kind = "hysteria2" if scheme in {"hysteria2", "hy2"} else scheme
    node = Node(
        kind=kind,
        server=server,
        port=port,
        password=secret if kind != "vless" else "",
        uuid=secret if kind == "vless" else "",
        network=network,
        tls=tls,
        reality=reality,
        sni=sni,
        path=path,
        host=host,
        fp=fp or ("chrome" if reality else ""),
        flow=flow,
        pbk=pbk,
        sid=sid,
        alpn=alpn,
        insecure=insecure or kind == "hysteria2",
        obfs=obfs,
        obfs_password=obfs_password,
        origin_name=name,
    )
    return node


def acceptable(node: Node | None) -> bool:
    if node is None:
        return False
    if node.port in BAD_PORTS or not (1 <= node.port <= 65535):
        return False
    if not valid_server(node.server):
        return False
    if node.network not in NETWORKS:
        return False
    if node.network != "tcp":
        node.flow = ""
    if node.sid and not re.fullmatch(r"[0-9a-fA-F]{1,16}", node.sid):
        node.sid = ""
    if node.kind in {"vmess", "vless"}:
        if not UUID_RE.fullmatch(node.uuid or ""):
            return False
        if not (node.tls or node.reality):
            return False
        if node.reality and (not node.pbk or len(node.pbk) < 20 or not node.sni):
            return False
    elif node.kind == "trojan":
        if not node.password or not node.tls:
            return False
    elif node.kind == "ss":
        if not node.password or node.cipher not in SS_CIPHERS:
            return False
    elif node.kind == "hysteria2":
        if not node.password:
            return False
        node.tls = True
        node.insecure = True
    else:
        return False
    if node.network == "ws" and not node.path:
        node.path = "/"
    if node.network == "h2" and not node.tls:
        return False
    return True


def node_score(node: Node) -> int:
    score = 0
    if node.reality:
        score += 100
    elif node.kind == "hysteria2":
        score += 85
    elif node.kind == "trojan":
        score += 70
    elif node.kind == "vless":
        score += 60
    elif node.kind == "vmess":
        score += 50
    elif node.kind == "ss":
        score += 20
        if node.cipher.startswith("2022-"):
            score += 15
    if node.port == 443:
        score += 40
    elif node.port in PREFERRED_PORTS:
        score += 22
    else:
        score -= 15
    if node.network in {"ws", "grpc"} and (node.tls or node.reality):
        score += 8
    if node.flow and "vision" in node.flow:
        score += 6
    return score


def extract_links(text: str) -> list[str]:
    found: list[str] = []

    def add_from(blob: str) -> None:
        for match in LINK_RE.findall(blob):
            found.append(match.strip().rstrip("),;\"'"))

    add_from(text)
    if not found:
        decoded = try_b64_text(text)
        if decoded:
            add_from(decoded)
    if not found:
        for line in text.splitlines():
            decoded = try_b64_text(line.strip())
            if decoded:
                add_from(decoded)
            else:
                add_from(line)
    unique: list[str] = []
    seen: set[str] = set()
    for link in found:
        if link not in seen:
            seen.add(link)
            unique.append(link)
    return unique


def http_get(url: str, timeout: int = 30, limit: int | None = None) -> bytes:
    last: Exception | None = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read() if limit is None else resp.read(limit + 1)
            return data
        except (urllib.error.URLError, TimeoutError, OSError, gzip.BadGzipFile) as exc:
            last = exc
            time.sleep(1 + attempt)
    assert last is not None
    raise last


def fetch_source(name: str, url: str) -> list[str]:
    try:
        data = http_get(url, timeout=30, limit=MAX_BYTES)
    except Exception as exc:
        log(f"{name} 拉取失败：{exc.__class__.__name__}")
        return []
    if len(data) > MAX_BYTES:
        data = data[:MAX_BYTES]
    text = data.decode("utf-8", errors="replace")
    if "<html" in text[:300].lower():
        log(f"{name} 返回的不是节点")
        return []
    links = extract_links(text)
    log(f"{name} 链接 {len(links)}")
    return links


def host_for_link(host: str, port: int) -> str:
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def share_link(node: Node, name: str) -> str:
    quoted = urllib.parse.quote(name, safe="")
    if node.kind == "vmess":
        payload = {
            "v": "2",
            "ps": name,
            "add": node.server,
            "port": str(node.port),
            "id": node.uuid,
            "aid": str(node.alter_id),
            "scy": node.cipher or "auto",
            "net": node.network,
            "type": "none",
            "host": node.host or node.sni or "",
            "path": node.path or "",
            "tls": "tls" if node.tls else "",
            "sni": node.sni or "",
            "fp": node.fp or "",
        }
        blob = base64.b64encode(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()).decode()
        return "vmess://" + blob
    if node.kind == "ss":
        userinfo = base64.b64encode(f"{node.cipher}:{node.password}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{host_for_link(node.server, node.port)}#{quoted}"
    query: dict[str, str] = {}
    if node.kind == "vless":
        query["encryption"] = "none"
        query["security"] = "reality" if node.reality else "tls"
        query["type"] = node.network
        secret = urllib.parse.quote(node.uuid, safe="")
        scheme = "vless"
    elif node.kind == "trojan":
        query["security"] = "tls"
        query["type"] = node.network
        secret = urllib.parse.quote(node.password, safe="")
        scheme = "trojan"
    else:
        secret = urllib.parse.quote(node.password, safe="")
        scheme = "hysteria2"
        if node.sni:
            query["sni"] = node.sni
        query["insecure"] = "1"
        if node.obfs:
            query["obfs"] = node.obfs
        if node.obfs_password:
            query["obfs-password"] = node.obfs_password
        q = urllib.parse.urlencode(query, quote_via=urllib.parse.quote)
        return f"{scheme}://{secret}@{host_for_link(node.server, node.port)}?{q}#{quoted}"
    if node.sni:
        query["sni"] = node.sni
    if node.fp:
        query["fp"] = node.fp
    if node.flow:
        query["flow"] = node.flow
    if node.pbk:
        query["pbk"] = node.pbk
    if node.sid:
        query["sid"] = node.sid
    if node.path:
        query["path"] = node.path
    if node.host:
        query["host"] = node.host
    if node.alpn:
        query["alpn"] = node.alpn
    if node.insecure and node.kind != "hysteria2":
        query["allowInsecure"] = "1"
    q = urllib.parse.urlencode(query, quote_via=urllib.parse.quote)
    return f"{scheme}://{secret}@{host_for_link(node.server, node.port)}?{q}#{quoted}"


def yaml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def emit_yaml(value: object, indent: int = 0) -> str:
    space = " " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key, item in value.items():
            if item is None or item == "" or item == [] or item == {}:
                continue
            if isinstance(item, (dict, list)):
                lines.append(f"{space}{key}:")
                lines.append(emit_yaml(item, indent + 2))
            else:
                lines.append(f"{space}{key}: {yaml_scalar(item)}")
        return "\n".join(lines)
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, dict):
                pairs = [(k, v) for k, v in item.items() if v not in (None, "", [], {})]
                if not pairs:
                    continue
                first_key, first_value = pairs[0]
                if isinstance(first_value, (dict, list)):
                    lines.append(f"{space}- {first_key}:")
                    lines.append(emit_yaml(first_value, indent + 4))
                else:
                    lines.append(f"{space}- {first_key}: {yaml_scalar(first_value)}")
                for key, item_value in pairs[1:]:
                    pad = " " * (indent + 2)
                    if isinstance(item_value, (dict, list)):
                        lines.append(f"{pad}{key}:")
                        lines.append(emit_yaml(item_value, indent + 4))
                    else:
                        lines.append(f"{pad}{key}: {yaml_scalar(item_value)}")
            else:
                lines.append(f"{space}- {yaml_scalar(item)}")
        return "\n".join(line for line in lines if line != "")
    return f"{space}{yaml_scalar(value)}"


def clash_proxy(node: Node, name: str) -> dict:
    proxy: dict = {
        "name": name,
        "type": node.kind,
        "server": node.server,
        "port": node.port,
        "udp": True,
    }
    if node.kind == "vmess":
        proxy.update({
            "uuid": node.uuid,
            "alterId": node.alter_id,
            "cipher": node.cipher or "auto",
            "tls": True,
            "network": node.network,
        })
        if node.sni:
            proxy["servername"] = node.sni
        if node.fp:
            proxy["client-fingerprint"] = node.fp
    elif node.kind == "vless":
        proxy.update({
            "uuid": node.uuid,
            "network": node.network,
            "tls": True,
        })
        if node.flow:
            proxy["flow"] = node.flow
        if node.sni:
            proxy["servername"] = node.sni
        proxy["client-fingerprint"] = node.fp or ("chrome" if node.reality else "")
        if node.reality:
            reality = {"public-key": node.pbk}
            if node.sid:
                reality["short-id"] = node.sid
            proxy["reality-opts"] = reality
    elif node.kind == "trojan":
        proxy.update({"password": node.password, "network": node.network})
        if node.sni:
            proxy["sni"] = node.sni
        if node.fp:
            proxy["client-fingerprint"] = node.fp
    elif node.kind == "ss":
        proxy.update({"cipher": node.cipher, "password": node.password})
    elif node.kind == "hysteria2":
        proxy.update({
            "password": node.password,
            "skip-cert-verify": True,
        })
        if node.sni:
            proxy["sni"] = node.sni
        if node.obfs:
            proxy["obfs"] = node.obfs
        if node.obfs_password:
            proxy["obfs-password"] = node.obfs_password
    if node.insecure and node.kind in {"vmess", "vless", "trojan"}:
        proxy["skip-cert-verify"] = True
    if node.network == "ws":
        ws_opts: dict = {"path": node.path or "/"}
        host = node.host or node.sni
        if host:
            ws_opts["headers"] = {"Host": host}
        proxy["ws-opts"] = ws_opts
    elif node.network == "grpc":
        proxy["grpc-opts"] = {"grpc-service-name": node.path or ""}
    elif node.network == "h2":
        h2_opts: dict = {}
        if node.path:
            h2_opts["path"] = node.path
        if node.host or node.sni:
            h2_opts["host"] = [node.host or node.sni]
        if h2_opts:
            proxy["h2-opts"] = h2_opts
    if node.alpn and node.kind in {"vmess", "vless", "trojan", "hysteria2"}:
        proxy["alpn"] = [part.strip() for part in node.alpn.split(",") if part.strip()]
    return proxy


def indent_block(text: str, spaces: int = 2) -> str:
    pad = " " * spaces
    return "\n".join(pad + line if line else line for line in text.splitlines())


def build_clash(named: list[tuple[Node, str]]) -> str:
    proxies = [clash_proxy(node, name) for node, name in named]
    names = [name for _, name in named]
    groups = [
        {"name": "选择", "type": "select", "proxies": ["自动", *names]},
        {
            "name": "自动",
            "type": "url-test",
            "url": TEST_URL,
            "interval": 300,
            "tolerance": 80,
            "proxies": names,
        },
    ]
    lines = [
        "#profile-title: 免费节点",
        "#profile-update-interval: 36",
        "#profile-web-page-url: https://github.com/ANDY202301S/free-nodes-36h",
        "# 公开节点，不保证一直能用",
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
        "ipv6: false",
        "proxies:",
        indent_block(emit_yaml(proxies)),
        "proxy-groups:",
        indent_block(emit_yaml(groups)),
        "rules:",
        '  - "MATCH,选择"',
        "",
    ]
    return "\n".join(lines)


def build_test_config(node: Node, port: int) -> str:
    proxy_yaml = indent_block(emit_yaml([clash_proxy(node, "n")]))
    return (
        f"mixed-port: {port}\n"
        "allow-lan: false\n"
        "mode: rule\n"
        "log-level: silent\n"
        "ipv6: false\n"
        "proxies:\n"
        f"{proxy_yaml}\n"
        "rules:\n"
        "  - MATCH,n\n"
    )


def load_country_table() -> RangeTable | None:
    cache = Path(tempfile.gettempdir()) / "dbip-country-ipv4.csv"
    try:
        if not cache.exists() or cache.stat().st_size < 100000:
            log("下载地址库")
            data = http_get(COUNTRY_CSV, timeout=60)
            cache.write_bytes(data)
        ranges: list[tuple[int, int, str]] = []
        for line in cache.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split(",")
            if len(parts) != 3 or ":" in parts[0]:
                continue
            start, end = ip_to_int(parts[0]), ip_to_int(parts[1])
            if start is None or end is None or end < start:
                continue
            ranges.append((start, end, parts[2].strip().upper()))
        ranges.sort()
        log(f"地址库 {len(ranges)}")
        return RangeTable(ranges)
    except Exception as exc:
        log(f"地址库不可用：{exc.__class__.__name__}")
        return None


def resolve_ips(host: str) -> list[str]:
    if is_ipv4(host):
        return [host]
    if ":" in host:
        return []
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(3)
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return []
    finally:
        socket.setdefaulttimeout(previous)
    ips: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


def annotate_countries(nodes: list[Node], geo: RangeTable | None) -> list[Node]:
    hosts = sorted({node.server for node in nodes})
    resolved: dict[str, list[str]] = {}
    lock = threading.Lock()

    def work(host: str) -> None:
        ips = resolve_ips(host)
        with lock:
            resolved[host] = ips

    with ThreadPoolExecutor(max_workers=30) as pool:
        list(pool.map(work, hosts))

    kept: list[Node] = []
    for node in nodes:
        ips = resolved.get(node.server, [])
        if ips and all(is_private_ip(ip) for ip in ips):
            continue
        codes = []
        if geo and ips:
            codes = [geo.lookup(ip) for ip in ips]
            codes = [code for code in codes if code]
        if codes and all(code == "CN" for code in codes):
            continue
        country = ""
        for code in codes:
            if code != "CN":
                country = code
                break
        if not country:
            country = guess_country(node.origin_name)
        if country == "CN":
            continue
        node.country = country
        kept.append(node)
    return kept


def endpoint_key(node: Node) -> str:
    if is_ipv4(node.server):
        parts = node.server.split(".")
        return ".".join(parts[:3])
    return node.server.lower()


def diversify(nodes: list[Node], limit: int) -> list[Node]:
    picked: list[Node] = []
    counts: dict[str, int] = {}
    for node in nodes:
        if len(picked) >= limit:
            break
        key = endpoint_key(node)
        if counts.get(key, 0) >= PER_HOST:
            continue
        counts[key] = counts.get(key, 0) + 1
        picked.append(node)
    return picked


def ensure_mihomo() -> str:
    configured = os.environ.get("MIHOMO_BIN", "")
    if configured and os.path.isfile(configured) and os.access(configured, os.X_OK):
        return configured
    found = shutil.which("mihomo")
    if found:
        return found
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine, "amd64")
    dest = Path(tempfile.gettempdir()) / f"mihomo-linux-{arch}-{MIHOMO_VERSION}"
    if dest.exists() and os.access(dest, os.X_OK) and dest.stat().st_size > 1000000:
        return str(dest)
    asset_re = re.compile(rf"mihomo-linux-{arch}-v\d+\.\d+\.\d+\.gz")
    url = ""
    try:
        meta = json.loads(http_get(
            "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest",
            timeout=30,
        ).decode("utf-8"))
        for asset in meta.get("assets", []):
            name = asset.get("name") or ""
            if asset_re.fullmatch(name):
                url = asset.get("browser_download_url") or ""
                break
    except Exception as exc:
        log(f"查询核心版本失败：{exc.__class__.__name__}")
    if not url:
        url = (
            "https://github.com/MetaCubeX/mihomo/releases/download/"
            f"{MIHOMO_VERSION}/mihomo-linux-{arch}-{MIHOMO_VERSION}.gz"
        )
    log("下载测试核心")
    blob = http_get(url, timeout=120)
    if blob[:2] == b"\x1f\x8b":
        blob = gzip.decompress(blob)
    if not blob.startswith(b"\x7fELF"):
        raise RuntimeError("测试核心不是可执行文件")
    dest.write_bytes(blob)
    dest.chmod(0o755)
    return str(dest)


def wait_port(port: int, proc: subprocess.Popen, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), 0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def probe(port: int) -> float | None:
    try:
        result = subprocess.run(
            [
                "curl", "-sS", "-o", "/dev/null",
                "-w", "%{http_code} %{time_total}",
                "--http1.1",
                "--connect-timeout", "5",
                "--max-time", str(int(PROBE_TIMEOUT)),
                "-x", f"http://127.0.0.1:{port}",
                TEST_URL,
            ],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT + 4,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    parts = (result.stdout or "").split()
    if len(parts) != 2:
        return None
    try:
        code = int(parts[0])
        elapsed = float(parts[1])
    except ValueError:
        return None
    if code != 204:
        return None
    return elapsed


def test_one(node: Node, port: int, binary: str) -> tuple[float | None, str]:
    work = Path(tempfile.mkdtemp(prefix="node-"))
    config = work / "config.yaml"
    stderr_path = work / "stderr.txt"
    config.write_text(build_test_config(node, port), encoding="utf-8")
    stderr_file = open(stderr_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [binary, "-d", str(work), "-f", str(config)],
        stdout=subprocess.DEVNULL,
        stderr=stderr_file,
        start_new_session=True,
    )
    ACTIVE_PIDS.add(proc.pid)
    try:
        ready = wait_port(port, proc, 6)
        line = ""
        if not ready and proc.poll() is not None:
            stderr_file.flush()
            text = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
            line = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
        if not ready:
            return None, line[:240]
        return probe(port), ""
    finally:
        stderr_file.close()
        ACTIVE_PIDS.discard(proc.pid)
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        shutil.rmtree(work, ignore_errors=True)


_port_lock = threading.Lock()
_port_next = 29100


def next_port() -> int:
    global _port_next
    with _port_lock:
        port = _port_next
        _port_next += 1
        return port


def test_many(nodes: list[Node], binary: str) -> list[Node]:
    if not nodes:
        return []
    tasks: queue.Queue[Node | None] = queue.Queue()
    for node in nodes:
        tasks.put(node)
    alive: list[Node] = []
    errors: list[str] = []
    done = {"n": 0}
    lock = threading.Lock()

    def worker(_index: int) -> None:
        while True:
            try:
                node = tasks.get_nowait()
            except queue.Empty:
                return
            latency, error = test_one(node, next_port(), binary)
            with lock:
                done["n"] += 1
                current = done["n"]
                if latency is not None:
                    node.latency = latency
                    alive.append(node)
                elif error and len(errors) < 5:
                    errors.append(error)
                if current == 1 or current % 8 == 0 or current == len(nodes):
                    log(f"已测 {current}/{len(nodes)}，通 {len(alive)}")

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(max(1, WORKERS))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    for item in errors:
        log(f"没连上的例子：{item}")
    return alive


def name_nodes(nodes: list[Node]) -> list[tuple[Node, str]]:
    counts: dict[str, int] = {}
    named: list[tuple[Node, str]] = []
    for node in nodes:
        code = node.country or "XX"
        flag, label, _tier = region_of(code)
        counts[code] = counts.get(code, 0) + 1
        named.append((node, f"{flag} {label} {counts[code]:02d}"))
    return named


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def collect_nodes() -> list[Node]:
    links: list[str] = []
    for name, url in SOURCES:
        links.extend(fetch_source(name, url))
    parsed: list[Node] = []
    seen: set[tuple] = set()
    for link in links:
        node = parse_share(link)
        if not acceptable(node):
            continue
        assert node is not None
        identity = node.identity()
        if identity in seen:
            continue
        seen.add(identity)
        node.score = node_score(node)
        parsed.append(node)
    log(f"解析后 {len(parsed)}")
    geo = load_country_table()
    parsed = annotate_countries(parsed, geo)
    log(f"筛过地址后 {len(parsed)}")
    random.Random(int(time.time()) // 3600).shuffle(parsed)
    parsed.sort(key=lambda item: item.score, reverse=True)
    return parsed


def rank_alive(nodes: list[Node]) -> list[Node]:
    fast = [node for node in nodes if node.latency <= SLOW_LIMIT]
    use = fast if len(fast) >= 5 else list(nodes)

    def sort_key(node: Node) -> tuple:
        preferred = 0 if node.port in PREFERRED_PORTS else 1
        plain = 0 if node.kind != "ss" else 1
        _flag, _label, tier = region_of(node.country)
        return (preferred, plain, tier, node.latency)

    use.sort(key=sort_key)
    picked: list[Node] = []
    counts: dict[str, int] = {}
    for node in use:
        key = endpoint_key(node)
        if counts.get(key, 0) >= 3:
            continue
        counts[key] = counts.get(key, 0) + 1
        picked.append(node)
        if len(picked) >= MAX_KEEP:
            break
    return picked


def write_outputs(nodes: list[Node]) -> None:
    named = name_nodes(nodes)
    clash = build_clash(named)
    links = [share_link(node, name) for node, name in named]
    blob = base64.b64encode(("\n".join(links) + "\n").encode()).decode()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    atomic_write(OUT / "clash.yaml", clash)
    atomic_write(OUT / "v2ray.txt", blob + "\n")
    atomic_write(OUT / "updated_at.txt", stamp + "\n")
    log(f"发布 {len(named)}")


def run_update() -> int:
    nodes = collect_nodes()
    preferred = [node for node in nodes if node.port in PREFERRED_PORTS]
    others = [node for node in nodes if node.port not in PREFERRED_PORTS]
    near = [node for node in preferred if region_of(node.country)[2] <= 2]
    far = [node for node in preferred if region_of(node.country)[2] > 2]
    primary = diversify(near + far, MAX_TEST)
    extra = diversify(others, MAX_EXTRA)
    log(f"准备测试 {len(primary)}，备用 {len(extra)}")
    binary = ensure_mihomo()
    alive = test_many(primary, binary)
    preferred_alive = [node for node in alive if node.port in PREFERRED_PORTS]
    if len(preferred_alive) < MIN_PREFERRED and extra:
        log("首选不够，再测一批")
        alive.extend(test_many(extra, binary))
    ranked = rank_alive(alive)
    if not ranked:
        log("没有能用的节点，这次不写文件")
        return 1
    write_outputs(ranked)
    return 0


def self_check() -> int:
    vless = (
        "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443"
        "?encryption=none&flow=xtls-rprx-vision&fp=chrome"
        "&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc"
        "&security=reality&sni=www.microsoft.com&sid=ab12&type=tcp#demo"
    )
    vmess_obj = {
        "v": "2", "ps": "香港", "add": "203.0.113.11", "port": "443",
        "id": "11111111-2222-3333-4444-555555555555", "aid": "0", "scy": "auto",
        "net": "ws", "type": "none", "host": "cdn.example.com", "path": "/live",
        "tls": "tls", "sni": "cdn.example.com", "fp": "chrome",
    }
    vmess = "vmess://" + base64.b64encode(json.dumps(vmess_obj).encode()).decode()
    trojan = (
        "trojan://secret@cdn.example.net:443?security=tls&sni=cdn.example.net"
        "&ws=1&wspath=%2Fassignment#美国"
    )
    ss = "ss://" + base64.b64encode(b"aes-256-gcm:secret@203.0.113.12:8443").decode() + "#%E6%97%A5%E6%9C%AC"
    hy2 = "hysteria2://pass@203.0.113.13:443?sni=cdn.example.org&insecure=1&obfs=salamander&obfs-password=ob#新加坡"
    samples = [vless, vmess, trojan, ss, hy2]
    for link in samples:
        node = parse_share(link)
        assert acceptable(node), link
        assert node is not None
        again = parse_share(share_link(node, "🇭🇰 香港 01"))
        assert again is not None
        assert (again.kind, again.server, again.port, again.network) == (
            node.kind, node.server, node.port, node.network
        )
    plain = parse_share(
        "vmess://" + base64.b64encode(json.dumps({
            "add": "203.0.113.20", "port": "10086",
            "id": "11111111-2222-3333-4444-555555555555", "net": "tcp", "tls": "",
        }).encode()).decode()
    )
    assert not acceptable(plain)
    local = parse_share(
        "trojan://secret@127.0.0.1:443?security=tls&sni=example.com#x"
    )
    assert not acceptable(local)
    blob = base64.b64encode(("\n".join(samples) + "\n").encode()).decode()
    assert len(extract_links(blob)) == len(samples)
    assert guess_country("香港 01") == "HK"
    assert guess_country("印度尼西亚") == "ID"
    table = RangeTable([(ip_to_int("1.0.1.0") or 0, ip_to_int("1.0.1.255") or 0, "CN")])
    assert table.lookup("1.0.1.8") == "CN"
    assert table.lookup("8.8.8.8") == ""
    node = parse_share(vless)
    assert node is not None
    text = build_clash([(node, "🇭🇰 香港 01")])
    assert "reality-opts:" in text
    assert "203.0.113.10" in text
    config = build_test_config(node, 29999)
    assert "mixed-port: 29999" in config
    assert "MATCH,n" in config
    log("自检通过")
    return 0


def main() -> int:
    if "--check" in sys.argv:
        return self_check()
    if "--dry-run" in sys.argv:
        nodes = collect_nodes()
        preferred = [node for node in nodes if node.port in PREFERRED_PORTS]
        log(f"候选 {len(preferred)} / 其余 {len(nodes) - len(preferred)}")
        return 0
    return run_update()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
