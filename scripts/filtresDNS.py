#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import concurrent.futures
import gzip
import http.client
import io
import lzma
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Iterable

BASE_DIR = Path(__file__).resolve().parents[1] if '__file__' in globals() else Path.cwd()
OUTPUT_FILE = BASE_DIR / 'filtresDNS.txt'
README_FILE = BASE_DIR / 'README.md'

MAX_WORKERS = 5
REQUEST_TIMEOUT = 45
MAX_RETRIES = 4
BACKOFF_BASE = 2
MAX_DOWNLOAD_SIZE = 100 * 1024 * 1024
USER_AGENT = 'Mozilla/5.0 (compatible; filtresDNS/2.0; +https://github.com/)'

BLOCKLIST_URLS = [
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.tif.txt',
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    'https://someonewhocares.org/hosts/zero/hosts',
    'https://mirror1.malwaredomains.com/files/justdomains',
    'https://adaway.org/hosts.txt',
    'https://v.firebog.net/hosts/AdguardDNS.txt',
    'https://v.firebog.net/hosts/Easyprivacy.txt',
    'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext',
]

COMMENT_PREFIXES = ('#', '!', ';', '[')
LOCAL_SKIP = {'localhost', 'localhost.localdomain', 'local', 'broadcasthost', 'ip6-localhost'}
DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$',
    re.IGNORECASE,
)
IPV4_RE = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
HOSTS_SPLIT_RE = re.compile(r'\s+')


@dataclass(slots=True)
class DownloadResult:
    url: str
    entries: set[str]
    success: bool
    error: str | None = None
    attempts: int = 1
    status: int | None = None
    bytes_downloaded: int = 0
    last_modified: str | None = None


class DomainTrieNode:
    __slots__ = ('children', 'terminal')

    def __init__(self) -> None:
        self.children: dict[str, 'DomainTrieNode'] = {}
        self.terminal = False

    def insert(self, parts: list[str]) -> bool:
        node = self
        for part in parts:
            if node.terminal:
                return False
            node = node.children.setdefault(part, DomainTrieNode())
        if node.terminal:
            return False
        node.terminal = True
        node.children.clear()
        return True


def domain_to_parts(domain: str) -> list[str]:
    return domain.lower().rstrip('.').split('.')[::-1]


def is_valid_domain(domain: str) -> bool:
    domain = domain.strip().lower().rstrip('.')
    if not domain or len(domain) > 253:
        return False
    if domain in LOCAL_SKIP:
        return False
    if '*' in domain or '/' in domain or ':' in domain:
        return False
    if IPV4_RE.match(domain):
        return False
    return bool(DOMAIN_RE.match(domain))


def normalize_domain(value: str) -> str | None:
    value = value.strip().lower().strip('.')
    if not value:
        return None
    if value.startswith('||'):
        value = value[2:]
    if value.startswith('*.'):
        value = value[2:]
    if value.startswith('.'):
        value = value[1:]
    if '^' in value:
        value = value.split('^', 1)[0]
    if '$' in value:
        value = value.split('$', 1)[0]
    if '#' in value:
        value = value.split('#', 1)[0]
    if value.startswith('http://') or value.startswith('https://'):
        parsed = urllib.parse.urlparse(value)
        value = parsed.hostname or ''
    if '/' in value:
        value = value.split('/', 1)[0]
    if ':' in value:
        value = value.split(':', 1)[0]
    if value.startswith('www.') and value.count('.') >= 2:
        value = value[4:]
    return value if is_valid_domain(value) else None


def extract_from_hosts_line(line: str) -> list[str]:
    parts = HOSTS_SPLIT_RE.split(line.strip())
    if len(parts) < 2:
        return []
    ip = parts[0]
    if ip not in {'0.0.0.0', '127.0.0.1', '::1', '::', '255.255.255.255'} and not IPV4_RE.match(ip):
        return []
    out: list[str] = []
    for host in parts[1:]:
        dom = normalize_domain(host)
        if dom:
            out.append(dom)
    return out


def extract_entries_from_text(text: str) -> set[str]:
    entries: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(COMMENT_PREFIXES):
            continue
        if ' ' in line or '\t' in line:
            for dom in extract_from_hosts_line(line):
                entries.add(dom)
            continue
        dom = normalize_domain(line)
        if dom:
            entries.add(dom)
    return entries


def maybe_decompress(data: bytes, url: str, content_type: str | None, encoding: str | None) -> bytes:
    lower_url = url.lower()
    ctype = (content_type or '').lower()
    cenc = (encoding or '').lower()

    try:
        if cenc == 'gzip' or lower_url.endswith('.gz') or 'gzip' in ctype:
            return gzip.decompress(data)
    except OSError:
        pass

    try:
        if lower_url.endswith('.xz') or 'xz' in ctype:
            return lzma.decompress(data)
    except lzma.LZMAError:
        pass

    if lower_url.endswith('.zip') or 'zip' in ctype:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = [n for n in zf.namelist() if not n.endswith('/')]
            if not names:
                return b''
            candidate = min(names, key=len)
            return zf.read(candidate)

    return data


def decode_bytes(data: bytes) -> str:
    for enc in ('utf-8', 'utf-8-sig', 'iso-8859-1'):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode('utf-8', errors='replace')


def build_request(url: str) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        headers={
            'User-Agent': USER_AGENT,
            'Accept': 'text/plain,text/*;q=0.9,*/*;q=0.5',
            'Accept-Encoding': 'gzip',
            'Connection': 'close',
        },
    )


def fetch_url_bytes(url: str) -> tuple[bytes, int | None, str | None, str | None, str | None]:
    req = build_request(url)
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
        status = getattr(response, 'status', None)
        content_type = response.headers.get('Content-Type')
        content_encoding = response.headers.get('Content-Encoding')
        last_modified = response.headers.get('Last-Modified')
        data = response.read(MAX_DOWNLOAD_SIZE + 1)
        if len(data) > MAX_DOWNLOAD_SIZE:
            raise ValueError(f'Téléchargement trop volumineux (> {MAX_DOWNLOAD_SIZE} octets) : {url}')
        return data, status, content_type, content_encoding, last_modified


def download_and_extract(url: str) -> DownloadResult:
    last_error: str | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            data, status, content_type, content_encoding, last_modified = fetch_url_bytes(url)
            payload = maybe_decompress(data, url, content_type, content_encoding)
            text = decode_bytes(payload)
            entries = extract_entries_from_text(text)
            return DownloadResult(
                url=url,
                entries=entries,
                success=True,
                attempts=attempt,
                status=status,
                bytes_downloaded=len(data),
                last_modified=last_modified,
            )
        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            TimeoutError,
            ConnectionResetError,
            ConnectionAbortedError,
            ConnectionRefusedError,
            socket.timeout,
            socket.gaierror,
            ssl.SSLError,
            http.client.HTTPException,
            ValueError,
            OSError,
            EOFError,
            zipfile.BadZipFile,
            lzma.LZMAError,
        ) as exc:
            last_error = f'{type(exc).__name__}: {exc}'
            print(f'⚠️  Échec {attempt}/{MAX_RETRIES} pour {url} -> {last_error}', file=sys.stderr)
            if attempt < MAX_RETRIES:
                time.sleep(BACKOFF_BASE ** (attempt - 1))

    return DownloadResult(url=url, entries=set(), success=False, error=last_error, attempts=MAX_RETRIES)


def write_blocklist(entries: Iterable[str], timestamp: str, output_path: Path = OUTPUT_FILE) -> None:
    header = [
        '! Title: filtresDNS',
        '! Description: Liste de domaines consolidée et dédupliquée',
        f'! Last modified: {timestamp}',
        '! Expires: 12 hours',
        '! Homepage: https://github.com/',
        '! Syntax: Adblock Plus / hosts-like domains',
        '',
    ]
    lines = header + sorted(entries)
    output_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def update_readme(stats: dict[str, int], readme_path: Path = README_FILE) -> None:
    start_tag = '<!-- filtresDNS:start -->'
    end_tag = '<!-- filtresDNS:end -->'
    total = stats.get('after', 0)
    failed = stats.get('failed_sources', 0)
    ok = stats.get('successful_sources', 0)
    skipped = stats.get('total_sources', 0) - ok
    new_table = (
        '\n'
        '| Indicateur | Valeur |\n'
        '|---|---:|\n'
        f'| Domaines uniques | {total} |\n'
        f'| Sources OK | {ok} |\n'
        f'| Sources en échec | {failed} |\n'
        f'| Sources totales | {stats.get("total_sources", 0)} |\n'
    )

    try:
        content = readme_path.read_text(encoding='utf-8')
    except FileNotFoundError:
        print(f'ℹ️ README introuvable : {readme_path}', file=sys.stderr)
        return

    start_pos = content.find(start_tag)
    end_pos = content.find(end_tag)
    if start_pos != -1 and end_pos != -1 and end_pos > start_pos:
        content = content[: start_pos + len(start_tag)] + new_table + '\n' + content[end_pos:]
    else:
        content += f'\n{start_tag}{new_table}\n{end_tag}\n'

    readme_path.write_text(content, encoding='utf-8')


def deduplicate_domains(entries: set[str]) -> set[str]:
    trie_root = DomainTrieNode()
    final_entries: set[str] = set()
    for entry in sorted(entries, key=lambda e: (e.count('.'), e)):
        if trie_root.insert(domain_to_parts(entry)):
            final_entries.add(entry)
    return final_entries


def format_dt_fr(dt: datetime) -> str:
    jours = ['lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi', 'dimanche']
    mois = [
        'janvier', 'février', 'mars', 'avril', 'mai', 'juin',
        'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre'
    ]
    return f"{jours[dt.weekday()]} {dt.day:02d} {mois[dt.month - 1]} {dt.year}, {dt:%H:%M}"


def format_last_modified(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value).isoformat()
    except Exception:
        return value


def main() -> None:
    started = time.perf_counter()
    all_entries: set[str] = set()
    results: list[DownloadResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {executor.submit(download_and_extract, url): url for url in BLOCKLIST_URLS}
        for future in concurrent.futures.as_completed(future_map):
            url = future_map[future]
            try:
                result = future.result()
            except Exception as exc:
                result = DownloadResult(url=url, entries=set(), success=False, error=f'Unhandled: {type(exc).__name__}: {exc}')
            results.append(result)
            all_entries.update(result.entries)
            if result.success:
                lm = format_last_modified(result.last_modified)
                suffix = f', last-modified={lm}' if lm else ''
                print(f'✅ {url} -> {len(result.entries)} entrées (tentative {result.attempts}{suffix})')
            else:
                print(f'❌ {url} -> {result.error}', file=sys.stderr)

    final_entries = deduplicate_domains(all_entries)
    total = len(final_entries)
    timestamp = format_dt_fr(datetime.now())
    write_blocklist(final_entries, timestamp=timestamp)

    successful_sources = sum(1 for r in results if r.success)
    failed_sources = len(results) - successful_sources
    duration = time.perf_counter() - started

    print(f'✅ filtresDNS.txt généré : {total} entrées uniques')
    print(f'📦 Sources OK: {successful_sources}/{len(results)} | échecs: {failed_sources} | durée: {duration:.1f}s')

    update_readme(
        {
            'after': total,
            'successful_sources': successful_sources,
            'failed_sources': failed_sources,
            'total_sources': len(results),
        }
    )

    if successful_sources == 0:
        raise SystemExit('Aucune source n’a pu être téléchargée.')


if __name__ == '__main__':
    main()
