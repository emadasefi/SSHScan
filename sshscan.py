#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2017 Vincent Ruijter
# Copyright (c) 2020-2025 Babak Farrokhi
#
# Algorithm classifications based on algorithm_guidance.json
# v3.3.2 - Original code + COMPLETE FIXED scoring

import argparse
import os
import socket
import struct
import sys
from typing import Any, Optional, Tuple, List, Dict

__version__ = "1.0.2"

# Terminal Colors
class TerminalColors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'

def supports_color() -> bool:
    if os.environ.get('NO_COLOR'): return False
    if os.environ.get('FORCE_COLOR'): return True
    if not sys.stdout.isatty(): return False
    return os.environ.get('TERM', '') != 'dumb'

USE_COLOR = supports_color()

def colorize(text: str, color: str) -> str:
    return f"{color}{text}{TerminalColors.RESET}" if USE_COLOR else text

def red(text: str) -> str: return colorize(text, TerminalColors.RED)
def green(text: str) -> str: return colorize(text, TerminalColors.GREEN)
def yellow(text: str) -> str: return colorize(text, TerminalColors.YELLOW)

# SSH Constants
SSH_MSG_KEXINIT = 20
MAX_PACKET_LENGTH = 1024 * 1024
SSH_HEADER_LENGTH = 5
KEXINIT_COOKIE_LENGTH = 16
VERSION_STRING_MAX_LENGTH = 255
MIN_PADDING_LENGTH = 4
MAX_PADDING_LENGTH = 255

# Strong lists (original)
STRONG_CIPHERS = [
    'chacha20-poly1305@openssh.com','aes256-gcm@openssh.com','aes128-gcm@openssh.com',
    'aes256-ctr','aes192-ctr','aes128-ctr'
]

STRONG_MACS = [
    'hmac-sha2-512-etm@openssh.com','hmac-sha2-256-etm@openssh.com','umac-128',
    'umac-128-etm@openssh.com','hmac-sha2-512','hmac-sha2-256','umac-128@openssh.com'
]

STRONG_KEX = [
    'curve25519-sha256','curve25519-sha256@libssh.org','diffie-hellman-group-exchange-sha256',
    'diffie-hellman-group14-sha256','diffie-hellman-group16-sha512','diffie-hellman-group18-sha512',
    'sntrup761x25519-sha512@openssh.com','sntrup761x25519-sha512','mlkem768x25519-sha256',
    'kex-strict-s-v00@openssh.com','ext-info-s'
]

STRONG_HOST_KEY_ALGORITHMS = [
    'ssh-ed25519','ssh-ed25519-cert-v01@openssh.com','rsa-sha2-256',
    'rsa-sha2-512','ssh-rsa-cert-v01@openssh.com'
]

# COMPLETE Scoring System
ALGORITHM_SCORES = {
    # Ciphers
    'chacha20-poly1305@openssh.com':100,'aes256-gcm@openssh.com':98,'aes128-gcm@openssh.com':95,
    'aes256-ctr':92,'aes192-ctr':90,'aes128-ctr':88,'aes256-cbc':70,'aes192-cbc':68,
    'aes128-cbc':65,'3des-cbc':20,'blowfish-cbc':15,'cast128-cbc':10,'arcfour':5,
    'arcfour128':5,'arcfour256':5,'rijndael-cbc@lysator.liu.se':60,

    # MACs
    'hmac-sha2-512-etm@openssh.com':100,'hmac-sha2-256-etm@openssh.com':98,
    'umac-128-etm@openssh.com':95,'umac-128@openssh.com':92,'hmac-sha2-512':90,
    'hmac-sha2-256':88,'umac-128':85,'hmac-sha2-256-etm':88,
    'hmac-sha1-etm@openssh.com':60,'hmac-sha1':50,'hmac-ripemd160-etm@openssh.com':25,
    'hmac-ripemd160':15,'hmac-md5-etm@openssh.com':20,'hmac-md5':10,'hmac-md5-96':5,

    # KEX
    'curve25519-sha256':100,'curve25519-sha256@libssh.org':100,
    'sntrup761x25519-sha512@openssh.com':98,'mlkem768x25519-sha256':97,
    'diffie-hellman-group16-sha512':95,'diffie-hellman-group18-sha512':94,
    'diffie-hellman-group14-sha256':92,'diffie-hellman-group15-sha512':93,
    'diffie-hellman-group-exchange-sha256':90,'ecdh-sha2-nistp384':87,
    'ecdh-sha2-nistp521':88,'ecdh-sha2-nistp256':85,'kex-strict-s-v00@openssh.com':95,
    'diffie-hellman-group-exchange-sha1':40,'diffie-hellman-group14-sha1':30,
    'diffie-hellman-group1-sha1':10,'gss-gex-sha1-':20,'gss-group14-sha1-':15,
    'ext-info-s':90,

    # HostKey
    'ssh-ed25519':100,'ssh-ed25519-cert-v01@openssh.com':100,'sk-ssh-ed25519@openssh.com':99,
    'rsa-sha2-512':95,'rsa-sha2-256':92,'ecdsa-sha2-nistp256':90,
    'ecdsa-sha2-nistp384':92,'ecdsa-sha2-nistp521':94,'ssh-rsa':40,
    'ssh-rsa-cert-v01@openssh.com':45,'ssh-dss':10
}

def get_score(algo: str) -> int: return ALGORITHM_SCORES.get(algo, 0)

def calculate_final_score(ciphers: List[str], kex: List[str], macs: List[str], hka: List[str]) -> float:
    cipher_avg = sum(get_score(c) for c in ciphers) / len(ciphers) if ciphers else 0
    kex_avg = sum(get_score(k) for k in kex) / len(kex) if kex else 0
    mac_avg = sum(get_score(m) for m in macs) / len(macs) if macs else 0
    hka_avg = sum(get_score(h) for h in hka) / len(hka) if hka else 0
    return cipher_avg * 0.35 + kex_avg * 0.30 + mac_avg * 0.25 + hka_avg * 0.10

def get_status(score: float) -> str:
    s = int(score)
    if s >= 90: return "EXCELLENT ✅"
    elif s >= 80: return "GOOD 👍"
    elif s >= 70: return "FAIR ⚠️"
    elif s >= 60: return "POOR 😐"
    return "DANGER ❌"

# Parsing functions
def parse_uint32(data: bytes, offset: int) -> Tuple[int, int]:
    if offset + 4 > len(data): raise ValueError("uint32")
    return struct.unpack('>I', data[offset:offset+4])[0], offset + 4

def parse_byte(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data): raise ValueError("byte")
    return data[offset], offset + 1

def parse_string(data: bytes, offset: int) -> Tuple[bytes, int]:
    length, offset = parse_uint32(data, offset)
    if offset + length > len(data): raise ValueError("string")
    return data[offset:offset+length], offset + length

def parse_name_list(data: bytes, offset: int) -> Tuple[List[str], int]:
    name_list_bytes, offset = parse_string(data, offset)
    if not name_list_bytes: return [], offset
    return name_list_bytes.decode('ascii').split(','), offset

def parse_boolean(data: bytes, offset: int) -> Tuple[bool, int]:
    value, offset = parse_byte(data, offset)
    return value != 0, offset

def parse_ssh_packet(conn: socket.socket) -> bytes:
    header = conn.recv(SSH_HEADER_LENGTH)
    packet_length = struct.unpack('>I', header[0:4])[0]
    padding_length = header[4]
    payload_length = packet_length - padding_length - 1
    remaining = packet_length - 1
    data = b''
    while len(data) < remaining:
        chunk = conn.recv(remaining - len(data))
        if not chunk: raise ValueError("Connection closed")
        data += chunk
    return data[:payload_length]

def parse_kexinit(payload: bytes) -> Dict[str, Any]:
    offset = 0
    msg_type, offset = parse_byte(payload, offset)
    if msg_type != SSH_MSG_KEXINIT: raise ValueError("Not KEXINIT")
    offset += KEXINIT_COOKIE_LENGTH
    kex, offset = parse_name_list(payload, offset)
    hka, offset = parse_name_list(payload, offset)
    enc_c2s, offset = parse_name_list(payload, offset)
    enc_s2c, offset = parse_name_list(payload, offset)
    mac_c2s, offset = parse_name_list(payload, offset)
    mac_s2c, offset = parse_name_list(payload, offset)
    comp_c2s, offset = parse_name_list(payload, offset)
    comp_s2c, offset = parse_name_list(payload, offset)
    lang_c2s, offset = parse_name_list(payload, offset)
    lang_s2c, offset = parse_name_list(payload, offset)
    parse_boolean(payload, offset)
    parse_uint32(payload, offset)
    return {
        'kex_algorithms': kex, 'server_host_key_algorithms': hka,
        'encryption_algorithms_server_to_client': enc_s2c,
        'mac_algorithms_server_to_client': mac_s2c
    }

def exchange(ip: str, port: int) -> Optional[Dict[str, Any]]:
    conn = None
    try:
        conn = socket.create_connection((ip, port), timeout=5)
        print(f"[*] Connected to {ip} on port {port}...")
        version_data = conn.recv(VERSION_STRING_MAX_LENGTH)
        version = version_data.decode('ascii', errors='ignore').split('\n')[0].strip()
        print(f"    [+] Target SSH version is: {version}")
        conn.send(b'SSH-2.0-OpenSSH_6.0p1\r\n')
        print("    [+] Retrieving algorithm information...")
        payload = parse_ssh_packet(conn)
        return parse_kexinit(payload)
    except Exception as e:
        print(f"[-] Error while connecting to {ip} on port {port}: {e}")
    finally:
        if conn: conn.close()
    return None

def validate_port(port_str: str) -> Tuple[Optional[int], Optional[str]]:
    try:
        port = int(port_str)
        if 1 <= port <= 65535: return port, None
        return None, "Port must be 1-65535"
    except: return None, "Invalid port"

def parse_target(target: str) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    port = 22
    host = target
    if target.startswith('['):
        bracket_end = target.find(']')
        if bracket_end == -1: return None, None, "Invalid IPv6"
        host = target[1:bracket_end]
        if bracket_end + 2 < len(target):
            port, error = validate_port(target[bracket_end+2:])
            if error: return None, None, error
    elif ':' in target:
        parts = target.split(':', 1)
        host, port_str = parts
        port, error = validate_port(port_str)
        if error: return None, None, error
    return host, port, None

def scan_target(target: str) -> int:
    host, port, error = parse_target(target)
    if error or not host:
        print(f"[-] Error: {error or 'Invalid host'}")
        return 1
    print(f"[*] Initiating scan for {host} on port {port}")
    data = exchange(host, port)
    if data: display_result(data); return 0
    return 1

def print_algo_list(algo_list: List[str], title: str, strong_list: Optional[List[str]] = None) -> None:
    if algo_list:
        print(f'    [+] Detected {title}: ')
        display_list = algo_list.copy()
        cols = 2
        while len(display_list) % cols != 0: display_list.append('')
        split = [display_list[i:i + len(display_list) // cols] for i in range(0, len(display_list), len(display_list) // cols)]
        for row in zip(*split):
            formatted_row = []
            for algo in row:
                if algo:
                    if strong_list:
                        colored = green(algo) if algo in strong_list else red(algo)
                        formatted_row.append(str.ljust(colored, 37 + len(colored) - len(algo)))
                    else:
                        formatted_row.append(str.ljust(algo, 37))
                else:
                    formatted_row.append(' ' * 37)
            print("          " + "".join(formatted_row))
    else:
        print(f'    [-] No {title} detected!')

def detect_not_recommended_algo(detected: List[str], strong: List[str]) -> List[str]:
    return [algo for algo in detected if algo not in strong]

def display_result(data: Dict[str, Any]) -> None:
    ciphers = data['encryption_algorithms_server_to_client']
    kex = data['kex_algorithms']
    macs = data['mac_algorithms_server_to_client']
    hka = data['server_host_key_algorithms']

    not_rec_c = detect_not_recommended_algo(ciphers, STRONG_CIPHERS)
    not_rec_k = detect_not_recommended_algo(kex, STRONG_KEX)
    not_rec_m = detect_not_recommended_algo(macs, STRONG_MACS)
    not_rec_h = detect_not_recommended_algo(hka, STRONG_HOST_KEY_ALGORITHMS)

    print_algo_list(ciphers, 'ciphers', STRONG_CIPHERS)
    print_algo_list(kex, 'KEX algorithms', STRONG_KEX)
    print_algo_list(macs, 'MACs', STRONG_MACS)
    print_algo_list(hka, 'HostKey algorithms', STRONG_HOST_KEY_ALGORITHMS)

    print_algo_list(not_rec_c, 'not recommended ciphers')
    print_algo_list(not_rec_k, 'not recommended KEX algorithms')
    print_algo_list(not_rec_m, 'not recommended MACs')
    print_algo_list(not_rec_h, 'not recommended HostKey algorithms')

    comp = data.get('compression_algorithms_server_to_client', [])
    print('    [+] Compression is enabled' if 'zlib@openssh.com' in comp or 'zlib' in comp else '    [-] Compression is *not* enabled')

    # SCORING
    print("\n" + "="*60)
    print(f"🏆 SSH SECURITY SCORE v{__version__}")
    print("="*60)

    final_score = calculate_final_score(ciphers, kex, macs, hka)
    final_int = int(final_score)

    status_colored = green(get_status(final_score)) if final_int >= 80 else yellow(get_status(final_score)) if final_int >= 60 else red(get_status(final_score))
    print(f"📊 FINAL SCORE: {final_int:3d}% {status_colored}")

    c_avg = int(sum(get_score(c) for c in ciphers) / len(ciphers))
    k_avg = int(sum(get_score(k) for k in kex) / len(kex))
    m_avg = int(sum(get_score(m) for m in macs) / len(macs))
    h_avg = int(sum(get_score(h) for h in hka) / len(hka))

    print(f"🔢 Ciphers: {c_avg:3d}% | KEX:     {k_avg:3d}%")
    print(f"🔢 MACs:    {m_avg:3d}% | HostKey: {h_avg:3d}%")
    print("="*60)

def main():
    global USE_COLOR
    parser = argparse.ArgumentParser(description=f'SSH Scanner v{__version__}')
    parser.add_argument('target', help='host[:port]')
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('--no-color', action='store_true')
    parser.add_argument('--color', action='store_true')
    args = parser.parse_args()

    if args.no_color: USE_COLOR = False
    elif args.color: USE_COLOR = True

    sys.exit(scan_target(args.target))

if __name__ == '__main__':
    main()