import contextlib
import io
import json
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import instagram as public
import instagram_oauth as oauth

CFG = {'app_id': '123', 'version': 'v25.0', 'redirect_uri': 'https://example.com/instagram/callback'}


class Vault:
    def __init__(self):
        self.values = {'app:123': 'test-app-secret'}
    def get_password(self, service, key):
        return self.values.get(key)
    def set_password(self, service, key, value):
        self.values[key] = value


class PublicTests(unittest.TestCase):
    def test_normalization(self):
        for value in ('@Example.User', 'example.user', 'instagram.com/example.user/',
                      'https://www.instagram.com/Example.User/?igsh=abc'):
            self.assertEqual(public.normalize_profile(value),
                             ('example.user', 'https://www.instagram.com/example.user/'))

    def test_rejects_non_profile_and_ssrf_inputs(self):
        for value in ('https://evil.com/alice/', 'https://instagram.com.evil.com/alice/',
                      'https://instagram.com@evil.com/alice/', 'http://instagram.com/alice/',
                      'https://instagram.com:8443/alice/', 'https://instagram.com/p/123/',
                      'https://instagram.com/accounts/login/', 'https://127.0.0.1/alice/',
                      'https://instagram.com/%61lice/', '@a..b', '@a.', '.alice', '@', 'a' * 31,
                      'https://instagram.com/alice/extra/', 'https://instagram.com:bad/alice/'):
            with self.subTest(value=value), self.assertRaises(public.ConnectorError):
                public.normalize_profile(value)

    def test_preserves_observed_strings_without_invented_metrics(self):
        html = '''<meta property="og:url" content="https://www.instagram.com/alice/">
        <meta property="og:title" content="Alice (@alice) • Instagram">
        <meta property="og:description" content="1.2K followers &amp; text">
        <script>{"reach":999999}</script>'''
        with patch.object(public, 'fetch_public', return_value=html):
            result = public.public_profile('@alice')
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['evidence'][1]['value'], '1.2K followers & text')
        self.assertFalse(result['insights_available'])
        self.assertNotIn('999999', json.dumps(result))
        self.assertFalse(result['ownership_verified'])

    def test_login_wrong_profile_and_generic_metadata_are_unavailable(self):
        for html in ('<title>Login • Instagram</title>',
                     '<meta property="og:title" content="Instagram">',
                     '<meta property="og:url" content="https://instagram.com/bob/">'
                     '<meta property="og:title" content="Bob (@bob)">',
                     '<meta property="og:url" content="https://instagram.com/alice/">'
                     '<meta property="og:title" content="Alice (@alice.other)">'):
            with patch.object(public, 'fetch_public', return_value=html):
                result = public.public_profile('@alice')
                self.assertEqual(result['status'], 'unavailable')
                self.assertEqual(result['evidence'], [])

    def test_redirects_not_followed(self):
        self.assertIsNone(public.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.com'))

    def test_network_errors_and_rates(self):
        for status, expected in ((429, 'RATE_LIMITED'), (403, 'ACCESS_RESTRICTED'),
                                 (302, 'ACCESS_RESTRICTED'), (404, 'NOT_AVAILABLE'), (500, 'UPSTREAM_ERROR')):
            with patch.object(public, 'build_opener') as opener:
                opener.return_value.open.side_effect = HTTPError('secret-url', status, 'secret', {}, None)
                result = public.public_profile('@alice')
            self.assertEqual(result['error']['code'], expected)
            self.assertNotIn('secret', json.dumps(result))

    def test_network_failure(self):
        with patch.object(public, 'build_opener') as opener:
            opener.return_value.open.side_effect = URLError('secret')
            self.assertEqual(public.public_profile('@alice')['error']['code'], 'NETWORK_ERROR')

    def test_response_size_limit(self):
        with patch.object(public, 'build_opener') as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.headers.get_content_type.return_value = 'text/html'
            response.read.return_value = b'x' * (public.MAX_BYTES + 1)
            self.assertEqual(public.public_profile('@alice')['error']['code'], 'RESPONSE_TOO_LARGE')

    def test_no_cookie_or_credential_header(self):
        with patch.object(public, 'build_opener') as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.headers.get_content_type.return_value = 'text/html'
            response.read.return_value = b''
            public.fetch_public('https://www.instagram.com/alice/')
            request = opener.return_value.open.call_args.args[0]
            self.assertIsNone(request.get_header('Cookie'))
            self.assertIsNone(request.get_header('Authorization'))


class OAuthTests(unittest.TestCase):
    def test_config_requires_https_and_explicit_version(self):
        for uri in ('http://localhost/instagram/callback', 'https://example.com/wrong',
                    'https://example.com/instagram/callback?code=x', 'https://user@example.com/instagram/callback'):
            with patch.dict(oauth.os.environ, {'IG_APP_ID': '123', 'IG_API_VERSION': 'v25.0', 'IG_REDIRECT_URI': uri}, clear=True):
                with self.assertRaises(oauth.ConnectorError):
                    oauth.config()
        with patch.dict(oauth.os.environ, {'IG_APP_ID': '123', 'IG_API_VERSION': 'v25.0',
                                         'IG_REDIRECT_URI': CFG['redirect_uri']}, clear=True):
            self.assertEqual(oauth.config(), CFG)

    def test_minimal_scope_no_secret_in_auth_url(self):
        query = parse_qs(urlsplit(oauth.authorization_url(CFG, 'state')).query)
        self.assertEqual(query['scope'], ['instagram_business_basic'])
        self.assertNotIn('client_secret', query)
        self.assertEqual(query['state'], ['state'])

    def test_callback_state_expiry_replay(self):
        callback = oauth.Callback('correct')
        self.assertEqual(callback.accept('/instagram/callback?state=wrong&code=x'), 400)
        self.assertFalse(callback.used)
        self.assertEqual(callback.accept('/instagram/callback?state=correct&state=correct&code=x'), 400)
        self.assertEqual(callback.accept('/other?state=correct&code=x'), 404)
        self.assertEqual(callback.accept('/instagram/callback?state=correct&code=ok'), 200)
        self.assertEqual(callback.code, 'ok')
        self.assertEqual(callback.accept('/instagram/callback?state=correct&code=x'), 410)
        expired = oauth.Callback('correct', lifetime=-1)
        self.assertEqual(expired.accept('/instagram/callback?state=correct&code=x'), 410)

    def test_callback_denial_and_malformed_code(self):
        denied = oauth.Callback('state')
        denied.accept('/instagram/callback?state=state&error=access_denied&error_description=secret')
        self.assertEqual(denied.error.code, 'CONSENT_DENIED')
        self.assertNotIn('secret', denied.error.message)
        duplicate = oauth.Callback('state')
        duplicate.accept('/instagram/callback?state=state&code=x&code=y')
        self.assertEqual(duplicate.error.code, 'INVALID_CALLBACK')

    def test_token_shapes(self):
        token = {'access_token': 'secret-token', 'user_id': '42'}
        self.assertEqual(oauth.token_payload(token), token)
        self.assertEqual(oauth.token_payload({'data': [token]}), token)
        for bad in ({}, {'data': []}, {'data': [token, token]}, {'data': [token], **token},
                    {'access_token': 'secret', 'user_id': '../../x'}):
            with self.assertRaises(oauth.ConnectorError):
                oauth.token_payload(bad)

    def test_login_verifies_account_before_save(self):
        backend = Vault()
        with patch.object(oauth, 'wait_for_code', return_value='test-code'), \
             patch.object(oauth, 'api_json', return_value={'access_token': 'secret-token', 'user_id': '42'}), \
             patch.object(oauth, 'graph', return_value={'user_id': '42', 'username': 'alice'}):
            result = oauth.login(CFG, backend, 'alice', 8765, False)
        self.assertEqual(result['status'], 'connected')
        self.assertNotIn('secret-token', json.dumps(result))
        stored = json.loads(backend.values['account:123:alice'])
        self.assertEqual(stored['token'], 'secret-token')
        self.assertLessEqual(stored['expires_at'], time.time() + 3600)

    def test_wrong_account_is_never_saved(self):
        backend = Vault()
        with patch.object(oauth, 'wait_for_code', return_value='test-code'), \
             patch.object(oauth, 'api_json', return_value={'access_token': 'secret-token', 'user_id': '42'}), \
             patch.object(oauth, 'graph', return_value={'user_id': '42', 'username': 'bob'}):
            with self.assertRaises(oauth.ConnectorError) as caught:
                oauth.login(CFG, backend, 'alice', 8765, False)
        self.assertEqual(caught.exception.code, 'ACCOUNT_MISMATCH')
        self.assertNotIn('account:123:alice', backend.values)

    def test_expired_token_never_calls_api(self):
        backend = Vault()
        backend.values['account:123:alice'] = json.dumps({'username': 'alice', 'user_id': '42',
                                                        'token': 'secret', 'expires_at': 0})
        with patch.object(oauth, 'graph') as graph:
            with self.assertRaises(oauth.ConnectorError) as caught:
                oauth.read_account(CFG, backend, 'alice')
            graph.assert_not_called()
        self.assertEqual(caught.exception.code, 'REAUTH_REQUIRED')

    def test_media_output_drops_token_bearing_pagination(self):
        backend = Vault()
        backend.values['account:123:alice'] = json.dumps({'username': 'alice', 'user_id': '42',
                                                        'token': 'secret', 'expires_at': time.time() + 1000})
        with patch.object(oauth, 'graph', side_effect=[{'user_id': '42', 'username': 'alice'},
             {'data': [{'id': '1', 'caption': 'hello', 'access_token': 'secret'}],
              'paging': {'next': 'https://graph.instagram.com?access_token=secret'}}]):
            result = oauth.read_account(CFG, backend, 'alice', media=True)
        self.assertNotIn('secret', json.dumps(result))
        self.assertEqual(result['media'], [{'id': '1', 'caption': 'hello'}])
        self.assertTrue(result['has_more'])

    def test_api_authorization_header_and_redirect_guard(self):
        with patch.object(oauth, 'build_opener') as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = b'{"user_id":"42"}'
            oauth.graph(CFG, 'me', 'secret', fields='user_id,username')
            req = opener.return_value.open.call_args.args[0]
            self.assertEqual(req.get_header('Authorization'), 'Bearer secret')
            self.assertNotIn('secret', req.full_url)
            self.assertIsInstance(opener.call_args.args[0], public.NoRedirect)

    def test_provider_errors_are_sanitized(self):
        for code, status, expected in ((190, 400, 'REAUTH_REQUIRED'), (10, 400, 'PERMISSION_DENIED'),
                                       (4, 400, 'RATE_LIMITED'), (999, 500, 'API_ERROR')):
            with patch.object(oauth, 'build_opener') as opener:
                body = io.BytesIO(json.dumps({'error': {'code': code, 'message': 'secret-token'}}).encode())
                opener.return_value.open.side_effect = HTTPError('secret-url', status, 'secret', {}, body)
                with self.assertRaises(oauth.ConnectorError) as caught:
                    oauth.api_json('https://graph.instagram.com/me')
            self.assertEqual(caught.exception.code, expected)
            self.assertNotIn('secret', str(caught.exception))

    def test_storage_exception_not_echoed(self):
        with patch.object(Vault, 'set_password', side_effect=RuntimeError('secret-token')):
            with self.assertRaises(oauth.ConnectorError) as caught:
                oauth.secret_set(Vault(), 'key', 'secret-token')
            self.assertNotIn('secret-token', str(caught.exception))

    def test_missing_config_cli_returns_json_without_traceback(self):
        output = io.StringIO()
        with patch.dict(oauth.os.environ, {}, clear=True), patch.object(sys, 'argv', ['oauth', 'status', '@alice']), \
             contextlib.redirect_stdout(output):
            self.assertEqual(oauth.main(), 2)
        self.assertEqual(json.loads(output.getvalue())['error']['code'], 'NOT_CONFIGURED')


class CallbackIntegrationTests(unittest.TestCase):
    def test_real_local_callback_without_code_in_output(self):
        import threading
        from urllib.request import urlopen
        actual_server = oauth.HTTPServer
        state = {}
        results = []
        errors = []

        def make_server(address, handler):
            server = actual_server(('127.0.0.1', 0), handler)
            state['port'] = server.server_port
            return server

        def open_browser(url):
            csrf = parse_qs(urlsplit(url).query)['state'][0]
            def send_callback():
                try:
                    target = 'http://127.0.0.1:%s/instagram/callback?state=%s&code=secret-code' % (state['port'], csrf)
                    with urlopen(target, timeout=5) as response:
                        results.append((response.status, response.headers['Cache-Control'], response.read()))
                except Exception as error:
                    errors.append(type(error).__name__)
            state['thread'] = threading.Thread(target=send_callback)
            state['thread'].start()
            return True

        output = io.StringIO()
        with patch.object(oauth, 'HTTPServer', side_effect=make_server), \
             patch.object(oauth.webbrowser, 'open', side_effect=open_browser), \
             contextlib.redirect_stderr(output):
            code = oauth.wait_for_code(CFG, 8765)
            state['thread'].join(timeout=5)
        self.assertEqual(code, 'secret-code')
        self.assertEqual(errors, [])
        self.assertEqual(results[0][:2], (200, 'no-store'))
        self.assertNotIn(b'secret-code', results[0][2])
        self.assertNotIn('secret-code', output.getvalue())

    def test_port_validation(self):
        for port in (0, -1, 65536):
            with self.assertRaises(public.ConnectorError) as caught:
                oauth.wait_for_code(CFG, port)
            self.assertEqual(caught.exception.code, 'INVALID_PORT')


if __name__ == '__main__':
    unittest.main()
