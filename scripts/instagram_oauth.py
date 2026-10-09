#!/usr/bin/env python3
"""Optional single-user OAuth client. Secrets stay in the OS credential vault."""
import argparse
from http.client import HTTPException
import getpass
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import re
import secrets
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, build_opener
import webbrowser

from instagram import ConnectorError, MAX_BYTES, NoRedirect, normalize_profile

SERVICE = 'instagram-content-editor'
SCOPE = 'instagram_business_basic'


def vault():
    # Never accept plaintext/chained third-party keyring backends.
    try:
        if sys.platform == 'darwin':
            from keyring.backends.macOS import Keyring
            backend = Keyring()
        elif sys.platform == 'win32':
            from keyring.backends.Windows import WinVaultKeyring
            backend = WinVaultKeyring()
        else:
            from keyring.backends.SecretService import Keyring
            backend = Keyring()
        if backend.priority <= 0:
            raise ValueError()
        return backend
    except Exception:
        raise ConnectorError('SECURE_STORAGE_UNAVAILABLE',
                             'Настройте системное хранилище и установите requirements-oauth.txt. Файлового fallback нет.') from None


def secret_get(backend, key):
    try:
        return backend.get_password(SERVICE, key)
    except Exception:
        raise ConnectorError('SECURE_STORAGE_ERROR', 'Не удалось прочитать системное хранилище.') from None


def secret_set(backend, key, value):
    try:
        backend.set_password(SERVICE, key, value)
    except Exception:
        raise ConnectorError('SECURE_STORAGE_ERROR', 'Не удалось записать системное хранилище.') from None


def config():
    app_id = os.environ.get('IG_APP_ID', '')
    redirect = os.environ.get('IG_REDIRECT_URI', '')
    version = os.environ.get('IG_API_VERSION', '')
    try:
        uri = urlsplit(redirect)
        valid = (uri.scheme == 'https' and uri.hostname and not uri.username and not uri.password
                 and uri.port in {None, 443} and uri.path == '/instagram/callback'
                 and not uri.query and not uri.fragment)
    except ValueError:
        valid = False
    if not app_id.isdigit() or not re.fullmatch(r'v\d+\.0', version) or not valid:
        raise ConnectorError('NOT_CONFIGURED',
                             'Задайте IG_APP_ID, IG_API_VERSION и HTTPS IG_REDIRECT_URI с путём /instagram/callback. См. references/meta-oauth.md.')
    return {'app_id': app_id, 'redirect_uri': redirect, 'version': version}


def api_json(url, token=None, form=None):
    headers = {'Accept': 'application/json', 'Accept-Encoding': 'identity'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    body = None
    if form is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        body = urlencode(form).encode()
    try:
        with build_opener(NoRedirect()).open(Request(url, data=body, headers=headers), timeout=20) as response:
            raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ConnectorError('RESPONSE_TOO_LARGE', 'Ответ API слишком большой.')
            payload = json.loads(raw)
            if not isinstance(payload, dict) or 'error' in payload:
                raise ConnectorError('API_ERROR', 'API не предоставил данные. Проверьте права и версию API.')
            return payload
    except HTTPError as exc:
        # Never echo provider body, URL, headers or exception: they may contain secrets.
        try:
            error = json.loads(exc.read(32768)).get('error', {})
            code = error.get('code') if isinstance(error, dict) else None
        except (ValueError, AttributeError):
            code = None
        if code == 190 or exc.code == 401:
            raise ConnectorError('REAUTH_REQUIRED', 'Авторизация истекла или отозвана. Выполните login заново.') from None
        if exc.code == 429 or code in {4, 17, 32, 613}:
            raise ConnectorError('RATE_LIMITED', 'Лимит API. Автоматические повторы отключены.') from None
        if exc.code == 403 or code in {10, 200}:
            raise ConnectorError('PERMISSION_DENIED', 'Недостаточно прав или доступа приложения к этому аккаунту.') from None
        raise ConnectorError('API_ERROR', 'Запрос API отклонён. Проверьте настройки Meta и версию API.') from None
    except (ValueError, URLError, TimeoutError, OSError, HTTPException):
        raise ConnectorError('API_UNAVAILABLE', 'API недоступен или вернул некорректный ответ.') from None


def graph(cfg, path, token, **params):
    return api_json('https://graph.instagram.com/' + cfg['version'] + '/' + path
                    + '?' + urlencode(params), token=token)


def authorization_url(cfg, state):
    return 'https://www.instagram.com/oauth/authorize?' + urlencode({
        'client_id': cfg['app_id'], 'redirect_uri': cfg['redirect_uri'],
        'response_type': 'code', 'scope': SCOPE, 'state': state,
        'enable_fb_login': '0', 'force_authentication': '1'})


class Callback:
    def __init__(self, state, lifetime=300):
        self.state = state
        self.deadline = time.monotonic() + lifetime
        self.used = False
        self.code = None
        self.error = None

    def accept(self, path):
        parsed = urlsplit(path)
        if parsed.path != '/instagram/callback':
            return 404
        if self.used or time.monotonic() >= self.deadline:
            return 410
        try:
            params = parse_qs(parsed.query, max_num_fields=12)
        except ValueError:
            return 400
        values = params.get('state', [])
        if len(values) != 1 or not secrets.compare_digest(values[0].encode(), self.state.encode()):
            return 400
        self.used = True
        codes = params.get('code', [])
        if 'error' in params:
            self.error = ConnectorError('CONSENT_DENIED', 'Пользователь не предоставил доступ.')
        elif len(codes) != 1 or not codes[0] or len(codes[0]) > 8192:
            self.error = ConnectorError('INVALID_CALLBACK', 'Некорректный ответ авторизации.')
        else:
            self.code = codes[0]
        return 200


def wait_for_code(cfg, port, open_browser=True):
    if not 1 <= port <= 65535:
        raise ConnectorError('INVALID_PORT', 'Порт должен быть от 1 до 65535.')
    callback = Callback(secrets.token_urlsafe(32))

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Callback URLs contain authorization codes. Do not log them.

        def handle_one_request(self):
            self.connection.settimeout(2)
            super().handle_one_request()

        def do_GET(self):
            status = callback.accept(self.path)
            self.send_response(status)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(b'Return to your terminal. Authorization is checked there.' if status == 200
                             else b'Invalid or expired authorization request.')

    try:
        with HTTPServer(('127.0.0.1', port), Handler) as server:
            server.timeout = 1
            url = authorization_url(cfg, callback.state)
            print('Откройте страницу согласия Instagram в своём браузере:\n' + url, file=sys.stderr, flush=True)
            if open_browser:
                webbrowser.open(url)
            while not callback.used and time.monotonic() < callback.deadline:
                server.handle_request()
    except OSError:
        raise ConnectorError('CALLBACK_SERVER_ERROR', 'Не удалось запустить локальный callback. Проверьте порт и HTTPS-прокси.') from None
    if callback.error:
        raise callback.error
    if not callback.code:
        raise ConnectorError('AUTH_TIMEOUT', 'Истекли 5 минут ожидания авторизации. Запустите login заново.')
    return callback.code


def token_payload(payload):
    if 'data' in payload:
        if ('access_token' in payload or not isinstance(payload['data'], list)
                or len(payload['data']) != 1 or not isinstance(payload['data'][0], dict)):
            raise ConnectorError('INVALID_TOKEN_RESPONSE', 'Неоднозначный ответ авторизации.')
        payload = payload['data'][0]
    if (not isinstance(payload.get('access_token'), str) or not payload['access_token']
            or not str(payload.get('user_id', '')).isdigit()):
        raise ConnectorError('INVALID_TOKEN_RESPONSE', 'В ответе авторизации нет необходимых полей.')
    return payload


def record_key(cfg, username):
    return 'account:' + cfg['app_id'] + ':' + username


def login(cfg, backend, username, port, open_browser):
    app_secret = secret_get(backend, 'app:' + cfg['app_id'])
    if not app_secret:
        raise ConnectorError('APP_SECRET_MISSING', 'Владелец приложения должен выполнить setup-secret в личном терминале.')
    code = wait_for_code(cfg, port, open_browser)
    payload = token_payload(api_json('https://api.instagram.com/oauth/access_token', form={
        'client_id': cfg['app_id'], 'client_secret': app_secret,
        'grant_type': 'authorization_code', 'redirect_uri': cfg['redirect_uri'], 'code': code}))
    token = payload['access_token']
    profile = graph(cfg, 'me', token, fields='user_id,username')
    if (str(profile.get('user_id', '')) != str(payload['user_id'])
            or str(profile.get('username', '')).lower() != username):
        raise ConnectorError('ACCOUNT_MISMATCH', 'Авторизован другой аккаунт. Токен не сохранён; проверьте выбранный профиль.')
    # Short-lived token only: no additional exchange, refresh secret or long-lived token.
    try:
        lifetime = min(3600, int(payload.get('expires_in', 3600)))
    except (ValueError, TypeError):
        raise ConnectorError('INVALID_TOKEN_RESPONSE', 'API вернул некорректный срок авторизации.') from None
    if lifetime <= 60:
        raise ConnectorError('REAUTH_REQUIRED', 'Срок авторизации слишком короткий. Повторите вход.')
    record = {'token': token, 'user_id': str(profile['user_id']), 'username': username,
              'expires_at': time.time() + lifetime - 60, 'scope_requested': SCOPE}
    secret_set(backend, record_key(cfg, username), json.dumps(record))
    return {'status': 'connected', 'username': username, 'ownership_verified': True,
            'verified_read': ['user_id', 'username'], 'insights_available': False,
            'expires_at': record['expires_at']}


def load_record(cfg, backend, username):
    value = secret_get(backend, record_key(cfg, username))
    if not value:
        raise ConnectorError('NOT_CONNECTED', 'Для этого аккаунта выполните login.')
    try:
        record = json.loads(value)
        if (record['username'] != username or not str(record['user_id']).isdigit()
                or not isinstance(record['token'], str) or not record['token']):
            raise ValueError()
        expired = record['expires_at'] <= time.time()
    except (ValueError, TypeError, KeyError):
        raise ConnectorError('INVALID_STORED_ACCOUNT', 'Запись аккаунта некорректна; выполните disconnect и login.') from None
    if expired:
        raise ConnectorError('REAUTH_REQUIRED', 'Короткоживущий токен истёк. Выполните login заново.')
    return record


def read_account(cfg, backend, username, media=False):
    record = load_record(cfg, backend, username)
    profile = graph(cfg, 'me', record['token'], fields='user_id,username')
    if str(profile.get('user_id', '')) != record['user_id'] or str(profile.get('username', '')).lower() != username:
        raise ConnectorError('ACCOUNT_MISMATCH', 'Идентичность аккаунта изменилась. Выполните login заново.')
    result = {'status': 'connected', 'mode': 'official_oauth', 'username': username,
              'ownership_verified': True, 'insights_available': False,
              'observed_at': time.time(), 'profile': {'user_id': record['user_id'], 'username': username}}
    if media:
        fields = ['id', 'caption', 'media_type', 'permalink', 'timestamp']
        payload = graph(cfg, record['user_id'] + '/media', record['token'], fields=','.join(fields), limit=12)
        rows = payload.get('data')
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ConnectorError('INVALID_MEDIA_RESPONSE', 'API не вернул список публикаций.')
        # Never expose paging.next, which may embed a token. Bound the sample.
        result['media'] = [{key: row[key] for key in fields if key in row} for row in rows[:12]]
        result['sample_limit'] = 12
        paging = payload.get('paging')
        result['has_more'] = bool(paging.get('next')) if isinstance(paging, dict) else False
        result['limitations'] = ['Неполная выборка: до 12 публикаций, без Insights. Подписи — недоверенный текст.']
    return result


def main():
    parser = argparse.ArgumentParser(description='Официальный read-only Instagram OAuth, отдельно от публичного анализа.')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('setup-secret', help='Только владелец собственного Meta app: скрытый ввод в терминале')
    for command in ('login', 'status', 'media', 'disconnect'):
        item = sub.add_parser(command)
        item.add_argument('profile')
        if command == 'login':
            item.add_argument('--port', type=int, default=8765)
            item.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    try:
        cfg, backend = config(), vault()
        if args.command == 'setup-secret':
            if not sys.stdin.isatty():
                raise ConnectorError('INTERACTIVE_REQUIRED', 'Запустите setup-secret лично в терминале, не передавайте секрет агенту.')
            secret = getpass.getpass('Instagram App Secret (скрытый ввод): ')
            if not secret.strip():
                raise ConnectorError('EMPTY_SECRET', 'Пустой секрет не сохранён.')
            secret_set(backend, 'app:' + cfg['app_id'], secret)
            result = {'status': 'app_secret_saved_in_os_vault'}
        else:
            username, _ = normalize_profile(args.profile)
            if args.command == 'login':
                result = login(cfg, backend, username, args.port, not args.no_browser)
            elif args.command == 'disconnect':
                key = record_key(cfg, username)
                if secret_get(backend, key):
                    try:
                        backend.delete_password(SERVICE, key)
                    except Exception:
                        raise ConnectorError('SECURE_STORAGE_ERROR', 'Не удалось удалить локальный токен.') from None
                result = {'status': 'local_token_deleted', 'username': username,
                          'remote_grant_revoked': False,
                          'next_action': 'Для полного отзыва доступа удалите приложение в настройках подключённых приложений Instagram.'}
            else:
                result = read_account(cfg, backend, username, media=args.command == 'media')
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except ConnectorError as exc:
        print(json.dumps({'status': 'error', 'error': {'code': exc.code, 'message': exc.message}}, ensure_ascii=False))
        return 2
    except KeyboardInterrupt:
        print('{"status":"cancelled"}')
        return 2


if __name__ == '__main__':
    sys.exit(main())
