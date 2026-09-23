"""Root-only WeChat Mini Program credentials and code2Session exchange.

The web process never reads AppSecret.  The root Agent performs one exact
outbound call, validates the response and returns only stable identity fields.
session_key is deliberately discarded and never stored/logged.
"""
import getpass
import json
import os
from pathlib import Path
import re
import stat

import httpx

STORE = Path('/etc/servicegateway/wechat')
APPID = re.compile(r'^wx[0-9A-Fa-f]{16}$')
SECRET = re.compile(r'^[A-Za-z0-9_-]{16,128}$')
CODE = re.compile(r'^[A-Za-z0-9_-]{1,256}$')
IDENTITY = re.compile(r'^[A-Za-z0-9_-]{1,128}$')


class WechatError(ValueError):
    pass


def _service_id(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', value):
        raise WechatError('Invalid service id')
    return value


def _dir():
    for parent in STORE.parents:
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise WechatError('Unsafe WeChat credential parent directory')
    STORE.mkdir(mode=0o700, exist_ok=True)
    st = STORE.lstat()
    if st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700 or not stat.S_ISDIR(st.st_mode):
        raise WechatError('WeChat credential directory must be root-owned 0700')


def _path(service_id):
    return STORE / (_service_id(service_id) + '.json')


def read(service_id):
    from .agent import root_file
    path = root_file(_path(service_id))
    if stat.S_IMODE(path.stat().st_mode) != 0o600 or path.stat().st_size > 8192:
        raise WechatError('Unsafe WeChat credential file')
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        raise WechatError('Invalid WeChat credential file') from None
    if (data.get('service_id') != service_id or not APPID.fullmatch(data.get('appid', ''))
            or not SECRET.fullmatch(data.get('app_secret', '')) or type(data.get('enabled')) is not bool):
        raise WechatError('Invalid WeChat credential file')
    return data


def status(service_id):
    try:
        data = read(service_id)
    except (OSError, WechatError, ValueError):
        return {'configured': False, 'enabled': False, 'appid': None}
    return {'configured': True, 'enabled': data['enabled'], 'appid': data['appid']}


def configure(service_id, appid, enabled=True, ask_secret=True):
    if os.geteuid() != 0:
        raise WechatError('Local root is required')
    _service_id(service_id)
    if not APPID.fullmatch(appid or ''):
        raise WechatError('AppID must look like wx + 16 hex characters')
    _dir()
    old = None
    try:
        old = read(service_id)
    except (OSError, WechatError, ValueError):
        pass
    secret = getpass.getpass('微信小程序 AppSecret（隐藏输入）: ') if ask_secret else (old or {}).get('app_secret', '')
    if not SECRET.fullmatch(secret or ''):
        raise WechatError('Invalid AppSecret format')
    from .agent import atomic_write
    atomic_write(_path(service_id), json.dumps({
        'service_id': service_id, 'appid': appid, 'app_secret': secret, 'enabled': bool(enabled)
    }, ensure_ascii=False, indent=2) + '\n', 0o600)
    return status(service_id)


def disable(service_id):
    if os.geteuid() != 0:
        raise WechatError('Local root is required')
    data = read(service_id)
    data['enabled'] = False
    from .agent import atomic_write
    atomic_write(_path(service_id), json.dumps(data, ensure_ascii=False, indent=2) + '\n', 0o600)
    return status(service_id)


def exchange_code(service_id, code):
    data = read(service_id)
    if not data['enabled']:
        raise WechatError('WeChat login is disabled for this service')
    if not isinstance(code, str) or not CODE.fullmatch(code):
        raise WechatError('Invalid WeChat login code')
    try:
        with httpx.Client(timeout=5.0, follow_redirects=False, trust_env=False) as client:
            response = client.get('https://api.weixin.qq.com/sns/jscode2session', params={
                'appid': data['appid'],
                'secret': data['app_secret'],
                'js_code': code,
                'grant_type': 'authorization_code',
            })
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError):
        raise WechatError('WeChat login service unavailable') from None
    if payload.get('errcode') not in (None, 0):
        code_value = payload.get('errcode')
        raise WechatError(f'WeChat login rejected ({code_value})')
    openid = payload.get('openid')
    unionid = payload.get('unionid')
    if not isinstance(openid, str) or not IDENTITY.fullmatch(openid):
        raise WechatError('WeChat response did not contain a valid openid')
    if unionid is not None and (not isinstance(unionid, str) or not IDENTITY.fullmatch(unionid)):
        raise WechatError('WeChat response contained an invalid unionid')
    # session_key is intentionally discarded here.
    return {'appid': data['appid'], 'openid': openid, 'unionid': unionid}
