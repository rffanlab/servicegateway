"""Root-only WeChat Mini Program credentials and code exchange.

AppSecret and WeChat session_key never enter the management DB or Web process.
The constrained root Agent performs code2Session and returns only identifiers that
the gateway needs to bind its own opaque business-user token.
"""
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlencode
from urllib.request import ProxyHandler, build_opener, Request
from urllib.error import HTTPError, URLError

STORE = Path("/etc/servicegateway/wechat-apps")
CODE2SESSION = "https://api.weixin.qq.com/sns/jscode2session"
APPID_RE = re.compile(r"^[A-Za-z0-9_-]{6,64}$")
SERVICE_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


class WechatConfigError(ValueError):
    pass


def _service(value):
    if not isinstance(value, str) or not SERVICE_RE.fullmatch(value):
        raise WechatConfigError("Invalid service id")
    return value


def _safe_dir():
    for parent in STORE.parents:
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise WechatConfigError("Unsafe WeChat credential parent directory")
    STORE.mkdir(mode=0o700, exist_ok=True)
    st = STORE.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise WechatConfigError("WeChat credential directory must be root-owned 0700")


def _path(service_id):
    return STORE / (_service(service_id) + ".json")


def _read(service_id):
    from .agent import root_file
    path = root_file(_path(service_id))
    if stat.S_IMODE(path.stat().st_mode) != 0o600 or path.stat().st_size > 8192:
        raise WechatConfigError("Unsafe WeChat credential file")
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        raise WechatConfigError("Invalid WeChat credential file") from None
    if data.get("service_id") != service_id or not APPID_RE.fullmatch(data.get("appid", "")):
        raise WechatConfigError("Invalid WeChat credential file")
    secret = data.get("appsecret", "")
    if not isinstance(secret, str) or not 16 <= len(secret) <= 128 or any(ord(ch) < 33 for ch in secret):
        raise WechatConfigError("Invalid WeChat AppSecret")
    return data


def status(service_id):
    try:
        data = _read(service_id)
        return {"configured": True, "appid": data["appid"]}
    except (OSError, WechatConfigError, ValueError):
        return {"configured": False, "appid": None}


def configure(service_id, appid, appsecret):
    if os.geteuid() != 0:
        raise WechatConfigError("Local root is required to configure WeChat")
    _service(service_id)
    if not isinstance(appid, str) or not APPID_RE.fullmatch(appid):
        raise WechatConfigError("Invalid Mini Program AppID")
    if not isinstance(appsecret, str) or not 16 <= len(appsecret) <= 128 or any(ord(ch) < 33 for ch in appsecret):
        raise WechatConfigError("Invalid Mini Program AppSecret")
    _safe_dir()
    from .agent import atomic_write
    path = _path(service_id)
    if path.exists() or path.is_symlink():
        _read(service_id)
    atomic_write(path, json.dumps({
        "service_id": service_id,
        "appid": appid,
        "appsecret": appsecret,
    }, indent=2) + "\n", 0o600)
    return {"configured": True, "appid": appid}


def remove(service_id):
    if os.geteuid() != 0:
        raise WechatConfigError("Local root is required to remove WeChat configuration")
    path = _path(service_id)
    if not path.exists() and not path.is_symlink():
        return False
    from .agent import root_file
    root_file(path)
    path.unlink()
    directory = os.open(STORE, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return True


def exchange_code(service_id, code, opener=None):
    data = _read(service_id)
    if not isinstance(code, str) or not 1 <= len(code) <= 256 or any(ord(ch) < 33 or ord(ch) > 126 for ch in code):
        raise WechatConfigError("Invalid WeChat login code")
    query = urlencode({
        "appid": data["appid"],
        "secret": data["appsecret"],
        "js_code": code,
        "grant_type": "authorization_code",
    })
    opener = opener or build_opener(ProxyHandler({}))
    request = Request(CODE2SESSION + "?" + query, headers={"Accept": "application/json", "User-Agent": "ServiceGateway/0.1"})
    try:
        with opener.open(request, timeout=8) as response:
            raw = response.read(32769)
    except (HTTPError, URLError, TimeoutError, OSError):
        raise WechatConfigError("WeChat login service unavailable") from None
    if len(raw) > 32768:
        raise WechatConfigError("WeChat login response exceeds limit")
    try:
        payload = json.loads(raw)
    except ValueError:
        raise WechatConfigError("Invalid WeChat login response") from None
    if payload.get("errcode") not in (None, 0):
        code_value = payload.get("errcode")
        if not isinstance(code_value, int):
            code_value = "unknown"
        raise WechatConfigError(f"WeChat login rejected ({code_value})")
    openid = payload.get("openid", "")
    unionid = payload.get("unionid")
    if not isinstance(openid, str) or not 1 <= len(openid) <= 128:
        raise WechatConfigError("WeChat login response missing openid")
    if unionid is not None and (not isinstance(unionid, str) or len(unionid) > 128):
        raise WechatConfigError("Invalid WeChat unionid")
    # Deliberately discard session_key. It is neither logged nor returned to Web.
    return {"appid": data["appid"], "openid": openid, "unionid": unionid}
