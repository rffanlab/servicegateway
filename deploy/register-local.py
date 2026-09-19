#!/usr/bin/env python3
"""Submit a local business manifest with an exact-scoped registration key.

Standard library only. No proxy, redirect, password arguments, or arbitrary URL.
The server still checks root-approved service grants. This command does not grant
privileges, start/stop a service, or publish a public gateway route.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import stat
import sys


def key_from_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError('Key file must be an owned regular file with mode 0600')
        key = stream.read(201).strip()
    if not key.startswith('sg_') or len(key) > 200 or any(c.isspace() or ord(c) < 32 for c in key):
        raise ValueError('Invalid registration key')
    return key


def submit(manifest, key_file):
    with Path(manifest).open('rb') as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError('Manifest exceeds 64 KiB')
    if not isinstance(json.loads(data), dict):
        raise ValueError('Manifest must be a JSON object')
    key = key_from_file(key_file)
    connection = http.client.HTTPConnection('127.0.0.1', 19092, timeout=30)
    try:
        connection.request('POST', '/internal/registry/services', body=data,
                           headers={'Content-Type': 'application/json', 'X-Gateway-Key': key})
        response = connection.getresponse()
        raw = response.read(8192)
        if response.status != 200:
            # Do not relay potentially hostile response bodies or ever echo the key.
            raise ValueError(f'Local registration failed: HTTP {response.status}; check service grant, key scope and application audit')
        result = json.loads(raw)
        print(json.dumps({k: result.get(k) for k in ('id', 'changed', 'revision')}, ensure_ascii=False))
    finally:
        connection.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', required=True, type=Path)
    p.add_argument('--key-file', required=True, type=Path)
    args = p.parse_args()
    try:
        submit(args.manifest, args.key_file)
    except (ValueError, OSError, http.client.HTTPException) as exc:
        print(f'提交失败：{exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
