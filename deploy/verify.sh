#!/usr/bin/env bash
set -Eeuo pipefail
for unit in servicegateway.service servicegateway-agent.service servicegateway-edge.service; do systemctl is-active --quiet "$unit"; done
curl -fsS --max-time 5 http://127.0.0.1:19092/healthz
curl -fsS --max-time 5 http://127.0.0.1:19092/readyz
curl -fsS --max-time 5 http://127.0.0.1:19093/_sg/ready
[[ $(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:19092/api/overview) == 401 ]]
[[ $(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:19092/internal/auth) == 403 ]]
ss -H -ltn 'sport = :19092' | grep -q '127.0.0.1:19092'
[[ $(stat -c '%a' /run/servicegateway-agent/agent.sock) == 660 ]]
[[ $(stat -c '%U' /etc/servicegateway/policy.json) == root ]]
nginx -t -c /etc/servicegateway/nginx.conf
printf '\n基础验收通过。仍需测试实际业务路由、SSE/WS、启停和发布失败回滚。\n'
