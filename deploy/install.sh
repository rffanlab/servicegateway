#!/usr/bin/env bash
set -Eeuo pipefail
# Run from a reviewed checkout. No curl|bash, package-manager changes or old E5 replacement.
[[ $EUID -eq 0 ]] || { echo '请用 sudo bash deploy/install.sh'; exit 1; }
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
for bin in python3 nginx systemctl curl ss busctl; do command -v "$bin" >/dev/null || { echo "缺少依赖: $bin"; exit 1; }; done
nginx -V 2>&1 | grep -q http_auth_request_module || { echo 'Nginx 缺少 auth_request 模块'; exit 1; }
BASE=/srv/e5-apps/servicegateway
CFG=/etc/servicegateway
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT
old=$(readlink -f "$BASE/current" || true)
if [[ ! -f "$CFG/app.env" ]]; then
    install -d -m 0750 "$CFG"
    install -m 0600 "$ROOT/.env.example" "$CFG/app.env"
    echo "已生成 $CFG/app.env。请配置独立 MySQL 与 HTTPS 管理域名；先阅读 docs/REMOTE-SECURITY.md。"
    exit 1
fi
if grep -q REPLACE_WITH "$CFG/app.env"; then echo '请先配置 app.env 中的 MySQL 凭据'; exit 1; fi
if [[ -z "$old" ]]; then
    for port in 19091 19092 19093; do
        if ss -H -ltn "sport = :$port" | grep -q .; then echo "端口 $port 已占用，拒绝覆盖现有服务"; exit 1; fi
    done
fi
id servicegateway >/dev/null 2>&1 || useradd --system --home /srv/e5-data/servicegateway --shell /usr/sbin/nologin servicegateway
install -d -o root -g servicegateway -m 0750 "$CFG"
for d in /srv/e5-data/servicegateway /srv/e5-workspaces/servicegateway; do install -d -o servicegateway -g servicegateway -m 0750 "$d"; done
# Root master must NEVER open logs in an application-writable directory (symlink risk).
[[ ! -L /srv/e5-logs/servicegateway ]] || { echo '日志目录是符号链接，拒绝部署'; exit 1; }
install -d -o root -g servicegateway -m 0750 /srv/e5-logs/servicegateway
for log in edge-access.log edge-error.log; do
    path="/srv/e5-logs/servicegateway/$log"
    [[ ! -L "$path" ]] || { echo '日志文件是符号链接，拒绝部署'; exit 1; }
    if [[ -e "$path" ]]; then
        [[ -f "$path" && $(stat -c '%h' "$path") == 1 ]] || { echo '日志不是独立普通文件'; exit 1; }
    fi
    touch "$path"
    chown root:servicegateway "$path"
    chmod 0640 "$path"
done
# Nginx's master creates logs; workers need traverse/write access for temp files only.
install -d -o root -g root -m 0755 /var/lib/servicegateway /var/lib/servicegateway/edge
install -d -o www-data -g www-data -m 0700 /var/lib/servicegateway/edge/client /var/lib/servicegateway/edge/proxy
install -d -m 0750 "$CFG/certs"
[[ -f "$CFG/policy.json" ]] || install -o root -g servicegateway -m 0640 "$ROOT/deploy/policy.example.json" "$CFG/policy.json"
if [[ ! -f "$CFG/auth-secret" ]]; then python3 -c 'import secrets; print(secrets.token_hex(32))' > "$CFG/auth-secret"; fi
chown root:servicegateway "$CFG/auth-secret"
chmod 0640 "$CFG/auth-secret"
version=$(date -u +%Y%m%dT%H%M%SZ)-$(python3 -c 'import secrets;print(secrets.token_hex(3))')
release="$BASE/releases/$version"
install -d -o root -g root -m 0755 "$BASE/releases" "$release"
tar -C "$ROOT" --exclude=.git --exclude=.venv --exclude=.env --exclude=__pycache__ --exclude=.pytest_cache --exclude='*.db' -cf - . | tar -C "$release" -xf -
python3 -m venv "$release/.venv"
"$release/.venv/bin/pip" install --disable-pip-version-check "$release"
chown -R root:root "$release"
chmod -R go-w "$release"
# Root-only env files are parsed by systemd, not sourced/evaluated as shell.
cd "$release"
set +e
systemd-run --quiet --wait --pipe --collect --unit="sg-migrate-$version" -p "EnvironmentFile=$CFG/app.env" -p "WorkingDirectory=$release" "$release/.venv/bin/python" -m servicegateway.preflight --migrate
migration_rc=$?
set -e
[[ $migration_rc -eq 0 ]] || { echo '数据库迁移失败；尚未切换运行版本'; exit 1; }
for file in servicegateway.service servicegateway-agent.service servicegateway-edge.service; do [[ ! -f "/etc/systemd/system/$file" ]] || cp -a "/etc/systemd/system/$file" "$WORK/$file"; done
[[ ! -f /etc/nginx/conf.d/servicegateway-console.conf ]] || cp -a /etc/nginx/conf.d/servicegateway-console.conf "$WORK/console.conf"
changed=0
rollback() {
    rc=$?
    trap - ERR
    if [[ $changed -eq 1 ]]; then
        echo '部署验收失败，恢复原运行版本；不回退/删除数据库。'
        systemctl stop servicegateway.service servicegateway-agent.service || true
        if [[ -n "$old" ]]; then ln -sfn "$old" "$BASE/current"; else rm -f "$BASE/current"; fi
        for file in servicegateway.service servicegateway-agent.service servicegateway-edge.service; do
            if [[ -f "$WORK/$file" ]]; then cp -a "$WORK/$file" "/etc/systemd/system/$file"; else systemctl disable --now "$file" || true; rm -f "/etc/systemd/system/$file"; fi
        done
        if [[ -f "$WORK/console.conf" ]]; then cp -a "$WORK/console.conf" /etc/nginx/conf.d/servicegateway-console.conf; else rm -f /etc/nginx/conf.d/servicegateway-console.conf; fi
        systemctl daemon-reload
        [[ -z "$old" ]] || systemctl start servicegateway-agent.service servicegateway.service || true
        nginx -t && systemctl reload nginx.service || true
    fi
    exit "$rc"
}
trap rollback ERR
changed=1
ln -sfn "$release" "$BASE/current"
for file in servicegateway.service servicegateway-agent.service servicegateway-edge.service; do install -o root -g root -m 0644 "$release/deploy/$file" "/etc/systemd/system/$file"; done
systemd-analyze verify /etc/systemd/system/servicegateway{,-agent,-edge}.service
"$release/.venv/bin/sgctl" init-edge
systemctl daemon-reload
systemctl enable --now servicegateway-edge.service
systemctl enable servicegateway-agent.service servicegateway.service
systemctl restart servicegateway-agent.service servicegateway.service
healthy=0
for i in $(seq 1 30); do if curl -fsS --max-time 2 http://127.0.0.1:19092/readyz >/dev/null; then healthy=1; break; fi; sleep 1; done
[[ $healthy -eq 1 ]]
install -o root -g root -m 0644 "$release/deploy/nginx-console.conf" /etc/nginx/conf.d/servicegateway-console.conf
nginx -t
systemctl reload nginx.service
install -o root -g root -m 0644 "$release/deploy/logrotate.conf" /etc/logrotate.d/servicegateway
bash "$release/deploy/verify.sh"
trap - ERR
echo '本机组件部署完成；管理入口仅监听 127.0.0.1:19091，未开放公网。请继续 docs/REMOTE-SECURITY.md 验收。'
echo '创建管理员（交互输入，不在参数中放密码）：'
echo "sudo systemd-run --quiet --wait --pty --collect -p EnvironmentFile=$CFG/app.env -p WorkingDirectory=$release $release/.venv/bin/sgctl admin rffanlab"
