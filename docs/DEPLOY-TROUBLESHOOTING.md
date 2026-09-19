# 部署排障：Bash pipefail / CRLF 换行

## 症状

执行 `sudo bash deploy/full-deploy.sh ...` 后，在第 2 行立即出现
`set: pipefail: invalid option name`，有时 `: invalid option name` 显示在行首。

先运行 `sed -n '1,4l' deploy/full-deploy.sh`。正常行尾显示 `$`；
若为 `\r$`，说明工作副本带有 CRLF 回车。Bash 把它读成 `pipefail\r`，
不是合法的选项名。仓库原脚本为 LF；可能是本地 checkout、编辑或传输转换了换行，
不能仅凭错误确定是哪一个环节。不要删掉 `pipefail`，也不要改用 `sh`。

## 修复工作副本

在仓库根目录执行（不需要 root，只处理 deploy 下的 Shell 脚本）：

```bash
find deploy -type f -name '*.sh' -exec sed -i.crlf-backup 's/\r$//' {} + && bash deploy/full-deploy.sh --dry-run
```

每个被处理的脚本留下 `.crlf-backup` 备份；再次执行同一命令会覆盖同名备份，
需要长期保留时先把备份移到仓库外。不要对 `/etc`、数据库、证书或整个磁盘递归转换。
这一步只修复行尾并显示部署计划，不安装包，不改防火墙或业务配置。

预览成功后，再按 FULL-DEPLOYMENT.md 运行原来的安装命令。邮箱和其他参数保持完整一行，
终端自动折行显示不影响命令，手动插入换行则会拆开参数。

## 防止复发

仓库的 `.gitattributes` 固定文本文件 checkout 为 LF，`.editorconfig` 提示支持它的编辑器
使用 UTF-8（无 BOM）和 LF。新增的测试检查部署文件字节、CRLF 错误复现与备份修复，
并验证 `core.autocrlf=true` / `core.eol=crlf` 下的 Git checkout 仍为 LF。

更新仓库不会保证重写已经存在或被编辑器再次转换的本地文件；已有错误副本仍需上面的修复。
只修改当前仓库的 Git 偏好可以执行 `git config --local core.autocrlf input`，无需改变全局设置。
不要使用 `git reset --hard` 丢弃本地修改来排查此问题。

此错误发生在调用 Python 部署器之前，不能归因于 Nginx、MySQL 或证书签发配置。
完成行尾修复仅说明入口恢复，后续部署阶段仍可能独立报错。
