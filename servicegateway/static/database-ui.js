// The database view never stores passwords in localStorage or renders them into HTML.
export function databaseUI({api, edit, field, table, badge, button, empty, esc, getOverview, getUser, showLogin}) {
  async function render() {
    const data = await api('/api/databases');
    const note = data.enabled
      ? '为已登记并获本机批准的业务建库。默认 utf8mb4，一服务一库；不接管同名旧库。'
      : '尚未启用建库。在服务器执行一次：sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl database-enable';
    const rows = data.items.map(r => [
      `${esc(r.database_name)}<small class="row-note">${esc(r.service_id)}</small>`,
      badge(r.status, r.status === 'ready' ? 'good' : 'warn') + `<small class="row-note">${esc(r.stage)}</small>`,
      `<code>${esc(r.accounts.runtime)}</code>`, `<code>${esc(r.accounts.migration)}</code>`,
      r.status === 'ready' && data.enabled ? button('下载连接配置', 'database-download', r.service_id) : '请本机核对'
    ]);
    return `<div class="section-head"><h2>业务数据库</h2>${data.enabled ? button('创建业务库', 'database-new', '', 'primary') : ''}</div>` +
      `<p class="hint">${esc(note)}</p>` +
      `<p class="hint">运行账号仅日常读写；迁移账号可建表、改表、删除本库对象，也能删除自己的库，勿用于日常运行。两者均不授予其他库、建用户或转授权权限。${esc(data.notice)}</p>` +
      (rows.length ? table(['数据库 / 服务', '创建记录', '运行账号', '迁移账号', '操作'], rows) : empty('暂无业务库', '不会扫描或导入服务器上的其他数据库。'));
  }

  async function download(id, form) {
    const account = form.get('account');
    const response = await fetch(`/api/databases/${encodeURIComponent(id)}/credentials`, {
      method: 'POST', cache: 'no-store', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getUser().csrf},
      body: JSON.stringify({current_password: form.get('current_password'), account})
    });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      if (response.status === 401) showLogin();
      throw new Error(typeof data.detail === 'string' ? data.detail : '连接配置下载失败');
    }
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement('a');
    link.href = url; link.download = `database-${id}-${account}.env`;
    document.body.appendChild(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  async function perform(action, id) {
    if (action === 'database-new') {
      const data = await api('/api/databases');
      if (!data.enabled) throw new Error('请先在本机运行 sgctl database-enable');
      const used = new Set(data.items.map(r => r.service_id));
      if (id && used.has(id)) throw new Error('该服务已有建库记录，请到“业务数据库”查看，不会改为给其他服务建库');
      const choices = getOverview().assets.filter(s => !used.has(s.id));
      if (!choices.length) throw new Error('先登记一个尚未建库的业务服务；已创建的数据库在“业务数据库”查看');
      const selected = choices.find(s => s.id === id) ?? choices[0];
      edit('创建业务数据库',
        field('service_id', '所属业务', selected.id, 'select', choices.map(s => [s.id, s.name])) +
        field('database_name', '库名（sgb_ 开头，仅小写字母、数字和下划线）', 'sgb_' + selected.id.replaceAll('-', '_').slice(0, 59)) +
        '<p class="hint full">只创建新业务库和两个随机密码专用账号；同名资源拒绝接管。数据库不是路由草稿，点击确认后立即创建；失败不会通过删库回滚。不会启动业务或开放 3306。</p>',
        async form => { await api('/api/databases', 'POST', {service_id: form.get('service_id'), database_name: form.get('database_name')}); },
        '确认创建');
      return true;
    }
    if (action === 'database-download') {
      edit('下载私有数据库连接配置',
        field('account', '账号用途', 'runtime', 'select', [['runtime', '日常运行：仅读写'], ['migration', '结构迁移：可删除本库数据/结构']]) +
        field('current_password', '当前网站登录密码', '', 'password').replace('new-password', 'current-password') +
        '<p class="hint full">下载的 .env 含该业务数据库密码。不要上传 Git 或发到聊天，不是网关自身数据库或 MySQL root 密码。需要自动建表的程序先使用迁移账号完成建表，再切运行账号。</p>',
        async form => { await download(id, form); document.querySelector('#editor-form').reset(); }, '验证并下载');
      return true;
    }
    return false;
  }
  return {render, perform};
}
