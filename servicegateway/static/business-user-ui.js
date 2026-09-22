let selectedService = '';
let users = [];

export function businessUserUI({api, edit, field, table, badge, button, empty, esc, getOverview}) {
  function serviceChoices() {
    return (getOverview()?.assets ?? []).map(s => [s.id, s.name]);
  }

  async function render() {
    const choices = serviceChoices();
    if (!choices.length) return empty('暂无业务服务', '先登记业务服务，再配置微信登录和业务用户。');
    if (!choices.some(([id]) => id === selectedService)) selectedService = choices[0][0];
    const [status, rows] = await Promise.all([
      api('/api/business-users/wechat-status/' + encodeURIComponent(selectedService)),
      api('/api/business-users?service_id=' + encodeURIComponent(selectedService) + '&limit=200'),
    ]);
    users = rows;
    const select = `<label>服务<select id="business-user-service">${choices.map(([id,name])=>`<option value="${esc(id)}" ${id===selectedService?'selected':''}>${esc(name)} (${esc(id)})</option>`).join('')}</select></label>`;
    const command = `sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl wechat-config --service ${selectedService} --appid 你的小程序AppID`;
    const login = `/_sg/wechat/${selectedService}/login`;
    const list = rows.length ? table(
      ['用户 / OpenID','角色','状态','最近登录','备注','操作'],
      rows.map(u => [
        `<code>${esc(u.user_id.slice(0,12))}</code><small class="row-note">openid: ${esc(u.openid??'—')}</small>`,
        badge(u.role),
        badge(u.enabled?'启用':'停用',u.enabled?'good':'warn'),
        u.last_login_at ? esc(new Date(u.last_login_at).toLocaleString()) : '—',
        esc(u.remark||''),
        `<div class="actions">${button('编辑','business-user-edit',u.user_id)}${button('撤销 Token','business-user-revoke',u.user_id,'danger')}</div>`
      ])
    ) : empty('暂无业务用户', '用户第一次通过微信登录后会自动创建。');
    return `<div class="section-head"><h2>业务用户</h2></div><div class="filters">${select}</div>
      <section class="panel"><p>${badge(status.configured?'微信已配置':'微信未配置',status.configured?'good':'warn')} ${status.appid?`<code>${esc(status.appid)}</code>`:''}</p>
      <p class="hint">AppSecret 不通过网页录入，使用服务器 root 隐藏输入：<code>${esc(command)}</code></p>
      <p class="hint">小程序先调用 wx.login() 取得 code，再 POST 到业务域名的 <code>${esc(login)}</code>；网关返回自己的 Bearer Token，不返回微信 session_key。</p></section>${list}`;
  }

  function bind(reload) {
    const select = document.querySelector('#business-user-service');
    if (select) select.onchange = () => { selectedService = select.value; reload(); };
  }

  async function perform(action, id) {
    if (action === 'business-user-edit') {
      const user = users.find(u => u.user_id === id);
      if (!user) throw new Error('用户不存在，请刷新');
      edit('编辑业务用户',
        field('role','业务角色',user.role) +
        field('display_name','显示名称',user.display_name||'') +
        field('avatar_url','头像 URL',user.avatar_url||'') +
        field('remark','管理员备注',user.remark||'') +
        field('enabled','允许登录和访问',user.enabled,'checkbox') +
        '<p class="hint full">停用用户会立即撤销其全部网关业务 Token。角色仅录响配置了“微信用户角色”的路由；OpenID/UnionID 不能从后台修改。</p>',
        async form => {
          await api('/api/business-users/' + encodeURIComponent(id),'PATCH',{
            role: form.get('role'),
            display_name: form.get('display_name'),
            avatar_url: form.get('avatar_url'),
            remark: form.get('remark'),
            enabled: form.has('enabled'),
          });
        });
      return true;
    }
    if (action === 'business-user-revoke') {
      if (!confirm('撤销该用户全部业务 Token？用户需要重新微信登录。')) return true;
      await api('/api/business-users/' + encodeURIComponent(id) + '/revoke-tokens','POST',{});
      return true;
    }
    return false;
  }

  return {render, bind, perform};
}
