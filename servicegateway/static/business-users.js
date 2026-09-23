let selectedService = '';

export function businessUserUI({api, edit, field, table, badge, button, empty, esc, getOverview}) {
  async function render() {
    const services = getOverview().assets;
    if (!services.length) return empty('暂无业务服务', '先登记服务，再配置微信登录。');
    if (!services.some(s => s.id === selectedService)) selectedService = services[0].id;
    const [users, wechat] = await Promise.all([
      api('/api/business-users?service_id=' + encodeURIComponent(selectedService)),
      api('/api/business-auth/wechat/' + encodeURIComponent(selectedService)),
    ]);
    const serviceOptions = services.map(s => `<option value="${esc(s.id)}" ${s.id===selectedService?'selected':''}>${esc(s.name)} · ${esc(s.id)}</option>`).join('');
    const rows = users.map(u => [
      `<code>${esc(u.id.slice(0,12))}</code><small class="row-note">${esc(u.display_name || '未设置显示名')}</small>`,
      `${badge(u.role)} ${badge(u.enabled?'启用':'停用',u.enabled?'good':'bad')}`,
      u.wechat ? `<code>${esc(u.wechat.openid)}</code><small class="row-note">AppID: ${esc(u.wechat.appid)}${u.wechat.unionid?' · UnionID 已记录':''}</small>` : '无微信身份',
      `${esc(u.last_login_at ? new Date(u.last_login_at).toLocaleString() : '从未登录')}<small class="row-note">${esc(u.remark || '')}</small>`,
      `<div class="actions">${button('编辑','business-user-edit',u.id)}${button('吊销 Token','business-user-revoke',u.id,'danger')}</div>`
    ]);
    const status = wechat.configured
      ? badge(wechat.enabled ? '微信登录已启用' : '微信登录已停用', wechat.enabled ? 'good' : 'warn') + ` <code>${esc(wechat.appid||'')}</code>`
      : badge('微信登录未配置','warn');
    return `<div class="section-head"><h2>业务用户</h2></div>
      <section class="panel"><label>所属服务<select id="business-user-service">${serviceOptions}</select></label>
      <p class="hint">${status}</p>
      <p class="hint">微信 AppSecret 不在网页配置。服务器执行 <code>sudo sgctl wechat-config --service 服务ID --appid wx...</code> 后隐藏输入 AppSecret。业务用户与网关管理员完全隔离。</p></section>
      ${rows.length ? table(['用户','角色 / 状态','微信身份','最近登录 / 备注','操作'],rows) : empty('暂无业务用户','该服务第一次微信登录成功后会自动创建用户。')}`;
  }

  function bind(reload) {
    const select = document.querySelector('#business-user-service');
    if (select) select.onchange = () => { selectedService = select.value; reload(); };
  }

  async function perform(action, id) {
    if (action === 'business-user-edit') {
      const users = await api('/api/business-users?service_id=' + encodeURIComponent(selectedService));
      const user = users.find(x => x.id === id);
      if (!user) throw new Error('业务用户不存在，请刷新');
      edit('编辑业务用户',
        field('display_name','显示名称',user.display_name) +
        field('role','业务角色',user.role) +
        field('enabled','启用该用户',user.enabled,'checkbox') +
        field('remark','管理员备注',user.remark,'textarea',{rows:4}) +
        '<p class="hint full">停用用户会立即吊销其全部业务 Token；不会影响其他服务中的用户身份。</p>',
        async form => {
          await api('/api/business-users/' + encodeURIComponent(id),'PATCH',{
            display_name: form.get('display_name'),
            role: form.get('role'),
            enabled: form.has('enabled'),
            remark: form.get('remark'),
          });
        });
      return true;
    }
    if (action === 'business-user-revoke') {
      if (confirm('吊销该用户当前所有业务 Token？用户可再次通过微信登录获得新 Token。')) {
        await api('/api/business-users/' + encodeURIComponent(id) + '/revoke-sessions','POST',{});
      }
      return true;
    }
    return false;
  }

  return {render, bind, perform};
}
