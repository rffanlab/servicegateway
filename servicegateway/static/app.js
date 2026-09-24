import {databaseUI} from './database-ui.js';
import {serviceFromForm} from './service-form.js';
import {authUsesClientCa, cloneRouteDraft, normalizeRouteAuthFields} from './route-tools.js';
import {businessUserUI} from './business-users.js';
const $ = s => document.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, x => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]));
let me = null, view = 'overview', overview = null, editorSave = null, toastTimer;
const titles = {databases:'业务数据库',businessUsers:'业务用户',overview:'运行总览',services:'服务管理',routes:'网关路由',releases:'发布与回滚',traffic:'访问采样',keys:'API 密钥',users:'用户与权限',audit:'操作审计',account:'账户与证书'};
function toast(message) { $('#toast').textContent = message; $('#toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => $('#toast').hidden = true, 9000); }
async function api(path, method='GET', body, retry=true) {
  const response = await fetch(path, {method, credentials:'same-origin', headers:{'Content-Type':'application/json', ...(me?.csrf ? {'X-CSRF-Token':me.csrf} : {})}, ...(body === undefined ? {} : {body:JSON.stringify(body)})});
  const data = await response.json().catch(() => ({}));
  if (response.status===428 && retry) { await reauthenticate(); return api(path,method,body,false); }
  if (!response.ok) { if (response.status === 401 && path!=='/api/auth/reauth') showLogin(); throw new Error(typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail ?? data)); }
  return data;
}
function reauthenticate(){
  return new Promise((resolve,reject)=>{
    const dialog=$('#reauth-dialog'), form=$('#reauth-form');form.reset();dialog.showModal();
    const cancel=()=>{form.reset();dialog.close();reject(new Error('已取消敏感操作'));};
    $('#reauth-cancel').onclick=cancel;dialog.oncancel=e=>{e.preventDefault();cancel();};
    form.onsubmit=async e=>{e.preventDefault();const b=e.submitter;b.disabled=true;
      try{await api('/api/auth/reauth','POST',{password:new FormData(form).get('password')},false);form.reset();dialog.close();resolve();}
      catch(err){form.reset();toast(err.message);}finally{b.disabled=false;}
    };
  });
}
function showLogin(){ me = null; $('#login').hidden = false; $('#shell').hidden = true; }
function showShell(){ $('#login').hidden = true; $('#shell').hidden = false; $('#identity').textContent = `${me.username} / ${me.role}`; const permitted = me.role === 'admin' ? Object.keys(titles) : me.role === 'operator' ? ['overview','services','routes','releases','traffic','audit','account'] : ['overview','services','routes','releases','account']; document.querySelectorAll('#nav button').forEach(b=>b.hidden=!permitted.includes(b.dataset.view)); }
const admin = () => me?.role === 'admin';
const operator = () => ['admin','operator'].includes(me?.role);
const button = (text, action, id='', cls='') => `<button class="${cls}" data-action="${action}" data-id="${esc(id)}">${esc(text)}</button>`;
const badge = (text, cls='') => `<span class="badge ${cls}">${esc(text)}</span>`;
const empty = (title, text) => `<div class="empty"><strong>${esc(title)}</strong>${esc(text)}</div>`;
const table = (heads, rows) => `<div class="table-wrap"><table><thead><tr>${heads.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(r=>`<tr>${r.map(c=>`<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
function field(name, title, value='', type='text', opts){ const control = type==='textarea' ? `<textarea name="${name}" rows="${opts?.rows ?? 6}">${esc(value)}</textarea>` : type==='select' ? `<select name="${name}">${opts.map(([v,t])=>`<option value="${v}" ${v===String(value)?'selected':''}>${esc(t)}</option>`).join('')}</select>` : type==='checkbox' ? `<input name="${name}" type="checkbox" ${value?'checked':''}>` : `<input name="${name}" type="${type}" value="${esc(value)}" ${type==='password'?'autocomplete="new-password"':''}>`; return `<label class="${type==='textarea'?'full':''}">${esc(title)}${control}</label>`; }
function edit(title, fields, save, label='保存'){ $('#editor-title').textContent=title; $('#editor-fields').innerHTML=fields; $('#save-editor').textContent=label; $('#save-editor').hidden=!save; $('#cancel-editor').textContent=save?'取消':'关闭'; editorSave=save; $('#editor').showModal(); }
function read(title, text){ edit(title, `<pre class="readbox">${esc(text)}</pre>`, null); }
function serviceCards(assets){ return `<div class="cards">${assets.map(s=>`<article class="card"><div class="card-head"><h3>${esc(s.name)}</h3>${badge(s.state,s.state==='running'?'good':['failed','stopped'].includes(s.state)?'bad':'warn')}</div><p>${esc(s.description || '暂无描述')}</p><div class="toolbar">${badge(s.healthy===true?'HTTP 健康':s.healthy===false?'HTTP 异常':'HTTP 未确认',s.healthy===true?'good':s.healthy===false?'bad':'warn')}${badge('自启 '+s.startup)}${s.latency_ms!==null?badge(s.latency_ms+' ms'):''}</div><div class="meta">${s.services.map(esc).join('<br>')}</div><p>${esc(s.gpu)} · ${s.checked_at ? esc(new Date(s.checked_at).toLocaleTimeString()) : '等待采集'}<br>${esc(s.detail)}</p><div class="card-actions">${s.url?`<a href="${esc(s.url)}" target="_blank" rel="noopener noreferrer">打开原入口 ↗</a>`:''}${operator()?button('启动','start',s.id)+button('停止','stop',s.id)+button('重启','restart',s.id)+button('启用自启','enable',s.id)+button('禁止自启','disable',s.id)+button('检查','check',s.id):''}${admin()?button('编辑','service-edit',s.id)+button('建业务库','database-new',s.id)+button('注销','service-delete',s.id,'danger'):''}</div></article>`).join('')}</div>`; }
const databases = databaseUI({api, edit, field, table, badge, button, empty, esc, getOverview:()=>overview, getUser:()=>me, showLogin});
const businessUsers = businessUserUI({api, edit, field, table, badge, button, empty, esc, getOverview:()=>overview});
async function load(){
  if (!me) return;
  overview = await api('/api/overview');
  $('#page-title').textContent=titles[view];
  $('#notice').textContent=`草稿版本 ${overview.revision} · ${overview.active_release ? '当前发布 '+overview.active_release.id.slice(0,8) : '尚未发布网关配置'} · ${overview.pending_release?'有待核对发布，请到“发布与回滚”处理。':overview.active_release?.digest===overview.draft_digest?'草稿与已发布配置一致。':'草稿尚未发布，线上配置保持不变。'}`;
  document.querySelectorAll('#nav button').forEach(b=>b.classList.toggle('active',b.dataset.view===view));
  let html='';
  if(view==='overview'){
    const stats=[['登记服务',overview.assets.length,'以真实登记数据为准'],['运行中',overview.assets.filter(s=>s.state==='running').length,'systemd 进程状态'],['HTTP 健康',overview.assets.filter(s=>s.healthy===true).length,'独立健康探测'],['草稿路由',overview.routes.length,'发布后生效']];
    html=`<div class="stats">${stats.map(([t,n,d])=>`<div class="stat"><label>${t}</label><strong>${n}</strong><small>${d}</small></div>`).join('')}</div><div class="section-head"><h2>服务状态</h2>${admin()?button('导入 E5 服务','import'):''}</div>`+(overview.assets.length?serviceCards(overview.assets):empty('从现有 E5 服务开始','先导入旧 Manager 登记，或新增一个已获本机批准的服务。'));
  }else if(view==='databases'){
    html=await databases.render();
  }else if(view==='businessUsers'){
    html=await businessUsers.render();
  }else if(view==='services'){
    html=`<div class="section-head"><h2>服务登记与生命周期</h2><div class="actions">${admin()?button('本机业务提交','local-submit')+button('导入 E5','import')+button('新增服务','service-new','','primary'):''}</div></div><div class="filters"><input id="service-filter" placeholder="按名称、ID 或 unit 过滤" aria-label="过滤服务"></div><div id="service-list">${overview.assets.length?serviceCards(overview.assets):empty('暂无服务','登记不会安装程序或修改 systemd unit。')}</div>`;
  }else if(view==='routes'){
    html=`<div class="section-head"><h2>路由草稿</h2><div class="actions">${admin()?button('预览并发布','preview')+button('新增路由','route-new','','primary'):''}</div></div>`+(overview.routes.length?table(['路由 / 服务','入口匹配','上游','鉴权 / 状态','操作'],overview.routes.map(r=>[`${esc(r.name)}<small class="row-note">${esc(r.id)} → ${esc(r.service_id)}</small>`,`<code>${r.certificate?'https':'http'}://${esc(r.host)}${r.listen_port===443?'':':'+r.listen_port}${esc(r.path)}</code>`,r.upstreams.map(u=>`<code>${esc(u.address)}:${u.port} ×${u.weight}</code>`).join('<br>'),badge(r.auth)+(r.enabled?badge('启用','good'):badge('停用'))+(r.rate_per_second?badge(r.rate_per_second+' r/s'):''),admin()?`<div class="actions">${button('编辑','route-edit',r.id)}${button('复制','route-copy',r.id)}${button('删除草稿','route-delete',r.id,'danger')}</div>`:'只读'])):empty('暂无路由','统一通过 HTTPS 443 按业务域名分流；80 仅跳转，不转发业务。'));
  }else if(view==='releases'){
    const rows=await api('/api/releases');
    html=`<div class="section-head"><h2>发布历史</h2><div class="actions">${admin()?button('核对发布状态','reconcile')+button('预览并发布','preview','','primary'):''}</div></div><p class="hint">回滚只切换网关快照，不回滚业务数据，也不覆盖当前编辑草稿。这里显示最近 50 条记录。</p>`+(rows.length?table(['版本 / 时间','状态','说明','摘要','操作'],rows.map(r=>[`<code>${r.id.slice(0,8)}</code><small class="row-note">${esc(new Date(r.created_at).toLocaleString())}</small>`,badge(r.status,r.status==='active'?'good':r.status==='failed'?'bad':'warn'),`${esc(r.note)}<small class="row-note">${esc(r.error)}</small>`,`<code>${r.digest.slice(0,14)}</code>`,admin()&&['active','superseded'].includes(r.status)?button('回滚到此版','rollback',r.id):'—'])):empty('还没有发布记录','保存路由后，通过预览检查生成配置，再执行发布。')); window.sgReleases=rows;
  }else if(view==='keys'){
    const rows=await api('/api/keys');
    html=`<div class="section-head"><h2>自动化与网关访问凭据</h2>${button('创建密钥','key-new','','primary')}</div><p class="hint">使用 X-Gateway-Key 请求头。路由作用域只能访问指定路由；登记作用域只能登记指定服务；业务用户查询作用域只允许本机 introspection 查询指定服务。三种作用域互不自动继承。密钥明文只返回一次。</p>`+(rows.length?table(['名称','路由作用域','登记作用域','业务用户查询','到期 / 状态','操作'],rows.map(k=>[esc(k.name),esc(k.route_ids.join(', ')),esc(k.service_ids.join(', ')),esc((k.user_service_ids??[]).join(', ')),`${esc(new Date(k.expires_at).toLocaleDateString())} ${badge(k.revoked?'已撤销':'有效',k.revoked?'':'good')}`,k.revoked?'—':button('撤销','key-revoke',k.id,'danger')])):empty('暂无 API Key','不创建全局万能密钥，按路由或注册任务分配权限。'));
  }else if(view==='users'){
    const rows=await api('/api/users');
    html=`<div class="section-head"><h2>账号与角色</h2>${button('新增用户','user-new','','primary')}</div><p class="hint">viewer：查看；operator：查看、启停与审计；admin：配置、发布、密钥和用户管理。</p>`+table(['用户名','角色','状态','操作'],rows.map(u=>[esc(u.username),badge(u.role),badge(u.enabled?'启用':'停用',u.enabled?'good':''),u.enabled&&u.username!==me.username?button('停用','user-disable',u.id,'danger'):'—']));
  }else if(view==='audit'){
    const rows=await api('/api/audit');
    html=`<div class="section-head"><h2>最近 100 条审计记录</h2></div>`+table(['时间','操作者','动作','目标','结果','详情'],rows.map(a=>[esc(new Date(a.created_at).toLocaleString()),esc(a.actor),esc(a.action),`<code>${esc(a.target)}</code>`,badge(a.outcome,a.outcome==='failed'?'bad':''),esc(a.detail)]));
  }else if(view==='account'){
    const data=await api('/api/account/security');
    html=`<div class="section-head"><h2>我的账户</h2></div><section class="panel"><h3>${esc(data.username)} · ${esc(data.role)}</h3><p class="hint">修改密码需校验当前密码。成功后所有登录会话失效，使用新密码重新登录；API Key 和客户端证书不会被改变。</p>${button('修改密码','password-change','','primary')}</section>`;
    if(admin()) {
      const p=data.pki??{};
      html+=`<div class="section-head"><h2>管理客户端证书与 CRL</h2></div><section class="panel"><p>${badge(p.timer_active&&p.credential_configured?'自动刷新已启用':'自动刷新尚未就绪',p.timer_active&&p.credential_configured?'good':'warn')} ${badge('CRL 剩余 '+(p.crl_days_remaining??'未知')+' 天')}</p><p class="hint">每天检查，剩余不足 30 天刷新为 90 天。不自动吊销或更换正在使用的浏览器证书。最近任务：${esc(p.last_run?.outcome??'尚无记录')} ${esc(p.last_run?.at??'')}</p><p class="hint">旧安装首次启用需在服务器执行 <code>sudo bash deploy/full-deploy.sh pki-auto-enable</code> 并隐藏输入原 PKI 口令一次。签名凭据不存入 Web 配置或 MySQL。</p><p class="hint">下载的是口令加密的管理客户端 P12，仍需原 P12 保护口令才能导入，不是网站登录密码。此操作只对管理员开放并再次验证当前密码。新设备首次访问仍需先导入客户端证书；没有公开免登录下载地址。</p>${button('下载客户端证书','client-download','','primary')}</section>`;
    }
  }else if(view==='traffic'){
    const data=await api('/api/traffic');
    html=`<div class="section-head"><h2>最近访问采样</h2></div><p class="hint">仅展示日志尾部最近 200 个完成请求，不是全量流量统计。长连接在结束后记录。不采集请求体、Cookie、密钥或查询参数。</p>`+(data.sample.length?table(['路由','状态码','耗时','响应字节','请求 ID'],data.sample.reverse().map(r=>[esc(r.route),badge(r.status,r.status>=500?'bad':r.status<400?'good':'warn'),esc(r.seconds)+' s',esc(r.bytes),`<code>${esc(r.request_id)}</code>`])):empty('暂无访问采样','发布路由并完成一次访问后，这里会出现真实记录。'));
  }
  $('#content').innerHTML=html;
  if(view==='businessUsers')businessUsers.bind(()=>load().catch(e=>toast(e.message)));
  $('#service-filter')?.addEventListener('input',e=>{const q=e.target.value.toLowerCase(); $('#service-list').innerHTML=serviceCards(overview.assets.filter(s=>[s.name,s.id,...s.services].join(' ').toLowerCase().includes(q)));});
}
function unitRow(value='') { return `<div class="unit-row"><input name="unit" value="${esc(value)}" placeholder="例如 my-app.service" required maxlength="108" aria-label="systemd 服务名称"><button type="button" data-remove-unit>移除</button></div>`; }
async function serviceEditor(id){
  const inv=await api('/api/inventory');
  const old=overview.assets.find(x=>x.id===id);
  const s=old??{id:'',name:'',description:'',services:[''],url:'',port:443,health_url:'http://127.0.0.1:18188/healthz',gpu:'CPU / API',accent:'cyan',warning:'停止或重启会中断当前任务。'};
  const grants=inv.grants??{};
  const choices=Object.keys(grants).map(key=>[key,key]);
  const fields=`<p class="hint full">登记不会安装程序、启停业务或发布公网路由。unit 与健康地址必须经过本机 root 批准；也可使用“本机业务提交”一次批准并登记。</p>`
    +(!old?field('approved','从已批准服务填入（可选）','','select',[['','手动填写'],...choices]):'')
    +field('id','服务 ID（小写字母、数字、连字符）',s.id)+field('name','显示名称',s.name)
    +field('description','服务说明',s.description)+field('url','业务访问 URL（可留空）',s.url)
    +field('port','展示入口端口（不是自动开放端口）',s.port,'number')+field('health_url','已批准的本机健康检查 URL',s.health_url)
    +`<div class="full"><label>systemd 服务（按依赖顺序填写，先启动的放前面）</label><div id="unit-fields">${s.services.map(unitRow).join('')}</div><button type="button" id="add-unit">增加一个服务</button></div>`
    +field('gpu','运行资源说明',s.gpu)+field('accent','标识颜色',s.accent,'select',[['cyan','青色'],['violet','紫色'],['amber','橙色'],['rose','红色']])
    +field('warning','停止/重启风险提示',s.warning);
  edit(old?'编辑服务':'新增服务',fields,async form=>{
    const data=serviceFromForm(form,old?.id);
    if(!grants[data.id])throw new Error('该服务尚未获得本机批准。请先用 sgctl register --approve 提交，或用 sgctl approve 批准 manifest。');
    await api('/api/registry/services','POST',data);
  });
  const form=$('#editor-form');
  if(old)form.elements.namedItem('id').readOnly=true;
  $('#add-unit').onclick=()=>{if(form.querySelectorAll('[name="unit"]').length>=16){toast('最多 16 个 unit');return;}$('#unit-fields').insertAdjacentHTML('beforeend',unitRow());};
  $('#unit-fields').onclick=e=>{if(e.target.closest('[data-remove-unit]'))e.target.closest('.unit-row').remove();};
  const approved=form.elements.namedItem('approved');
  if(approved)approved.onchange=()=>{const grant=grants[approved.value];if(!grant)return;form.elements.namedItem('id').value=approved.value;form.elements.namedItem('health_url').value=grant.health_url;$('#unit-fields').innerHTML=grant.units.map(unitRow).join('');};
}
async function downloadClientCertificate(password){
  const response=await fetch('/api/account/client-certificate',{method:'POST',cache:'no-store',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':me.csrf},body:JSON.stringify({current_password:password})});
  if(!response.ok){const data=await response.json().catch(()=>({}));if(response.status===401)showLogin();throw new Error(typeof data.detail==='string'?data.detail:'证书下载失败');}
  const blob=await response.blob();
  const url=URL.createObjectURL(blob), link=document.createElement('a');link.href=url;link.download='admin-browser.p12';document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),2000);
}
async function routeEditor(id, copy=false){
  const policy=await api('/api/inventory');
  const remote=policy.remote_mode!==false;
  if(!overview.assets.length) throw new Error('请先注册服务');
  const source=id?overview.routes.find(r=>r.id===id):null;
  if(id&&!source)throw new Error('路由不存在，请刷新页面');
  const old=copy?null:source;
  const cloned=copy?cloneRouteDraft(overview.routes,id):null;
  const r=cloned??old??{id:'',name:'',service_id:overview.assets[0].id,listen_port:443,host:'',path:'/',upstreams:[{address:'127.0.0.1',port:18188,weight:1}],auth:'api_key',upstream_auth:{mode:'none'},enabled:true,websocket:true,buffering:false,strip_prefix:false,timeout_seconds:300,max_body_mb:512,rate_per_second:10,burst:20,allow_cidrs:[],certificate:null,balance:'round_robin'};
  const grants=policy.grants??{};
  const sourceScope=(grants[r.service_id]?.source_cidrs??policy.allowed_cidrs??[]).join(', ')||'未配置';
  const authValue=r.auth==='mtls_api_key'?'mtls_or_api_key':r.auth;
  const fields=field('id','路由 ID',r.id)+field('name','显示名称',r.name)+field('service_id','所属服务',r.service_id,'select',overview.assets.map(s=>[s.id,s.name]))+(remote?'<label>统一 HTTPS 入口<input name="listen_port" type="number" value="443" readonly></label>':field('listen_port','LAN 监听端口',r.listen_port,'number'))+field('host',remote?'业务域名（与管理域名分离）':'精确域名；_ 为 LAN 默认入口',r.host)+field('path','路径前缀；必须以 / 结尾',r.path)+field('auth','边缘鉴权',authValue,'select',[...(remote?[]:[['session','ServiceGateway 登录'],['e5','旧 E5 统一登录'],['public','无需登录（仅 LAN）']]),['api_key','仅 API Key'],['service_auth','业务自行鉴权 / 公开透传'],['mtls','仅客户端证书'],['mtls_or_api_key','客户端证书 或 API Key（任一通过即可）'],['wechat_user','微信登录用户']])+field('client_ca','客户端 CA 目录 ID（证书鉴权必填）',r.client_ca??'')+field('upstream_auth','上游身份确认',r.upstream_auth?.mode??'none','select',[['none','不注入路由 Secret'],['route_secret','注入每路由独立 Secret']])+`<p class="hint full">所属服务必须从已登记服务中选择，不能手填。当前所选服务的来源 CIDR 上限：${esc(sourceScope)}。路由留空时继承服务上限；“业务自行鉴权 / 公开透传”表示整个 path 前缀不做网关身份校验，由上游服务决定匿名或自身 Token 权限；如果存在更具体的下级路由，则下级路由权限优先，例如 /api/ 透传而 /api/private/ 微信鉴权；上游 Secret 不显示在页面中。</p>`+field('session_users','允许会话用户（逗号分隔；空则仅管理员）',(r.session_users??[]).join(','))+field('business_roles','微信业务角色（逗号分隔；空则所有已启用微信用户）',(r.business_roles??[]).join(','))+field('max_connections','每 IP 最大同时连接数',r.max_connections??16,'number')+field('balance','负载均衡',r.balance,'select',[['round_robin','加权轮询'],['least_conn','最少连接'],['ip_hash','来源 IP 绑定']])+field('upstreams','上游列表 JSON',JSON.stringify(r.upstreams,null,2),'textarea')+field('timeout_seconds','读取/发送空闲超时（秒）',r.timeout_seconds,'number')+field('max_body_mb','上传上限（MB）',r.max_body_mb,'number')+field('rate_per_second','每来源 IP 限流（0 不限制）',r.rate_per_second,'number')+field('burst','突发额度',r.burst,'number')+field('certificate',remote?'证书目录 ID（必填）':'证书目录 ID（可空）',r.certificate??'')+field('allow_cidrs','来源 IP 白名单（逗号分隔；空则继承所属服务上限）',r.allow_cidrs.join(','))+field('enabled','启用此路由',r.enabled,'checkbox')+field('websocket','WebSocket 转发',r.websocket,'checkbox')+field('buffering','启用响应缓冲（SSE 应关闭）',r.buffering,'checkbox')+field('strip_prefix','移除路径前缀（业务程序需支持）',r.strip_prefix,'checkbox');
  let rememberedClientCa=r.client_ca??'';
  edit(copy?'复制路由草稿':(id?'编辑路由草稿':'新增路由草稿'),fields,async f=>{
    let data={...r};
    ['id','name','service_id','host','path','auth','balance'].forEach(k=>data[k]=f.get(k));
    ['listen_port','timeout_seconds','max_body_mb','rate_per_second','burst','max_connections'].forEach(k=>data[k]=Number(f.get(k)));
    ['enabled','websocket','buffering','strip_prefix'].forEach(k=>data[k]=f.has(k));
    data.upstreams=JSON.parse(f.get('upstreams'));
    data.certificate=f.get('certificate')||null;
    data.client_ca=authUsesClientCa(data.auth)?(f.get('client_ca')||null):null;
    data.upstream_auth={mode:f.get('upstream_auth')};
    data.session_users=(f.get('session_users')??'').split(',').map(x=>x.trim()).filter(Boolean);
    data.business_roles=(f.get('business_roles')??'').split(',').map(x=>x.trim()).filter(Boolean);
    data.allow_cidrs=f.get('allow_cidrs').split(',').map(x=>x.trim()).filter(Boolean);
    data=normalizeRouteAuthFields(data);
    if(old&&data.id!==old.id)throw new Error('编辑不能更改路由 ID');
    if(!overview.assets.some(s=>s.id===data.service_id))throw new Error('请选择已登记服务');
    await api(`/api/routes/${encodeURIComponent(data.id)}?revision=${overview.revision}`,'PUT',data);
  });
  const routeForm=$('#editor-form'), authSelect=routeForm.elements.namedItem('auth'), caInput=routeForm.elements.namedItem('client_ca');
  const syncClientCa=()=>{
    const usesCa=authUsesClientCa(authSelect.value);
    caInput.disabled=!usesCa;
    caInput.closest('label')?.classList.toggle('disabled',!usesCa);
    if(!usesCa){if(caInput.value)rememberedClientCa=caInput.value;caInput.value='';}
    else if(!caInput.value&&rememberedClientCa)caInput.value=rememberedClientCa;
  };
  authSelect.addEventListener('change',syncClientCa);
  syncClientCa();
}
async function perform(action,id){
  if(await databases.perform(action,id))return;
  if(await businessUsers.perform(action,id))return;
  if(action==='password-change'){
    edit('修改我的密码',field('current_password','当前密码','','password').replace('new-password','current-password')+field('new_password','新密码（12–256 位）','','password')+field('confirm_password','确认新密码','','password'),async form=>{const result=await api('/api/account/password','POST',Object.fromEntries(form));$('#editor-form').reset();$('#editor').close();showLogin();toast(result.notice);return false;},'确认修改并退出登录');return;
  }
  if(action==='client-download'){
    edit('验证密码后下载加密 P12',`<p class="hint full">只下载浏览器客户端证书，不含 CA 签名私钥或探测私钥。导入时仍需原 P12 保护口令；不要将文件上传公开站点。</p>`+field('current_password','当前网站登录密码','','password').replace('new-password','current-password'),async form=>{await downloadClientCertificate(form.get('current_password'));$('#editor-form').reset();});return;
  }
  if(action==='local-submit'){
    read('本机业务提交',`方式一：本机管理员/部署 Agent
先准备真实 manifest（仓库 examples/service-registration.json），然后执行：
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl register /实际路径/service-registration.json --approve

只批准并登记已安装的非 root 业务，不执行 Shell、不发布公网路由。重复提交相同内容不会重复登记。

方式二：普通业务进程自动登记
管理员先批准该 manifest，再创建只包含该服务 ID 的“登记作用域”API Key，并保存为业务用户自己的 0600 文件。
python3 deploy/register-local.py --manifest /实际路径/service-registration.json --key-file /安全路径/registration.key

仅访问 127.0.0.1:19092/internal/registry/services；服务名必须在 Key 作用域和本机授权中。没有匿名本机免登录接口。`);return;
  }
  if(['start','stop','restart','enable','disable'].includes(action)){const s=overview.assets.find(x=>x.id===id);if(['stop','restart','disable'].includes(action)&&!confirm(`${s.name}\n${s.warning}\n确认执行 ${action}？`))return; await api(`/api/services/${id}/actions`,'POST',{action,confirm:s.name});await load();return;}
  if(action==='check'){await api(`/api/services/${id}/health`,'POST');await load();return;}
  if(action==='service-new'||action==='service-edit'){await serviceEditor(id);return;}
  if(action==='route-new'||action==='route-edit'){await routeEditor(id,false);return;}
  if(action==='route-copy'){await routeEditor(id,true);return;}
  if(action==='service-delete'){if(confirm('仅注销管理登记，不停止程序、不删除数据。确认？')){await api(`/api/registry/services/${id}`,'DELETE');await load();}return;}
  if(action==='route-delete'){if(confirm('删除路由草稿？发布后才会停止此入口转发。')){await api(`/api/routes/${id}?revision=${overview.revision}`,'DELETE');await load();}return;}
  if(action==='preview'){const p=await api('/api/gateway/preview','POST');const missing=p.missing_upstream_secrets??[];const warning=missing.length?`<p class="hint full"><strong>缺少上游路由 Secret：</strong>${esc(missing.join(', '))}<br>先在服务器执行 sgctl route-secret --route 路由ID --output /root/安全文件，再让上游应用接受该 Secret；未配置时发布会失败。</p>`:'';edit('发布预览',`<p class="hint full">草稿版本 ${p.revision} · ${esc(p.digest)}<br>将执行二次校验、nginx -t、reload 与配置指纹检查。失败时恢复旧配置。</p>${warning}<pre class="readbox">${esc(p.config)}</pre>`+field('note','发布说明','','text'),async f=>{await api('/api/gateway/publish','POST',{revision:p.revision,digest:p.digest,note:f.get('note')});},'确认发布');return;}
  if(action==='reconcile'){await api('/api/gateway/reconcile','POST');toast('状态核对完成');await load();return;}
  if(action==='rollback'){const r=window.sgReleases.find(x=>x.id===id);if(confirm(`将线上网关回滚到 ${r.id.slice(0,8)}？当前草稿不会被覆盖。`)){await api(`/api/gateway/rollback/${id}`,'POST',{revision:overview.revision,digest:r.digest,note:'从控制台回滚到 '+id});await load();}return;}
  if(action==='import'){const inv=await api('/api/inventory');edit('导入 E5 服务',`<p class="hint full">远程模式不自动信任旧 E5 登记。请粘贴导出的清单并在远程机重新批准实际 unit；不会执行旧源码、覆盖已有登记或自动创建路由。</p>`+field('items','服务清单数组 JSON',JSON.stringify(inv.manifests,null,2),'textarea',{rows:18}),async f=>{const services=JSON.parse(f.get('items'));const p=await api('/api/import/e5','POST',{services,apply:false});if(p.conflicts.length)throw new Error('存在冲突：'+p.conflicts.join(', '));if(!confirm(`新增 ${p.additions.length} 项，保持 ${p.unchanged.length} 项不变，确认导入？`))throw new Error('已取消导入');await api('/api/import/e5','POST',{services,apply:true,revision:p.revision});},'预览导入');return;}
  if(action==='key-new'){edit('创建限定作用域密钥',field('name','名称')+field('expires_days','有效天数',90,'number')+field('route_ids','可访问的路由 ID（逗号分隔）')+field('service_ids','可登记的服务 ID（逗号分隔）')+field('user_service_ids','可查询业务用户的服务 ID（逗号分隔）'),async f=>{const split=k=>f.get(k).split(',').map(x=>x.trim()).filter(Boolean);const result=await api('/api/keys','POST',{name:f.get('name'),expires_days:Number(f.get('expires_days')),route_ids:split('route_ids'),service_ids:split('service_ids'),user_service_ids:split('user_service_ids')});$('#editor').close();read('请立即保存；密钥仅显示一次',result.token+'\n\n请求头：X-Gateway-Key\n关闭后无法再次查看。');return false;});return;}
  if(action==='key-revoke'){if(confirm('立即撤销此密钥？')){await api(`/api/keys/${id}`,'DELETE');await load();}return;}
  if(action==='user-new'){edit('新增用户',field('username','用户名')+field('password','密码（至少 12 位）','','password')+field('role','角色','viewer','select',[['viewer','只读'],['operator','运维'],['admin','管理员']]),async f=>{await api('/api/users','POST',Object.fromEntries(f.entries()));});return;}
  if(action==='user-disable'){if(confirm('停用此用户并立即吊销其会话？')){await api(`/api/users/${id}`,'DELETE');await load();}}
}
$('#login-form').addEventListener('submit',async e=>{e.preventDefault();const b=e.submitter;b.disabled=true;try{me=await api('/api/auth/login','POST',Object.fromEntries(new FormData(e.target)));e.target.reset();view='overview';showShell();await load();}catch(err){toast(err.message);}finally{b.disabled=false;}});
$('#logout').addEventListener('click',async()=>{try{await api('/api/auth/logout','POST');showLogin();}catch(e){toast(e.message);}});
$('#nav').addEventListener('click',e=>{const b=e.target.closest('[data-view]');if(b){view=b.dataset.view;load().catch(e=>toast(e.message));}});
$('#refresh').addEventListener('click',()=>load().catch(e=>toast(e.message)));
$('#content').addEventListener('click',async e=>{const b=e.target.closest('[data-action]');if(!b)return;b.disabled=true;try{await perform(b.dataset.action,b.dataset.id);}catch(e){toast(e.message);}finally{b.disabled=false;}});
$('#editor-form').addEventListener('submit',async e=>{e.preventDefault();if(!editorSave)return;const b=$('#save-editor');b.disabled=true;try{const keep=await editorSave(new FormData(e.target));if(keep!==false){$('#editor').close();toast('操作完成');}await load();}catch(e){toast(e.message);}finally{b.disabled=false;}});
$('#close-editor').onclick=$('#cancel-editor').onclick=()=>$('#editor').close();
api('/api/auth/me').then(data=>{me=data;showShell();return load();}).catch(()=>showLogin());
setInterval(()=>{if(me&&!$('#editor').open&&view==='overview'&&document.visibilityState==='visible')load().catch(()=>{});},30000);

$("#editor").addEventListener("close",()=>{if(!$("#editor").open){$("#editor-fields").replaceChildren();editorSave=null;}});
