const $ = s => document.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, x => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]));
let me = null, view = 'overview', overview = null, editorSave = null, toastTimer;
const titles = {overview:'运行总览',services:'服务管理',routes:'网关路由',releases:'发布与回滚',traffic:'访问采样',keys:'API 密钥',users:'用户与权限',audit:'操作审计'};
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
function showShell(){ $('#login').hidden = true; $('#shell').hidden = false; $('#identity').textContent = `${me.username} / ${me.role}`; const permitted = me.role === 'admin' ? Object.keys(titles) : me.role === 'operator' ? ['overview','services','routes','releases','traffic','audit'] : ['overview','services','routes','releases']; document.querySelectorAll('#nav button').forEach(b=>b.hidden=!permitted.includes(b.dataset.view)); }
const admin = () => me?.role === 'admin';
const operator = () => ['admin','operator'].includes(me?.role);
const button = (text, action, id='', cls='') => `<button class="${cls}" data-action="${action}" data-id="${esc(id)}">${esc(text)}</button>`;
const badge = (text, cls='') => `<span class="badge ${cls}">${esc(text)}</span>`;
const empty = (title, text) => `<div class="empty"><strong>${esc(title)}</strong>${esc(text)}</div>`;
const table = (heads, rows) => `<div class="table-wrap"><table><thead><tr>${heads.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(r=>`<tr>${r.map(c=>`<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
function field(name, title, value='', type='text', opts){ const control = type==='textarea' ? `<textarea name="${name}" rows="${opts?.rows ?? 6}">${esc(value)}</textarea>` : type==='select' ? `<select name="${name}">${opts.map(([v,t])=>`<option value="${v}" ${v===String(value)?'selected':''}>${esc(t)}</option>`).join('')}</select>` : type==='checkbox' ? `<input name="${name}" type="checkbox" ${value?'checked':''}>` : `<input name="${name}" type="${type}" value="${esc(value)}" ${type==='password'?'autocomplete="new-password"':''}>`; return `<label class="${type==='textarea'?'full':''}">${esc(title)}${control}</label>`; }
function edit(title, fields, save, label='保存'){ $('#editor-title').textContent=title; $('#editor-fields').innerHTML=fields; $('#save-editor').textContent=label; $('#save-editor').hidden=!save; $('#cancel-editor').textContent=save?'取消':'关闭'; editorSave=save; $('#editor').showModal(); }
function read(title, text){ edit(title, `<pre class="readbox">${esc(text)}</pre>`, null); }
function serviceCards(assets){ return `<div class="cards">${assets.map(s=>`<article class="card"><div class="card-head"><h3>${esc(s.name)}</h3>${badge(s.state,s.state==='running'?'good':['failed','stopped'].includes(s.state)?'bad':'warn')}</div><p>${esc(s.description || '暂无描述')}</p><div class="toolbar">${badge(s.healthy===true?'HTTP 健康':s.healthy===false?'HTTP 异常':'HTTP 未确认',s.healthy===true?'good':s.healthy===false?'bad':'warn')}${badge('自启 '+s.startup)}${s.latency_ms!==null?badge(s.latency_ms+' ms'):''}</div><div class="meta">${s.services.map(esc).join('<br>')}</div><p>${esc(s.gpu)} · ${s.checked_at ? esc(new Date(s.checked_at).toLocaleTimeString()) : '等待采集'}<br>${esc(s.detail)}</p><div class="card-actions">${s.url?`<a href="${esc(s.url)}" target="_blank" rel="noopener noreferrer">打开原入口 ↗</a>`:''}${operator()?button('启动','start',s.id)+button('停止','stop',s.id)+button('重启','restart',s.id)+button('启用自启','enable',s.id)+button('禁止自启','disable',s.id)+button('检查','check',s.id):''}${admin()?button('编辑','service-edit',s.id)+button('注销','service-delete',s.id,'danger'):''}</div></article>`).join('')}</div>`; }
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
  }else if(view==='services'){
    html=`<div class="section-head"><h2>服务登记与生命周期</h2><div class="actions">${admin()?button('导入 E5','import')+button('新增服务','service-new','','primary'):''}</div></div><div class="filters"><input id="service-filter" placeholder="按名称、ID 或 unit 过滤" aria-label="过滤服务"></div><div id="service-list">${overview.assets.length?serviceCards(overview.assets):empty('暂无服务','登记不会安装程序或修改 systemd unit。')}</div>`;
  }else if(view==='routes'){
    html=`<div class="section-head"><h2>路由草稿</h2><div class="actions">${admin()?button('预览并发布','preview')+button('新增路由','route-new','','primary'):''}</div></div>`+(overview.routes.length?table(['路由 / 服务','入口匹配','上游','鉴权 / 状态','操作'],overview.routes.map(r=>[`${esc(r.name)}<small class="row-note">${esc(r.id)} → ${esc(r.service_id)}</small>`,`<code>${r.certificate?'https':'http'}://${esc(r.host)}:${r.listen_port}${esc(r.path)}</code>`,r.upstreams.map(u=>`<code>${esc(u.address)}:${u.port} ×${u.weight}</code>`).join('<br>'),badge(r.auth)+(r.enabled?badge('启用','good'):badge('停用'))+(r.rate_per_second?badge(r.rate_per_second+' r/s'):''),admin()?`<div class="actions">${button('编辑','route-edit',r.id)}${button('删除草稿','route-delete',r.id,'danger')}</div>`:'只读'])):empty('暂无路由','推荐先按端口代理整个服务，再按需增加域名和路径路由。'));
  }else if(view==='releases'){
    const rows=await api('/api/releases');
    html=`<div class="section-head"><h2>发布历史</h2><div class="actions">${admin()?button('核对发布状态','reconcile')+button('预览并发布','preview','','primary'):''}</div></div><p class="hint">回滚只切换网关快照，不回滚业务数据，也不覆盖当前编辑草稿。这里显示最近 50 条记录。</p>`+(rows.length?table(['版本 / 时间','状态','说明','摘要','操作'],rows.map(r=>[`<code>${r.id.slice(0,8)}</code><small class="row-note">${esc(new Date(r.created_at).toLocaleString())}</small>`,badge(r.status,r.status==='active'?'good':r.status==='failed'?'bad':'warn'),`${esc(r.note)}<small class="row-note">${esc(r.error)}</small>`,`<code>${r.digest.slice(0,14)}</code>`,admin()&&['active','superseded'].includes(r.status)?button('回滚到此版','rollback',r.id):'—'])):empty('还没有发布记录','保存路由后，通过预览检查生成配置，再执行发布。')); window.sgReleases=rows;
  }else if(view==='keys'){
    const rows=await api('/api/keys');
    html=`<div class="section-head"><h2>自动化与网关访问凭据</h2>${button('创建密钥','key-new','','primary')}</div><p class="hint">使用 X-Gateway-Key 请求头。路由作用域只能访问指定路由，注册作用域只能登记指定服务，不能控制启停。密钥明文只返回一次。</p>`+(rows.length?table(['名称','路由作用域','登记作用域','到期 / 状态','操作'],rows.map(k=>[esc(k.name),esc(k.route_ids.join(', ')),esc(k.service_ids.join(', ')),`${esc(new Date(k.expires_at).toLocaleDateString())} ${badge(k.revoked?'已撤销':'有效',k.revoked?'':'good')}`,k.revoked?'—':button('撤销','key-revoke',k.id,'danger')])):empty('暂无 API Key','不创建全局万能密钥，按路由或注册任务分配权限。'));
  }else if(view==='users'){
    const rows=await api('/api/users');
    html=`<div class="section-head"><h2>账号与角色</h2>${button('新增用户','user-new','','primary')}</div><p class="hint">viewer：查看；operator：查看、启停与审计；admin：配置、发布、密钥和用户管理。</p>`+table(['用户名','角色','状态','操作'],rows.map(u=>[esc(u.username),badge(u.role),badge(u.enabled?'启用':'停用',u.enabled?'good':''),u.enabled&&u.username!==me.username?button('停用','user-disable',u.id,'danger'):'—']));
  }else if(view==='audit'){
    const rows=await api('/api/audit');
    html=`<div class="section-head"><h2>最近 100 条审计记录</h2></div>`+table(['时间','操作者','动作','目标','结果','详情'],rows.map(a=>[esc(new Date(a.created_at).toLocaleString()),esc(a.actor),esc(a.action),`<code>${esc(a.target)}</code>`,badge(a.outcome,a.outcome==='failed'?'bad':''),esc(a.detail)]));
  }else if(view==='traffic'){
    const data=await api('/api/traffic');
    html=`<div class="section-head"><h2>最近访问采样</h2></div><p class="hint">仅展示日志尾部最近 200 个完成请求，不是全量流量统计。长连接在结束后记录。不采集请求体、Cookie、密钥或查询参数。</p>`+(data.sample.length?table(['路由','状态码','耗时','响应字节','请求 ID'],data.sample.reverse().map(r=>[esc(r.route),badge(r.status,r.status>=500?'bad':r.status<400?'good':'warn'),esc(r.seconds)+' s',esc(r.bytes),`<code>${esc(r.request_id)}</code>`])):empty('暂无访问采样','发布路由并完成一次访问后，这里会出现真实记录。'));
  }
  $('#content').innerHTML=html;
  $('#service-filter')?.addEventListener('input',e=>{const q=e.target.value.toLowerCase(); $('#service-list').innerHTML=serviceCards(overview.assets.filter(s=>[s.name,s.id,...s.services].join(' ').toLowerCase().includes(q)));});
}
function serviceEditor(id){ const old=overview.assets.find(s=>s.id===id); const s=old??{id:'',name:'',description:'',services:[],url:'',port:19100,health_url:'http://127.0.0.1:18188/healthz',gpu:'CPU / API',accent:'cyan',warning:'停止或重启会中断当前任务。'}; const spec=Object.fromEntries(['id','name','description','services','url','port','health_url','gpu','accent','warning'].map(k=>[k,s[k]])); edit(id?'编辑服务登记':'新增服务登记',`<p class="hint full">远程机上的服务必须先由本机 root 批准。旧 E5 清单仅用于导入资料，不自动继承主机授权。</p>`+field('spec','服务登记 JSON',JSON.stringify(spec,null,2),'textarea',{rows:18}),async f=>{await api('/api/registry/services','POST',JSON.parse(f.get('spec')));}); }
function routeEditor(id){
  if(!overview.assets.length) throw new Error('请先注册服务');
  const old=overview.routes.find(r=>r.id===id); const r=old??{id:'',name:'',service_id:overview.assets[0].id,listen_port:19100,host:'',path:'/',upstreams:[{address:'127.0.0.1',port:18188,weight:1}],auth:'api_key',enabled:true,websocket:true,buffering:false,strip_prefix:false,timeout_seconds:300,max_body_mb:512,rate_per_second:10,burst:20,allow_cidrs:[],certificate:null,balance:'round_robin'};
  const fields=field('id','路由 ID',r.id)+field('name','显示名称',r.name)+field('service_id','所属服务',r.service_id,'select',overview.assets.map(s=>[s.id,s.name]))+field('listen_port','监听端口',r.listen_port,'number')+field('host','精确域名；_ 表示此端口默认入口',r.host)+field('path','路径前缀；必须以 / 结尾',r.path)+field('auth','鉴权',r.auth,'select',[['session','ServiceGateway 登录'],['api_key','限定 API Key'],['e5','旧 E5 统一登录'],['public','无需登录（仅 LAN）'],['mtls','客户端证书（远程网页）']])+field('client_ca','客户端 CA 目录 ID（mTLS 必填）',r.client_ca??'')+field('session_users','允许会话用户（逗号分隔；空则仅管理员）',(r.session_users??[]).join(','))+field('max_connections','每 IP 最大同时连接数',r.max_connections??16,'number')+field('balance','负载均衡',r.balance,'select',[['round_robin','加权轮询'],['least_conn','最少连接'],['ip_hash','来源 IP 绑定']])+field('upstreams','上游列表 JSON',JSON.stringify(r.upstreams,null,2),'textarea')+field('timeout_seconds','读取/发送空闲超时（秒）',r.timeout_seconds,'number')+field('max_body_mb','上传上限（MB）',r.max_body_mb,'number')+field('rate_per_second','每来源 IP 限流（0 不限制）',r.rate_per_second,'number')+field('burst','突发额度',r.burst,'number')+field('certificate','证书目录 ID（可空，不接受任意路径）',r.certificate??'')+field('allow_cidrs','IP 白名单（逗号分隔；空则使用 root 策略）',r.allow_cidrs.join(','))+field('enabled','启用此路由',r.enabled,'checkbox')+field('websocket','WebSocket 转发',r.websocket,'checkbox')+field('buffering','启用响应缓冲（SSE 应关闭）',r.buffering,'checkbox')+field('strip_prefix','移除路径前缀（业务程序需支持）',r.strip_prefix,'checkbox');
  edit(id?'编辑路由草稿':'新增路由草稿',fields,async f=>{const data={...r}; ['id','name','service_id','host','path','auth','balance'].forEach(k=>data[k]=f.get(k)); ['listen_port','timeout_seconds','max_body_mb','rate_per_second','burst','max_connections'].forEach(k=>data[k]=Number(f.get(k))); ['enabled','websocket','buffering','strip_prefix'].forEach(k=>data[k]=f.has(k)); data.upstreams=JSON.parse(f.get('upstreams'));data.certificate=f.get('certificate')||null;data.client_ca=f.get('client_ca')||null;data.session_users=f.get('session_users').split(',').map(x=>x.trim()).filter(Boolean);data.allow_cidrs=f.get('allow_cidrs').split(',').map(x=>x.trim()).filter(Boolean);if(old&&data.id!==old.id)throw new Error('编辑不能更改路由 ID');await api(`/api/routes/${encodeURIComponent(data.id)}?revision=${overview.revision}`,'PUT',data);});
}
async function perform(action,id){
  if(['start','stop','restart','enable','disable'].includes(action)){const s=overview.assets.find(x=>x.id===id);if(['stop','restart','disable'].includes(action)&&!confirm(`${s.name}\n${s.warning}\n确认执行 ${action}？`))return; await api(`/api/services/${id}/actions`,'POST',{action,confirm:s.name});await load();return;}
  if(action==='check'){await api(`/api/services/${id}/health`,'POST');await load();return;}
  if(action==='service-new'||action==='service-edit'){serviceEditor(id);return;}
  if(action==='route-new'||action==='route-edit'){routeEditor(id);return;}
  if(action==='service-delete'){if(confirm('仅注销管理登记，不停止程序、不删除数据。确认？')){await api(`/api/registry/services/${id}`,'DELETE');await load();}return;}
  if(action==='route-delete'){if(confirm('删除路由草稿？发布后才会停止此入口转发。')){await api(`/api/routes/${id}?revision=${overview.revision}`,'DELETE');await load();}return;}
  if(action==='preview'){const p=await api('/api/gateway/preview','POST');edit('发布预览',`<p class="hint full">草稿版本 ${p.revision} · ${esc(p.digest)}<br>将执行二次校验、nginx -t、reload 与配置指纹检查。失败时恢复旧配置。</p><pre class="readbox">${esc(p.config)}</pre>`+field('note','发布说明','','text'),async f=>{await api('/api/gateway/publish','POST',{revision:p.revision,digest:p.digest,note:f.get('note')});},'确认发布');return;}
  if(action==='reconcile'){await api('/api/gateway/reconcile','POST');toast('状态核对完成');await load();return;}
  if(action==='rollback'){const r=window.sgReleases.find(x=>x.id===id);if(confirm(`将线上网关回滚到 ${r.id.slice(0,8)}？当前草稿不会被覆盖。`)){await api(`/api/gateway/rollback/${id}`,'POST',{revision:overview.revision,digest:r.digest,note:'从控制台回滚到 '+id});await load();}return;}
  if(action==='import'){const inv=await api('/api/inventory');edit('导入 E5 服务',`<p class="hint full">远程模式不自动信任旧 E5 登记。请粘贴导出的清单并在远程机重新批准实际 unit；不会执行旧源码、覆盖已有登记或自动创建路由。</p>`+field('items','服务清单数组 JSON',JSON.stringify(inv.manifests,null,2),'textarea',{rows:18}),async f=>{const services=JSON.parse(f.get('items'));const p=await api('/api/import/e5','POST',{services,apply:false});if(p.conflicts.length)throw new Error('存在冲突：'+p.conflicts.join(', '));if(!confirm(`新增 ${p.additions.length} 项，保持 ${p.unchanged.length} 项不变，确认导入？`))throw new Error('已取消导入');await api('/api/import/e5','POST',{services,apply:true,revision:p.revision});},'预览导入');return;}
  if(action==='key-new'){edit('创建限定作用域密钥',field('name','名称')+field('expires_days','有效天数',90,'number')+field('route_ids','可访问的路由 ID（逗号分隔）')+field('service_ids','可登记的服务 ID（逗号分隔）'),async f=>{const split=k=>f.get(k).split(',').map(x=>x.trim()).filter(Boolean);const result=await api('/api/keys','POST',{name:f.get('name'),expires_days:Number(f.get('expires_days')),route_ids:split('route_ids'),service_ids:split('service_ids')});$('#editor').close();read('请立即保存；密钥仅显示一次',result.token+'\n\n请求头：X-Gateway-Key\n关闭后无法再次查看。');return false;});return;}
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
