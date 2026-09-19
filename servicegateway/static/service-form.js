// Pure form conversion, shared by the console and Node regression tests.
export function serviceFromForm(form, previousId = null) {
  const string = name => String(form.get(name) ?? '').trim();
  const id = string('id');
  if (!/^[a-z][a-z0-9-]{0,62}$/.test(id)) throw new Error('服务 ID 必须以小写字母开头，只能包含小写字母、数字和连字符');
  if (previousId && id !== previousId) throw new Error('编辑不能更改服务 ID');
  const services = form.getAll('unit').map(x => String(x).trim()).filter(Boolean);
  if (!services.length || services.length > 16 || new Set(services).size !== services.length || services.some(x => !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}\.service$/.test(x))) throw new Error('请填写 1–16 个不同的完整 .service 名称，不支持通配符或模板');
  const port = Number(string('port'));
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('展示入口端口必须为 1–65535；该字段不会开放防火墙');
  if (!string('name')) throw new Error('请填写服务名称');
  if (!/^http:\/\/[0-9.]+(?::[0-9]+)?\//.test(string('health_url'))) throw new Error('健康地址请使用完整的已批准 HTTP IPv4 地址，例如 http://127.0.0.1:18188/healthz');
  return {id, name: string('name'), description: string('description'), services, url: string('url'), port, health_url: string('health_url'), gpu: string('gpu'), accent: string('accent'), warning: string('warning')};
}
