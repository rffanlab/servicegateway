export function cloneRouteDraft(routes, sourceId) {
  const source = routes.find(route => route.id === sourceId);
  if (!source) throw new Error('路由不存在，请刷新页面');
  const copy = JSON.parse(JSON.stringify(source));
  const used = new Set(routes.map(route => route.id));
  let base = (source.id + '-copy').slice(0, 63), candidate = base, n = 2;
  while (used.has(candidate)) {
    const suffix = '-' + n++;
    candidate = base.slice(0, 63 - suffix.length) + suffix;
  }
  copy.id = candidate;
  copy.name = (source.name + ' 副本').slice(0, 100);
  return copy;
}
