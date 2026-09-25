export function keyScopeData(overview) {
  const services=(overview?.assets??[]).map(s=>({id:s.id,name:s.name}));
  const routes=(overview?.routes??[]).map(r=>({
    id:r.id,
    name:r.name,
    service_id:r.service_id,
    host:r.host,
    path:r.path,
    auth:r.auth
  }));
  return {services,routes};
}

export function collectKeyScopes(form) {
  const uniq=name=>[...new Set(form.getAll(name).map(String).map(x=>x.trim()).filter(Boolean))];
  return {
    route_ids:uniq('route_ids'),
    service_ids:uniq('service_ids'),
    user_service_ids:uniq('user_service_ids')
  };
}
