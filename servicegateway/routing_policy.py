"""Root-policy helpers for per-service source CIDR ceilings.

Existing policies remain compatible: a service without ``source_cidrs`` inherits
``policy.allowed_cidrs``.  Route CIDRs may narrow that ceiling but never widen it.
"""
import ipaddress


def _networks(values, label):
    if not isinstance(values, list) or not values or any(not isinstance(v, str) for v in values):
        raise ValueError(f"{label} must be a non-empty list of IPv4 CIDRs")
    try:
        return [ipaddress.IPv4Network(v, strict=False) for v in values]
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 CIDR in {label}") from exc


def normalize_service_source_cidrs(policy):
    global_networks = _networks(policy.get("allowed_cidrs", []), "allowed_cidrs")
    policy["allowed_cidrs"] = [str(n) for n in global_networks]
    for service_id, grant in policy.get("services", {}).items():
        if not isinstance(grant, dict):
            raise ValueError(f"Invalid service grant: {service_id}")
        if "source_cidrs" in grant:
            grant["source_cidrs"] = [str(n) for n in _networks(grant["source_cidrs"], f"services.{service_id}.source_cidrs")]
    return policy


def service_source_cidrs(policy, service_id):
    grant = policy.get("services", {}).get(service_id)
    if not grant:
        raise ValueError(f"Unknown service source policy: {service_id}")
    return grant.get("source_cidrs") or policy["allowed_cidrs"]


def effective_route_cidrs(policy, route):
    ceiling = service_source_cidrs(policy, route.service_id)
    return route.allow_cidrs or ceiling


def validate_route_source_cidrs(policy, route):
    ceilings = [ipaddress.IPv4Network(v, strict=False) for v in service_source_cidrs(policy, route.service_id)]
    requested = route.allow_cidrs or [str(n) for n in ceilings]
    for value in requested:
        network = ipaddress.IPv4Network(value, strict=False)
        if not any(network.subnet_of(parent) for parent in ceilings):
            raise ValueError("Route CIDRs cannot broaden the service source CIDR ceiling")
    return [str(ipaddress.IPv4Network(v, strict=False)) for v in requested]
