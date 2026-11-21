"""Correlation engine — connects events that share attributes (username, IPs,
hostname, file hash, domain, URL, session, process) into possible attack chains
using union-find clustering."""
from __future__ import annotations

from collections import defaultdict

CORRELATION_KEYS = ("username", "source_ip", "destination_ip", "hostname",
                    "file_hash", "domain", "url", "session_id", "process_id")

# attribute values too generic to correlate on
STOP_VALUES = {"", "unknown", "n/a", "none", "system", "-"}


class _UnionFind:
    def __init__(self, size):
        self.parent = list(range(size))

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _event_attr(event, key):
    value = getattr(event, key, None)
    if value is None:
        return None
    value = str(value).strip().lower()
    return value if value and value not in STOP_VALUES else None


def build_correlation(events) -> dict:
    """Cluster events by shared attributes; return chains + link counts."""
    suspicious = [e for e in events if e.is_suspicious]
    # Correlate suspicious events with every event (so benign context joins chains)
    pool = suspicious + [e for e in events if not e.is_suspicious]
    index = {e.id: i for i, e in enumerate(pool)}
    uf = _UnionFind(len(pool))

    groups: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
    for e in pool:
        for key in CORRELATION_KEYS:
            value = _event_attr(e, key)
            if value:
                groups[key][value].append(e.id)

    link_counts = {key: sum(1 for v in groups[key].values() if len(v) > 1) for key in CORRELATION_KEYS}
    for key in CORRELATION_KEYS:
        for value, event_ids in groups[key].items():
            if len(event_ids) > 1:
                first = index[event_ids[0]]
                for eid in event_ids[1:]:
                    uf.union(first, index[eid])

    clusters: dict[int, list] = defaultdict(list)
    for e in pool:
        clusters[uf.find(index[e.id])].append(e)

    # A chain must contain at least 2 suspicious events to be an attack sequence
    chains = []
    for members in clusters.values():
        susp = sorted([e for e in members if e.is_suspicious], key=lambda e: e.timestamp or "")
        if len(susp) < 2:
            continue
        context = [e for e in members if not e.is_suspicious]
        shared = defaultdict(set)
        for key in CORRELATION_KEYS:
            values = defaultdict(int)
            for e in members:
                v = _event_attr(e, key)
                if v:
                    values[v] += 1
            for v, c in values.items():
                if c >= 2:
                    shared[key].add(v)
        chains.append({
            "chain_id": f"CHAIN-{len(chains) + 1:02d}",
            "event_count": len(members),
            "suspicious_count": len(susp),
            "event_ids": [e.code for e in susp],
            "context_event_ids": [e.code for e in context[:10]],
            "evidence_ids": sorted({e.evidence.code for e in members if e.evidence}),
            "shared_attributes": {k: sorted(v)[:5] for k, v in shared.items() if v},
            "time_span": {"start": susp[0].timestamp, "end": susp[-1].timestamp},
            "sequence": [
                {"event_code": e.code, "timestamp": e.timestamp, "event_type": e.event_type,
                 "username": e.username, "source_ip": e.source_ip,
                 "summary": (e.message or f"{e.event_type} {e.action or ''}".strip())[:220]}
                for e in susp
            ],
        })

    chains.sort(key=lambda c: -c["suspicious_count"])
    for i, c in enumerate(chains):
        c["chain_id"] = f"CHAIN-{i + 1:02d}"

    return {
        "chains": chains,
        "correlated_events": sum(c["event_count"] for c in chains),
        "link_counts": link_counts,
        "note": "Events were clustered on shared username, IP, hostname, file hash, domain, "
                "URL, session and process identifiers. Clusters are possible relationships, "
                "not proof of causation.",
    }
