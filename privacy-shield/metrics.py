"""Privacy-Shield runtime metrics.

Provides small, side-channel-safe counters for cache efficiency and masking
volume. Optional prometheus_client integration is loaded lazily; when the
package is not installed the Prometheus path is a no-op.
"""

from __future__ import annotations

import threading
from typing import Any

# Side-channel-safe integer counters. These are updated on the hot path,
# so we keep the implementation lock-free (single integer increments).
_cache_hits: int = 0
_cache_misses: int = 0
_masking_volume: int = 0
_lock = threading.Lock()


def record_cache_hit() -> None:
    """Increment the pseudonymizer token-cache hit counter."""
    global _cache_hits
    with _lock:
        _cache_hits += 1


def record_cache_miss() -> None:
    """Increment the pseudonymizer token-cache miss counter."""
    global _cache_misses
    with _lock:
        _cache_misses += 1


def record_masking(count: int = 1) -> None:
    """Increment the total number of PII values replaced by tokens."""
    global _masking_volume
    with _lock:
        _masking_volume += count


def get_metrics() -> dict[str, Any]:
    """Return a snapshot of all current Privacy-Shield metrics.

    PERF-2 (Morpheus R5): exposes ``cache_hit_ratio`` as a stable alias
    for ``cache_hit_rate`` so the metrics contract matches the acceptance
    criterion while remaining backward compatible with callers that
    already read ``cache_hit_rate``.
    """
    with _lock:
        total = _cache_hits + _cache_misses
        hit_rate = _cache_hits / total if total else 0.0
        return {
            "cache_hits": _cache_hits,
            "cache_misses": _cache_misses,
            "cache_hit_rate": round(hit_rate, 4),
            "cache_hit_ratio": round(hit_rate, 4),
            "masking_volume": _masking_volume,
        }


def reset_metrics() -> None:
    """Reset all counters to zero. Intended for tests only."""
    global _cache_hits, _cache_misses, _masking_volume
    with _lock:
        _cache_hits = 0
        _cache_misses = 0
        _masking_volume = 0


# ── Optional Prometheus integration ──────────────────────────────────────────
# v0.21.0: the plugin module can be imported more than once per process
# (main + auxiliary loader). Registering into the global REGISTRY then
# raises "Duplicated timeseries" and aborts the whole plugin load. Use a
# module-private registry and tolerate re-imports.
try:
    from prometheus_client import (
        REGISTRY,
        CollectorRegistry,
        Counter,
    )

    _prom_registry: CollectorRegistry | None = CollectorRegistry()
    if not getattr(REGISTRY, "_names_to_collectors", {}).get(
        "privacy_shield_cache_hits_total"
    ):
        _prom_registry = REGISTRY
    _prom_cache_hits = Counter(
        "privacy_shield_cache_hits_total",
        "Token cache hits",
        registry=_prom_registry,
    )
    _prom_cache_misses = Counter(
        "privacy_shield_cache_misses_total",
        "Token cache misses",
        registry=_prom_registry,
    )
    _prom_masking_volume = Counter(
        "privacy_shield_masking_volume_total",
        "Number of PII values replaced by tokens",
        registry=_prom_registry,
    )

    def _record_prometheus(hits: int = 0, misses: int = 0, masking: int = 0) -> None:
        if _prom_cache_hits is not None:
            _prom_cache_hits.inc(hits)
        if _prom_cache_misses is not None:
            _prom_cache_misses.inc(misses)
        if _prom_masking_volume is not None:
            _prom_masking_volume.inc(masking)

    # Patch the public helpers to also update Prometheus counters.
    _original_record_cache_hit = record_cache_hit
    _original_record_cache_miss = record_cache_miss
    _original_record_masking = record_masking

    def record_cache_hit() -> None:
        _original_record_cache_hit()
        _record_prometheus(hits=1)

    def record_cache_miss() -> None:
        _original_record_cache_miss()
        _record_prometheus(misses=1)

    def record_masking(count: int = 1) -> None:
        _original_record_masking(count)
        _record_prometheus(masking=count)

except ImportError:
    # prometheus_client is optional; when absent the in-memory counters still work.
    pass
