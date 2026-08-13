"""Aegis frame-pipeline metrics.

The metrics module is intentionally small: it re-exports
:class:`FrameMetrics` and :class:`FrameMetricsSnapshot` from
:mod:`guardianmesh.aegis.models` so that callers can import the
metrics primitives from a focused, dedicated module.

The module exists to:

* document the metrics contract in one place;
* give the unit tests a single import path;
* separate the ``metrics`` API from the ``models`` API while sharing
  the same data structures.
"""

from __future__ import annotations

from guardianmesh.aegis.models import FrameMetrics, FrameMetricsSnapshot

__all__ = [
    "FrameMetrics",
    "FrameMetricsSnapshot",
]
