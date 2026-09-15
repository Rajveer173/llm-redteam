"""Attack success rate with a bootstrap confidence interval.

Reusing the tokfair approach: rather than report a bare percentage, resample the trial outcomes to get a
95% CI, so "40% ASR" carries how many trials it came from. Deterministic given a seed.
"""

from __future__ import annotations

import numpy as np


def asr_ci(successes: list[bool], n_boot: int = 10_000, seed: int = 0) -> tuple[float, float, float]:
    """Return (mean, lo, hi) of the attack success rate as fractions in [0, 1]."""
    if not successes:
        return 0.0, 0.0, 0.0
    arr = np.array(successes, dtype=float)
    mean = float(arr.mean())
    if len(arr) == 1:
        return mean, mean, mean
    rng = np.random.default_rng(seed)
    boots = rng.choice(arr, size=(n_boot, len(arr)), replace=True).mean(axis=1)
    lo, hi = np.percentile(boots, [2.5, 97.5])
    return mean, float(lo), float(hi)


def pct(x: float) -> str:
    return f"{100 * x:.1f}%"
