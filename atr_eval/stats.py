"""Interval estimates and exact tests for success rates over a small number of trials."""

from __future__ import annotations

import math

_Z95 = 1.959963984540054
_Z90 = 1.6448536269514722


def _hypergeom(k: int, n1: int, n2: int, total: int) -> float:
    return math.comb(total, k) * math.comb(n1 + n2 - total, n1 - k) / math.comb(n1 + n2, n1)


def fisher_two_sided(a: int, n1: int, b: int, n2: int) -> float:
    """Two-sided Fisher exact test for a/n1 vs b/n2: the probability of tables at least as extreme as observed."""
    total = a + b
    lo, hi = max(0, total - n2), min(total, n1)
    observed = _hypergeom(a, n1, n2, total)
    p = sum(q for k in range(lo, hi + 1) if (q := _hypergeom(k, n1, n2, total)) <= observed * (1 + 1e-9))
    return min(1.0, p)


def fisher_greater(a: int, n1: int, b: int, n2: int) -> float:
    """One-sided Fisher exact test that a/n1 is greater than b/n2: P(first group has a or more successes | margins)."""
    total = a + b
    hi = min(total, n1)
    return min(1.0, sum(_hypergeom(k, n1, n2, total) for k in range(a, hi + 1)))


def shown(p: float) -> float:
    """A p-value as it is recorded: four significant figures, so a very small value does not read as 0."""
    return float(f"{p:.4g}")


def _wilson_raw(successes: int, trials: int, z: float) -> tuple[float, float]:
    p = successes / trials
    denom = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denom
    half = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def wilson(successes: int, trials: int, z: float = _Z95) -> tuple[float, float]:
    """Wilson score interval, rounded to 4 places."""
    if trials <= 0:
        raise ValueError("trials must be positive")
    if not 0 <= successes <= trials:
        raise ValueError("successes must be between 0 and trials")
    lo, hi = _wilson_raw(successes, trials, z)
    return (round(lo, 4), round(hi, 4))


def newcombe_difference(a: int, n1: int, b: int, n2: int, z: float = _Z90) -> tuple[float, float]:
    """Newcombe's hybrid score interval for a/n1 - b/n2 (his method 10). The default z gives the 90% interval that a
    two one-sided tests (TOST) equivalence check at alpha 0.05 needs."""
    if n1 <= 0 or n2 <= 0:
        raise ValueError("trials must be positive")
    p1, p2 = a / n1, b / n2
    l1, u1 = _wilson_raw(a, n1, z)
    l2, u2 = _wilson_raw(b, n2, z)
    d = p1 - p2
    lo = d - math.sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2)
    hi = d + math.sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2)
    return (round(max(-1.0, lo), 4), round(min(1.0, hi), 4))


def holm(pvalues: list[float]) -> list[float]:
    """Holm step-down adjusted p-values, returned in the order given. Pass unrounded p-values: rounding first can
    move a value across alpha."""
    m = len(pvalues)
    order = sorted(range(m), key=lambda i: pvalues[i])
    adjusted = [0.0] * m
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (m - rank) * pvalues[i]))
        adjusted[i] = running
    return adjusted


def smallest_detectable(n_now: int, baseline_successes: int, n_before: int, alpha: float = 0.05) -> int | None:
    """The fewest successes in n_now trials that a one-sided Fisher test at alpha calls an increase over the
    baseline. None when no count can."""
    for k in range(n_now + 1):
        if k / n_now > baseline_successes / n_before and fisher_greater(k, n_now, baseline_successes, n_before) < alpha:
            return k
    return None


def stratified_exact(tables: list[tuple[int, int, int, int]]) -> float:
    """Exact conditional test of no difference across strata (the exact Cochran-Mantel-Haenszel test).

    Each table is (a, n1, b, n2): a successes in n1 trials of the first condition, b in n2 of the second, for one
    atomic. The statistic is the first condition's total successes; its null distribution is the convolution of
    each stratum's hypergeometric distribution. Two-sided: tables no more likely than the one observed."""
    dist = {0: 1.0}
    observed = 0
    for a, n1, b, n2 in tables:
        total = a + b
        lo, hi = max(0, total - n2), min(total, n1)
        stratum = [(k, _hypergeom(k, n1, n2, total)) for k in range(lo, hi + 1)]
        convolved: dict[int, float] = {}
        for s, ps in dist.items():
            for k, pk in stratum:
                convolved[s + k] = convolved.get(s + k, 0.0) + ps * pk
        dist = convolved
        observed += a
    p_obs = dist.get(observed, 0.0)
    return min(1.0, sum(q for q in dist.values() if q <= p_obs * (1 + 1e-7)))
