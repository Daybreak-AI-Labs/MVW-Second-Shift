"""Statistical drift for a registered model: the formulas and the profiles.

Second Shift receives no inputs or outputs from the platforms where models run.
The owner of a model sends batches of samples (numbers, categories, predicted
labels or scores, true labels when known, optionally embeddings) and this module
turns a batch into a small aggregate profile and compares two profiles:

* ``build_profile`` -- the profile of a batch: per signal a histogram (bin edges
  and counts) or category counts, a mean, an embedding centroid or an accuracy.
  The samples are read once, in memory, and are not kept. What survives is
  bounded and holds no row: at most ``MAX_FEATURES`` features, ``bins`` bins
  each, ``MAX_CATEGORIES`` category names (a value seen fewer than
  ``MIN_CATEGORY_COUNT`` times is counted under "other" and never named) and one
  embedding centroid of at most ``MAX_EMBEDDING_DIMENSIONS`` numbers. Bin edges
  run from the 1st to the 99th percentile of the batch, so they describe the
  spread, not any one value.
* ``compare`` -- a check batch against an approved baseline profile: population
  stability index, Jensen-Shannon divergence, a chi-squared two-sample test, a
  Kolmogorov-Smirnov test over the binned values (numeric signals), embedding
  centroid cosine distance and accuracy decay, with a finding wherever a
  setting says the result is too large.

The formulas are the standard ones, written here in pure Python. Chi-squared and
Kolmogorov-Smirnov p-values come from the incomplete gamma function and the
asymptotic Kolmogorov series (Numerical Recipes, ``gammq`` and ``probks``).

What it does not do. It does not store, send or log a sample, decide what a
finding means, or act on one: a statistic says the data looks different, never
that the model is wrong. The thresholds in :func:`settings` are defaults that
must be calibrated for each model; with large samples even a harmless change
gives a tiny p-value.
"""
from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from typing import Any

SCHEMA = 1

MAX_FEATURES = 16
MAX_VALUES = 5000
MAX_CATEGORIES = 32
MIN_CATEGORY_COUNT = 5
MAX_TEXT = 64
MAX_EMBEDDING_ROWS = 200
MAX_EMBEDDING_DIMENSIONS = 256
#: Numbers in one batch, over every series together, so a batch fits the
#: 256 KiB an outside agent's request may carry.
MAX_NUMBERS = 20_000
#: A probability below this is treated as this, so an empty bin cannot make the
#: index infinite.
_FLOOR = 1e-4
#: A whole-number prediction with at most this many distinct values is a class.
_CLASS_LIMIT = 10
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.\-]{0,63}")

LOW, MEDIUM, HIGH = "low", "medium", "high"

#: ``[model_drift]`` number settings: name -> (type, default, lowest, highest).
_NUMBER_SETTINGS: dict[str, tuple[type, float, float, float]] = {
    "bins": (int, 10, 2, 32),
    "min_samples": (int, 30, 10, MAX_VALUES),
    "psi_threshold": (float, 0.2, 0.01, 10.0),
    "js_threshold": (float, 0.1, 0.001, 1.0),
    "ks_p_value_floor": (float, 0.01, 0.0001, 0.5),
    "chi2_p_value_floor": (float, 0.01, 0.0001, 0.5),
    "embedding_cosine_threshold": (float, 0.1, 0.001, 2.0),
    "accuracy_decay_threshold": (float, 0.05, 0.001, 1.0),
    "batches_per_minute": (int, 20, 1, 600),
}


class SampleError(ValueError):
    """A batch that cannot be used. The message says what to fix."""


# ----------------------------------------------------------------- settings

def settings() -> dict:
    """The validated ``[model_drift]`` section: ``enable`` (default on), the
    histogram ``bins``, ``min_samples`` a series needs, one threshold per
    statistic and ``batches_per_minute``. A number outside its range is
    clamped; anything malformed, or a section that cannot be read, falls back to
    the default. Defaults are a starting point: calibrate them per model."""
    try:
        from .config import load_config
        section = (load_config() or {}).get("model_drift")
    except Exception:
        section = None
    section = section if isinstance(section, dict) else {}
    flag = section.get("enable")
    out: dict[str, Any] = {"enable": flag if isinstance(flag, bool) else True}
    for name, (kind, default, low, high) in _NUMBER_SETTINGS.items():
        raw = section.get(name)
        ok = (isinstance(raw, (int, float)) and not isinstance(raw, bool) and math.isfinite(raw)
              and not (kind is int and raw != int(raw)))
        out[name] = kind(max(low, min(high, raw))) if ok else kind(default)
    return out


# ---------------------------------------------------------------- statistics

def _distribution(counts: Sequence[float]) -> list[float]:
    values = [float(c) for c in counts]
    if not values or any(not math.isfinite(v) or v < 0 for v in values):
        raise SampleError("Counts must be zero or more.")
    total = sum(values)
    if total <= 0:
        raise SampleError("Counts must hold at least one sample.")
    return [max(v / total, _FLOOR) for v in values]


def population_stability_index(reference: Sequence[float], current: Sequence[float]) -> float:
    """PSI between two aligned count vectors: the sum over bins of
    ``(actual - expected) * ln(actual / expected)`` on the shares of each bin.
    0 for the same spread; about 0.1 is a small shift and 0.25 a large one by
    the usual rule of thumb. A share under 0.01% counts as 0.01%."""
    if len(reference) != len(current):
        raise SampleError("The two distributions must have the same bins.")
    expected, actual = _distribution(reference), _distribution(current)
    return max(0.0, sum((a - e) * math.log(a / e) for e, a in zip(expected, actual, strict=True)))


def js_divergence(reference: Sequence[float], current: Sequence[float]) -> float:
    """Jensen-Shannon divergence between two aligned count vectors, in bits:
    0 for the same spread and 1 for spreads with nothing in common."""
    if len(reference) != len(current):
        raise SampleError("The two distributions must have the same bins.")
    p = [c / sum(reference) for c in reference] if sum(reference) > 0 else []
    q = [c / sum(current) for c in current] if sum(current) > 0 else []
    if not p or not q or any(c < 0 for c in (*reference, *current)):
        raise SampleError("Counts must hold at least one sample.")
    total = 0.0
    for a, b in zip(p, q, strict=True):
        middle = (a + b) / 2
        if a > 0:
            total += a * math.log2(a / middle)
        if b > 0:
            total += b * math.log2(b / middle)
    return min(1.0, max(0.0, total / 2))


def chi_square_survival(statistic: float, dof: int) -> float:
    """P(chi-squared with ``dof`` degrees of freedom >= ``statistic``): the
    upper regularised incomplete gamma function Q(dof/2, statistic/2), by its
    series below ``s + 1`` and a continued fraction above."""
    s, x = dof / 2.0, statistic / 2.0
    if dof < 1 or statistic < 0 or not math.isfinite(statistic):
        raise SampleError("The chi-squared statistic is not valid.")
    if x == 0:
        return 1.0
    prefix = math.exp(-x + s * math.log(x) - math.lgamma(s))
    if x < s + 1.0:
        term = total = 1.0 / s
        denominator = s
        for _ in range(1000):
            denominator += 1.0
            term *= x / denominator
            total += term
            if abs(term) < abs(total) * 1e-16:
                break
        return min(1.0, max(0.0, 1.0 - total * prefix))
    tiny = 1e-300
    b = x + 1.0 - s
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 1000):
        a = -i * (i - s)
        b += 2.0
        d = a * d + b
        d = tiny if abs(d) < tiny else d
        c = b + a / c
        c = tiny if abs(c) < tiny else c
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-16:
            break
    return min(1.0, max(0.0, h * prefix))


def chi_squared_two_sample(reference: Sequence[float], current: Sequence[float]) -> dict:
    """Two-sample chi-squared test that two count vectors come from the same
    spread. With totals ``R`` and ``S`` the statistic is the sum over bins of
    ``(sqrt(S/R) r - sqrt(R/S) s)^2 / (r + s)``; bins empty in both samples are
    left out and the degrees of freedom are the bins used minus one."""
    if len(reference) != len(current) or not reference:
        raise SampleError("The two distributions must have the same bins.")
    r_total, s_total = float(sum(reference)), float(sum(current))
    if r_total <= 0 or s_total <= 0 or any(c < 0 for c in (*reference, *current)):
        raise SampleError("Counts must hold at least one sample.")
    up, down = math.sqrt(s_total / r_total), math.sqrt(r_total / s_total)
    statistic, used = 0.0, 0
    for r, s in zip(reference, current, strict=True):
        if r + s > 0:
            used += 1
            statistic += (up * r - down * s) ** 2 / (r + s)
    dof = max(1, used - 1)
    return {"statistic": statistic, "dof": dof, "p_value": chi_square_survival(statistic, dof)}


def ks_survival(lam: float) -> float:
    """The Kolmogorov distribution's tail, ``2 * sum (-1)^(k-1) exp(-2 k^2 lam^2)``.
    1 where the series does not converge (a ``lam`` too small to tell apart)."""
    if lam <= 0:
        return 1.0
    total = 0.0
    for k in range(1, 101):
        term = (-1.0) ** (k - 1) * math.exp(-2.0 * (k * lam) ** 2)
        total += term
        if abs(term) < 1e-16:
            return min(1.0, max(0.0, 2.0 * total))
    return 1.0


def ks_two_sample_binned(reference: Sequence[float], current: Sequence[float]) -> dict:
    """Two-sample Kolmogorov-Smirnov test on two aligned histograms: the
    largest gap between their cumulative shares, and the asymptotic p-value
    with the effective sample size ``R*S/(R+S)`` (Stephens' correction). Exact
    for the binned values, so it cannot see a difference inside one bin."""
    if len(reference) != len(current) or not reference:
        raise SampleError("The two distributions must have the same bins.")
    r_total, s_total = float(sum(reference)), float(sum(current))
    if r_total <= 0 or s_total <= 0 or any(c < 0 for c in (*reference, *current)):
        raise SampleError("Counts must hold at least one sample.")
    gap = left = right = 0.0
    for r, s in zip(reference, current, strict=True):
        left += r / r_total
        right += s / s_total
        gap = max(gap, abs(left - right))
    effective = r_total * s_total / (r_total + s_total)
    lam = (math.sqrt(effective) + 0.12 + 0.11 / math.sqrt(effective)) * gap
    return {"statistic": gap, "p_value": ks_survival(lam)}


def cosine_distance(reference: Sequence[float], current: Sequence[float]) -> float:
    """``1 - cosine similarity``: 0 for the same direction, 1 at right angles,
    2 for opposite. A zero vector against anything else is 1."""
    if not reference or len(reference) != len(current):
        raise SampleError("The two embeddings must have the same length.")
    a_norm = math.sqrt(sum(v * v for v in reference))
    b_norm = math.sqrt(sum(v * v for v in current))
    if a_norm == 0 and b_norm == 0:
        return 0.0
    if a_norm == 0 or b_norm == 0:
        return 1.0
    similarity = sum(a * b for a, b in zip(reference, current, strict=True)) / (a_norm * b_norm)
    return max(0.0, 1.0 - max(-1.0, min(1.0, similarity)))


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _outcome(value: Any) -> tuple[str, Any]:
    return ("n", float(value)) if _number(value) else ("s", str(value).strip())


def accuracy(predictions: Sequence[Any], labels: Sequence[Any]) -> float:
    """The share of predictions equal to the true label. Numbers compare by
    value (``1`` equals ``1.0``); anything else by its trimmed text."""
    if len(predictions) != len(labels) or not predictions:
        raise SampleError("Predictions and true labels must be the same, non-zero length.")
    hits = sum(_outcome(p) == _outcome(t) for p, t in zip(predictions, labels, strict=True))
    return hits / len(predictions)


# ------------------------------------------------------------------ profiles

def _sig(value: float, digits: int = 9) -> float:
    return float(f"{value:.{digits}g}")


def _text(value: Any, what: str) -> str:
    ok = isinstance(value, (str, int, float)) and not isinstance(value, bool)
    text = str(value).strip() if ok else ""
    if not text or len(text) > MAX_TEXT or not text.isprintable():
        raise SampleError(f"{what} must be short text of at most {MAX_TEXT} characters.")
    return text


def _numbers(values: Any, what: str, minimum: int) -> list[float]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise SampleError(f"{what} must be a list of numbers.")
    if len(values) > MAX_VALUES:
        raise SampleError(f"{what} may hold at most {MAX_VALUES} values.")
    if len(values) < minimum:
        raise SampleError(f"{what} needs at least {minimum} values; it has {len(values)}.")
    if not all(_number(v) for v in values):
        raise SampleError(f"{what} must hold only finite numbers.")
    return [float(v) for v in values]


def _percentile(ordered: Sequence[float], share: float) -> float:
    position = (len(ordered) - 1) * share
    below = int(math.floor(position))
    above = min(len(ordered) - 1, below + 1)
    return ordered[below] + (ordered[above] - ordered[below]) * (position - below)


def _edges(values: Sequence[float], bins: int) -> list[float]:
    ordered = sorted(values)
    low, high = _percentile(ordered, 0.01), _percentile(ordered, 0.99)
    if low == high:
        pad = max(abs(low) * 0.01, 0.5)
        low, high = low - pad, high + pad
    width = (high - low) / bins
    return [_sig(low + width * i) for i in range(bins + 1)]


def _bin_counts(values: Sequence[float], edges: Sequence[float]) -> list[int]:
    bins = len(edges) - 1
    low, high = edges[0], edges[-1]
    width = (high - low) / bins
    counts = [0] * bins
    for value in values:
        counts[0 if value <= low else bins - 1 if value >= high else min(bins - 1, int((value - low) / width))] += 1
    return counts


def _numeric_profile(values: Sequence[float], bins: int) -> dict:
    edges = _edges(values, bins)
    return {"kind": "numeric", "n": len(values), "mean": _sig(sum(values) / len(values)),
            "edges": edges, "counts": _bin_counts(values, edges)}


def _category_profile(values: Sequence[str]) -> dict:
    tally: dict[str, int] = {}
    for value in values:
        tally[value] = tally.get(value, 0) + 1
    named = sorted((name for name, count in tally.items() if count >= MIN_CATEGORY_COUNT),
                   key=lambda name: (-tally[name], name))[:MAX_CATEGORIES]
    other = len(values) - sum(tally[name] for name in named)
    return {"kind": "categorical", "n": len(values), "categories": named,
            "counts": [tally[name] for name in named] + [other]}


def _is_class(values: Sequence[float]) -> bool:
    return all(v == int(v) for v in values) and len(set(values)) <= _CLASS_LIMIT


def _class_name(value: float) -> str:
    return str(int(value))


def _prediction_profile(values: Sequence[Any], bins: int, minimum: int) -> dict:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise SampleError("Predictions must be a list.")
    if len(values) > MAX_VALUES:
        raise SampleError(f"Predictions may hold at most {MAX_VALUES} values.")
    if len(values) < minimum:
        raise SampleError(f"Predictions need at least {minimum} values; they have {len(values)}.")
    if all(_number(v) for v in values):
        floats = [float(v) for v in values]
        if _is_class(floats):
            return _category_profile([_class_name(v) for v in floats])
        return _numeric_profile(floats, bins)
    return _category_profile([_text(v, "A prediction") for v in values])


def _current_prediction_counts(values: Sequence[Any], base: Mapping) -> list[int]:
    if all(_number(v) for v in values):
        floats = [float(v) for v in values]
        if base["kind"] == "numeric":
            return _bin_counts(floats, base["edges"])
        return _category_counts([_class_name(v) if v == int(v) else str(v) for v in floats], base)
    if base["kind"] == "numeric":
        raise SampleError("Predictions were numbers in the baseline but are text in this batch.")
    return _category_counts([_text(v, "A prediction") for v in values], base)


def _category_counts(values: Sequence[str], base: Mapping) -> list[int]:
    names = list(base["categories"])
    counts = [0] * (len(names) + 1)
    position = {name: i for i, name in enumerate(names)}
    for value in values:
        counts[position.get(value, len(names))] += 1
    return counts


def _embedding_profile(rows: Any, minimum: int) -> dict:
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        raise SampleError("Embeddings must be a list of lists of numbers.")
    if len(rows) > MAX_EMBEDDING_ROWS:
        raise SampleError(f"Embeddings may hold at most {MAX_EMBEDDING_ROWS} rows.")
    if len(rows) < minimum:
        raise SampleError(f"Embeddings need at least {minimum} rows; they have {len(rows)}.")
    width = len(rows[0]) if isinstance(rows[0], Sequence) and not isinstance(rows[0], (str, bytes)) else 0
    if not 1 <= width <= MAX_EMBEDDING_DIMENSIONS:
        raise SampleError(f"Each embedding needs between 1 and {MAX_EMBEDDING_DIMENSIONS} numbers.")
    total = [0.0] * width
    for row in rows:
        if (not isinstance(row, Sequence) or isinstance(row, (str, bytes)) or len(row) != width
                or not all(_number(v) for v in row)):
            raise SampleError("Every embedding must be a list of the same number of finite numbers.")
        for i, v in enumerate(row):
            total[i] += float(v)
    return {"kind": "embedding", "n": len(rows), "dimension": width,
            "centroid": [_sig(v / len(rows)) for v in total]}


def check_size(samples: Mapping[str, Any]) -> None:
    """Refuse a batch with too many numbers or features before reading it."""
    numeric = samples.get("numeric") or {}
    categorical = samples.get("categorical") or {}
    if len(numeric) + len(categorical) > MAX_FEATURES:
        raise SampleError(f"A batch may hold at most {MAX_FEATURES} features.")
    count = sum(len(v) for v in numeric.values()) + sum(len(v) for v in categorical.values())
    count += len(samples.get("predictions") or ()) + len(samples.get("labels") or ())
    count += sum(len(r) for r in samples.get("embeddings") or ())
    if count > MAX_NUMBERS:
        raise SampleError(f"A batch may hold at most {MAX_NUMBERS:,} values in all.")
    for name in (*numeric, *categorical):
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise SampleError("A feature name is letters, digits, spaces, dots, dashes and underscores, "
                              "up to 64 characters.")
    if set(numeric) & set(categorical):
        raise SampleError("A feature is either numbers or categories, not both.")


def build_profile(samples: Mapping[str, Any], *, bins: int, min_samples: int) -> dict:
    """The aggregate profile of a baseline batch. ``samples`` may hold
    ``numeric`` and ``categorical`` (name to list), ``predictions``, ``labels``
    (true values, which need predictions) and ``embeddings``. Raises
    :class:`SampleError` for a batch that is too small, too large or malformed,
    or that holds nothing to monitor. Nothing of ``samples`` is kept."""
    check_size(samples)
    signals: dict[str, dict] = {}
    for name, values in (samples.get("numeric") or {}).items():
        signals[f"feature:{name}"] = _numeric_profile(_numbers(values, f"Feature {name}", min_samples), bins)
    for name, values in (samples.get("categorical") or {}).items():
        if len(values) < min_samples or len(values) > MAX_VALUES:
            raise SampleError(f"Feature {name} needs between {min_samples} and {MAX_VALUES} values.")
        signals[f"feature:{name}"] = _category_profile([_text(v, f"A value of {name}") for v in values])
    predictions, labels = samples.get("predictions"), samples.get("labels")
    if predictions is not None:
        signals["prediction"] = _prediction_profile(predictions, bins, min_samples)
    if labels is not None:
        if predictions is None or len(labels) != len(predictions):
            raise SampleError("True labels need predictions, one for each label.")
        signals["accuracy"] = {"kind": "accuracy", "n": len(labels),
                               "value": _sig(accuracy(predictions, labels))}
    if samples.get("embeddings") is not None:
        signals["embedding"] = _embedding_profile(samples["embeddings"], min_samples)
    if not signals:
        raise SampleError("Send at least one thing to monitor: a feature, predictions or embeddings.")
    return {"schema": SCHEMA, "bins": bins, "signals": signals}


def well_formed(profile: Any) -> bool:
    """Whether a stored profile has the shape ``build_profile`` makes."""
    if not isinstance(profile, dict) or profile.get("schema") != SCHEMA:
        return False
    signals = profile.get("signals")
    if not isinstance(signals, dict) or not signals or len(signals) > MAX_FEATURES + 3:
        return False
    for signal in signals.values():
        kind = signal.get("kind") if isinstance(signal, dict) else None
        if kind == "numeric":
            ok = len(signal.get("edges") or ()) == len(signal.get("counts") or ()) + 1 >= 3
        elif kind == "categorical":
            ok = len(signal.get("counts") or ()) == len(signal.get("categories") or ()) + 1
        elif kind == "embedding":
            ok = len(signal.get("centroid") or ()) == signal.get("dimension")
        else:
            ok = kind == "accuracy" and _number(signal.get("value"))
        if not ok:
            return False
    return True


# ---------------------------------------------------------------- comparison

def _what(signal: str) -> str:
    if signal.startswith("feature:"):
        return f"the feature '{signal[8:]}'"
    return {"prediction": "the predictions", "embedding": "the embeddings",
            "accuracy": "accuracy"}.get(signal, signal)


def _finding(signal: str, kind: str, severity: str, value: float, threshold: float, summary: str) -> dict:
    return {"key": f"{signal}:{kind}", "signal": signal, "kind": kind, "severity": severity,
            "value": round(value, 6), "threshold": threshold, "summary": summary}


def _scaled(value: float, threshold: float) -> str:
    return HIGH if value >= 2 * threshold else MEDIUM


def _compare_counts(signal: str, base: Mapping, counts: Sequence[int], cfg: Mapping) -> tuple[dict, list[dict]]:
    ref = base["counts"]
    what = _what(signal)
    metrics: dict[str, Any] = {"psi": population_stability_index(ref, counts),
                               "js": js_divergence(ref, counts),
                               "chi2": chi_squared_two_sample(ref, counts)}
    if base["kind"] == "numeric":
        metrics["ks"] = ks_two_sample_binned(ref, counts)
    found = []
    if metrics["psi"] >= cfg["psi_threshold"]:
        found.append(_finding(signal, "psi", _scaled(metrics["psi"], cfg["psi_threshold"]), metrics["psi"],
                              cfg["psi_threshold"],
                              f"The spread of {what} has moved from the baseline (population stability index "
                              f"{metrics['psi']:.2f}; the limit is {cfg['psi_threshold']:.2f})."))
    if metrics["js"] >= cfg["js_threshold"]:
        found.append(_finding(signal, "js", _scaled(metrics["js"], cfg["js_threshold"]), metrics["js"],
                              cfg["js_threshold"],
                              f"{what.capitalize()} differs from the baseline (Jensen-Shannon divergence "
                              f"{metrics['js']:.2f}; the limit is {cfg['js_threshold']:.2f})."))
    if metrics["chi2"]["p_value"] <= cfg["chi2_p_value_floor"]:
        found.append(_finding(signal, "chi2", MEDIUM, metrics["chi2"]["p_value"], cfg["chi2_p_value_floor"],
                              f"A chi-squared test finds {what} unlikely to have the baseline's spread "
                              f"(p-value {metrics['chi2']['p_value']:.3g}; the floor is {cfg['chi2_p_value_floor']})."))
    if "ks" in metrics and metrics["ks"]["p_value"] <= cfg["ks_p_value_floor"]:
        found.append(_finding(signal, "ks", MEDIUM, metrics["ks"]["p_value"], cfg["ks_p_value_floor"],
                              f"A Kolmogorov-Smirnov test finds {what} unlikely to have the baseline's spread "
                              f"(p-value {metrics['ks']['p_value']:.3g}; the floor is {cfg['ks_p_value_floor']})."))
    return metrics, found


def current_counts(base: Mapping, signal: str, samples: Mapping[str, Any]) -> list[int] | None:
    """The batch binned into the baseline's bins, or ``None`` when the batch
    does not carry this signal."""
    if signal.startswith("feature:"):
        name = signal[8:]
        if name in (samples.get("numeric") or {}):
            if base["kind"] != "numeric":
                raise SampleError(f"Feature {name} was categories in the baseline but is numbers here.")
            return _bin_counts(_numbers(samples["numeric"][name], f"Feature {name}", 1), base["edges"])
        if name in (samples.get("categorical") or {}):
            if base["kind"] != "categorical":
                raise SampleError(f"Feature {name} was numbers in the baseline but is categories here.")
            return _category_counts([_text(v, f"A value of {name}") for v in samples["categorical"][name]], base)
        return None
    if signal == "prediction" and samples.get("predictions") is not None:
        return _current_prediction_counts(samples["predictions"], base)
    return None


def compare(baseline: Mapping, samples: Mapping[str, Any], cfg: Mapping) -> dict:
    """A check batch against an approved baseline profile.

    Returns ``{"signals", "findings", "skipped", "compared"}``: the statistics
    for each signal compared, a finding for each that crosses its setting, and
    what was left out and why (a baseline signal the batch did not carry, or one
    with fewer than ``min_samples`` values). Raises :class:`SampleError` when
    the batch is malformed or shares nothing with the baseline."""
    check_size(samples)
    signals: dict[str, dict] = {}
    findings: list[dict] = []
    skipped: list[dict] = []
    for signal, base in baseline["signals"].items():
        kind = base["kind"]
        if kind == "accuracy":
            continue
        if kind == "embedding":
            rows = samples.get("embeddings")
            if rows is None:
                skipped.append({"signal": signal, "reason": "The batch did not include embeddings."})
                continue
            now = _embedding_profile(rows, cfg["min_samples"])
            if now["dimension"] != base["dimension"]:
                raise SampleError(f"The embeddings have {now['dimension']} numbers; the baseline has {base['dimension']}.")
            distance = cosine_distance(base["centroid"], now["centroid"])
            signals[signal] = {"n": now["n"], "cosine_distance": distance}
            if distance >= cfg["embedding_cosine_threshold"]:
                findings.append(_finding(
                    signal, "cosine", _scaled(distance, cfg["embedding_cosine_threshold"]), distance,
                    cfg["embedding_cosine_threshold"],
                    f"The average of the embeddings points a different way from the baseline "
                    f"(cosine distance {distance:.2f}; the limit is {cfg['embedding_cosine_threshold']:.2f})."))
            continue
        counts = current_counts(base, signal, samples)
        if counts is None:
            skipped.append({"signal": signal, "reason": "The batch did not include it."})
        elif sum(counts) < cfg["min_samples"]:
            skipped.append({"signal": signal, "reason": f"Fewer than {cfg['min_samples']} values."})
        else:
            metrics, found = _compare_counts(signal, base, counts, cfg)
            signals[signal] = {"n": sum(counts), **metrics}
            findings.extend(found)
    baseline_accuracy = baseline["signals"].get("accuracy")
    if baseline_accuracy is not None:
        if samples.get("labels") is None or samples.get("predictions") is None:
            skipped.append({"signal": "accuracy", "reason": "The batch did not include true labels."})
        elif len(samples["labels"]) != len(samples["predictions"]):
            raise SampleError("True labels need predictions, one for each label.")
        elif len(samples["labels"]) < cfg["min_samples"]:
            skipped.append({"signal": "accuracy", "reason": f"Fewer than {cfg['min_samples']} labels."})
        else:
            now = accuracy(samples["predictions"], samples["labels"])
            drop = baseline_accuracy["value"] - now
            signals["accuracy"] = {"n": len(samples["labels"]), "value": now, "baseline": baseline_accuracy["value"],
                                   "decay": drop}
            if drop >= cfg["accuracy_decay_threshold"]:
                findings.append(_finding(
                    "accuracy", "decay", _scaled(drop, cfg["accuracy_decay_threshold"]), drop,
                    cfg["accuracy_decay_threshold"],
                    f"Accuracy fell from {baseline_accuracy['value']:.0%} to {now:.0%} "
                    f"(the limit is a drop of {cfg['accuracy_decay_threshold']:.0%})."))
    if not signals:
        raise SampleError("Nothing in this batch matches the baseline. Send the same features, "
                          "predictions or embeddings the baseline was made from.")
    return {"signals": signals, "findings": findings, "skipped": skipped, "compared": sorted(signals)}


__all__ = [
    "HIGH", "LOW", "MEDIUM", "SampleError", "accuracy", "build_profile", "check_size", "chi_square_survival",
    "chi_squared_two_sample", "compare", "cosine_distance", "js_divergence", "ks_survival",
    "ks_two_sample_binned", "population_stability_index", "settings", "well_formed",
]
