"""Statistical drift: each statistic against values worked out by hand, and
profiles that are bounded and hold no sample."""
from __future__ import annotations

import json
import math
import random

import pytest

from maverick import model_drift as md

CFG = md.settings()


# ---------------------------------------------------------------- statistics

def test_psi_matches_the_worked_example_and_is_zero_for_the_same_spread():
    # (0.1-0.25)ln(0.4) + (0.2-0.25)ln(0.8) + (0.3-0.25)ln(1.2) + (0.4-0.25)ln(1.6)
    # = 0.137444 + 0.011157 + 0.009116 + 0.070501 = 0.228218
    assert md.population_stability_index([25, 25, 25, 25], [10, 20, 30, 40]) == pytest.approx(0.228218, abs=1e-5)
    assert md.population_stability_index([5, 9, 2], [50, 90, 20]) == pytest.approx(0.0, abs=1e-12)


def test_psi_is_symmetric_and_an_empty_bin_does_not_make_it_infinite():
    left, right = [40, 30, 20, 10], [10, 20, 30, 40]
    assert md.population_stability_index(left, right) == pytest.approx(md.population_stability_index(right, left))
    assert math.isfinite(md.population_stability_index([50, 50, 0], [50, 0, 50]))


def test_js_divergence_in_bits():
    assert md.js_divergence([1, 0], [0, 1]) == pytest.approx(1.0)
    assert md.js_divergence([3, 7], [30, 70]) == pytest.approx(0.0, abs=1e-12)
    # P = (0.5, 0.5), Q = (0.9, 0.1), M = (0.7, 0.3)
    expected = 0.5 * (0.5 * math.log2(0.5 / 0.7) + 0.5 * math.log2(0.5 / 0.3)) \
        + 0.5 * (0.9 * math.log2(0.9 / 0.7) + 0.1 * math.log2(0.1 / 0.3))
    assert md.js_divergence([5, 5], [9, 1]) == pytest.approx(expected)
    assert md.js_divergence([5, 5], [9, 1]) == pytest.approx(md.js_divergence([9, 1], [5, 5]))
    assert expected == pytest.approx(0.1468, abs=1e-4)


def test_chi_square_tail_matches_the_textbook_critical_values():
    assert md.chi_square_survival(3.841459, 1) == pytest.approx(0.05, abs=1e-5)
    assert md.chi_square_survival(5.991465, 2) == pytest.approx(0.05, abs=1e-5)
    assert md.chi_square_survival(9.487729, 4) == pytest.approx(0.05, abs=1e-5)
    assert md.chi_square_survival(18.307038, 10) == pytest.approx(0.05, abs=1e-5)
    assert md.chi_square_survival(6.634897, 1) == pytest.approx(0.01, abs=1e-5)
    assert md.chi_square_survival(0.0, 3) == 1.0
    # two degrees of freedom has a closed form, exp(-x/2), in both branches of the method
    for x in (0.5, 2.0, 7.5, 30.0):
        assert md.chi_square_survival(x, 2) == pytest.approx(math.exp(-x / 2), rel=1e-9)


def test_chi_squared_two_sample_by_hand():
    # equal totals of 60: (10-20)^2/30 + 0 + (30-20)^2/50 = 3.3333 + 2 = 5.3333 on 2 degrees of freedom
    result = md.chi_squared_two_sample([10, 20, 30], [20, 20, 20])
    assert result["statistic"] == pytest.approx(16 / 3)
    assert result["dof"] == 2
    assert result["p_value"] == pytest.approx(math.exp(-8 / 3), rel=1e-9)
    same = md.chi_squared_two_sample([10, 20, 30], [20, 40, 60])
    assert same["statistic"] == pytest.approx(0.0, abs=1e-12) and same["p_value"] == pytest.approx(1.0)


def test_chi_squared_ignores_bins_empty_on_both_sides():
    assert md.chi_squared_two_sample([10, 0, 20], [20, 0, 10])["dof"] == 1


def test_ks_tail_matches_the_textbook_critical_value():
    assert md.ks_survival(1.358) == pytest.approx(0.05, abs=1e-3)
    assert md.ks_survival(1.628) == pytest.approx(0.01, abs=5e-4)
    assert md.ks_survival(0.0) == 1.0
    assert md.ks_survival(0.1) == 1.0  # too small to tell apart


def test_ks_two_sample_binned_by_hand():
    result = md.ks_two_sample_binned([50, 50], [80, 20])
    assert result["statistic"] == pytest.approx(0.3)
    lam = (math.sqrt(50) + 0.12 + 0.11 / math.sqrt(50)) * 0.3
    expected = 2 * (math.exp(-2 * lam**2) - math.exp(-8 * lam**2))
    assert result["p_value"] == pytest.approx(expected, rel=1e-6)
    assert result["p_value"] < 0.001
    same = md.ks_two_sample_binned([10, 30, 60], [100, 300, 600])
    assert same["statistic"] == pytest.approx(0.0, abs=1e-12) and same["p_value"] == 1.0


def test_cosine_distance():
    assert md.cosine_distance([1, 0], [0, 1]) == pytest.approx(1.0)
    assert md.cosine_distance([1, 0], [1, 1]) == pytest.approx(1 - 1 / math.sqrt(2))
    assert md.cosine_distance([2, 2], [1, 1]) == pytest.approx(0.0, abs=1e-12)
    assert md.cosine_distance([1, 0], [-1, 0]) == pytest.approx(2.0)
    assert md.cosine_distance([0, 0], [0, 0]) == 0.0 and md.cosine_distance([0, 0], [1, 0]) == 1.0


def test_accuracy_compares_numbers_by_value_and_text_by_trimmed_text():
    assert md.accuracy([1, 0, 1, 1], [1.0, 0, 0, 1]) == pytest.approx(0.75)
    assert md.accuracy(["cat", " dog "], ["cat", "dog"]) == 1.0
    with pytest.raises(md.SampleError):
        md.accuracy([1], [1, 0])


@pytest.mark.parametrize("bad", [[-1, 5], [0, 0]])
def test_counts_must_be_usable(bad):
    with pytest.raises(md.SampleError):
        md.population_stability_index(bad, [1, 1])


# ------------------------------------------------------------------ profiles

def _values(seed, n=400, mean=50.0, spread=10.0):
    rng = random.Random(seed)
    return [round(rng.gauss(mean, spread), 3) for _ in range(n)]


def test_a_profile_is_bounded_and_holds_no_value_from_the_batch():
    ages = _values(1)
    colour = ["red"] * 200 + ["blue"] * 150 + ["unique-secret-value"] + ["rare-a"] * 2 + ["green"] * 47
    batch = {"numeric": {"age": ages}, "categorical": {"colour": colour},
             "predictions": [round(random.Random(2).random(), 6) for _ in range(400)]}
    profile = md.build_profile(batch, bins=10, min_samples=30)
    text = json.dumps(profile)
    assert "unique-secret-value" not in text and "rare-a" not in text
    assert profile["signals"]["feature:colour"]["categories"] == ["red", "blue", "green"]
    assert sum(profile["signals"]["feature:colour"]["counts"]) == 400  # the rare ones sit under "other"
    age = profile["signals"]["feature:age"]
    assert len(age["counts"]) == 10 and len(age["edges"]) == 11 and sum(age["counts"]) == 400
    for value in ages:
        assert str(value) not in {str(e) for e in age["edges"]}
    assert len(text) < 3000
    assert md.well_formed(profile)


def test_edges_follow_the_spread_not_the_extremes():
    values = [float(i) for i in range(100)] + [10_000.0]
    profile = md.build_profile({"numeric": {"x": values}}, bins=10, min_samples=30)
    edges = profile["signals"]["feature:x"]["edges"]
    assert edges[-1] < 200 and 10_000.0 not in edges


def test_a_class_prediction_is_counted_by_class_and_accuracy_needs_labels():
    predictions = [0, 1] * 100
    labels = [0, 1] * 90 + [1, 0] * 10
    profile = md.build_profile({"predictions": predictions, "labels": labels}, bins=10, min_samples=30)
    assert profile["signals"]["prediction"]["kind"] == "categorical"
    assert profile["signals"]["prediction"]["categories"] == ["0", "1"]
    assert profile["signals"]["accuracy"]["value"] == pytest.approx(0.9)


def test_an_embedding_profile_keeps_only_the_centroid():
    rows = [[1.0, 2.0, 3.0]] * 20 + [[3.0, 2.0, 1.0]] * 20
    profile = md.build_profile({"embeddings": rows}, bins=10, min_samples=30)
    assert profile["signals"]["embedding"] == {"kind": "embedding", "n": 40, "dimension": 3,
                                              "centroid": [2.0, 2.0, 2.0]}


@pytest.mark.parametrize("batch, fragment", [
    ({}, "at least one"),
    ({"numeric": {"x": [1.0] * 5}}, "at least 30"),
    ({"numeric": {"x": [1.0] * 29 + [float("nan")]}}, "finite"),
    ({"numeric": {"x": [1.0] * 29 + [float("inf")]}}, "finite"),
    ({"numeric": {"x": ["a"] * 40}}, "finite"),
    ({"numeric": {"bad/name": [1.0] * 40}}, "feature name"),
    ({"numeric": {"x": [1.0] * 40}, "categorical": {"x": ["a"] * 40}}, "not both"),
    ({"numeric": {f"f{i}": [1.0] * 40 for i in range(17)}}, "at most 16 features"),
    ({"numeric": {"x": [1.0] * 5001}}, "at most 5000"),
    ({"labels": [1] * 40}, "need predictions"),
    ({"predictions": [1, 0] * 20, "labels": [1] * 39}, "one for each"),
    ({"embeddings": [[1.0]] * 201}, "at most 200"),
    ({"embeddings": [[1.0, 2.0]] * 39 + [[1.0]]}, "same number"),
    ({"embeddings": [[1.0] * 257] * 40}, "between 1 and 256"),
    ({"numeric": {f"f{i}": [1.0] * 2000 for i in range(11)}}, "values in all"),
])
def test_a_bad_baseline_batch_is_refused_with_a_plain_message(batch, fragment):
    with pytest.raises(md.SampleError, match=fragment):
        md.build_profile(batch, bins=10, min_samples=30)


# ---------------------------------------------------------------- comparison

def _base(**extra):
    batch = {"numeric": {"age": _values(1)}, "categorical": {"colour": ["red"] * 200 + ["blue"] * 200}}
    batch.update(extra)
    return md.build_profile(batch, bins=10, min_samples=30)


def test_the_same_spread_makes_no_finding():
    result = md.compare(_base(), {"numeric": {"age": _values(7)}, "categorical": {"colour": ["red", "blue"] * 200}}, CFG)
    assert result["findings"] == [] and result["skipped"] == []
    assert set(result["signals"]) == {"feature:age", "feature:colour"}
    assert result["signals"]["feature:age"]["psi"] < 0.1


def test_a_shifted_feature_crosses_every_numeric_threshold():
    result = md.compare(_base(), {"numeric": {"age": _values(7, mean=65.0)}}, CFG)
    assert {f["kind"] for f in result["findings"]} == {"psi", "js", "chi2", "ks"}
    assert {f["key"] for f in result["findings"]} == {f"feature:age:{k}" for k in ("psi", "js", "chi2", "ks")}
    assert all(f["summary"] and "'age'" in f["summary"] for f in result["findings"])


def test_each_threshold_alone_decides_its_finding():
    shifted = {"numeric": {"age": _values(7, mean=58.0)}}
    base = _base()
    none = {**CFG, "psi_threshold": 10.0, "js_threshold": 1.0, "chi2_p_value_floor": 0.0, "ks_p_value_floor": 0.0}
    assert md.compare(base, shifted, none)["findings"] == []
    for name, expected in (("psi_threshold", "psi"), ("js_threshold", "js"),
                           ("chi2_p_value_floor", "chi2"), ("ks_p_value_floor", "ks")):
        loose = {**none, name: 0.5 if name.endswith("floor") else 0.001}  # a floor of 0.5 flags any p-value up to 0.5
        assert [f["kind"] for f in md.compare(base, shifted, loose)["findings"]] == [expected]


def test_a_category_mix_that_moves_is_found_and_unseen_values_go_to_other():
    now = {"categorical": {"colour": ["red"] * 350 + ["blue"] * 20 + ["never-seen"] * 30}}
    result = md.compare(_base(), now, CFG)
    kinds = {f["kind"] for f in result["findings"]}
    assert {"psi", "js", "chi2"} <= kinds and "ks" not in kinds


def test_embedding_drift_uses_the_centroid_cosine_distance():
    base = md.build_profile({"embeddings": [[1.0, 0.0]] * 40}, bins=10, min_samples=30)
    quiet = md.compare(base, {"embeddings": [[1.0, 0.05]] * 40}, CFG)
    assert quiet["findings"] == [] and quiet["signals"]["embedding"]["cosine_distance"] < 0.01
    moved = md.compare(base, {"embeddings": [[1.0, 1.0]] * 40}, CFG)
    (finding,) = moved["findings"]
    assert finding["kind"] == "cosine" and finding["value"] == pytest.approx(1 - 1 / math.sqrt(2), abs=1e-5)
    with pytest.raises(md.SampleError, match="baseline has 2"):
        md.compare(base, {"embeddings": [[1.0, 1.0, 1.0]] * 40}, CFG)


def test_accuracy_decay_is_a_drop_from_the_baseline():
    base = md.build_profile({"predictions": [0, 1] * 100, "labels": [0, 1] * 95 + [1, 0] * 5}, bins=10, min_samples=30)
    ok = md.compare(base, {"predictions": [0, 1] * 50, "labels": [0, 1] * 48 + [1, 0] * 2}, CFG)
    assert ok["findings"] == [] and ok["signals"]["accuracy"]["value"] == pytest.approx(0.96)
    worse = md.compare(base, {"predictions": [0, 1] * 50, "labels": [0, 1] * 40 + [1, 0] * 10}, CFG)
    (finding,) = [f for f in worse["findings"] if f["kind"] == "decay"]
    assert finding["value"] == pytest.approx(0.95 - 0.8) and finding["severity"] == "high"
    assert "95%" in finding["summary"] and "80%" in finding["summary"]


def test_a_signal_the_batch_lacks_or_a_series_too_short_is_skipped_not_judged():
    result = md.compare(_base(), {"numeric": {"age": _values(7)}, "categorical": {"colour": ["red"] * 5}}, CFG)
    assert [s["signal"] for s in result["skipped"]] == ["feature:colour"]
    assert result["findings"] == []


def test_a_batch_with_nothing_in_common_is_refused():
    with pytest.raises(md.SampleError, match="Nothing in this batch"):
        md.compare(_base(), {"numeric": {"height": _values(3)}}, CFG)


def test_severity_is_high_at_twice_the_limit():
    result = md.compare(_base(), {"numeric": {"age": _values(7, mean=90.0)}}, CFG)
    by_kind = {f["kind"]: f["severity"] for f in result["findings"]}
    assert by_kind["psi"] == "high" and by_kind["chi2"] == "medium"


def test_settings_default_and_clamp(tmp_path, monkeypatch):
    from maverick import config

    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    config.reset_config_cache()
    assert md.settings() == {"enable": True, "bins": 10, "min_samples": 30, "psi_threshold": 0.2, "js_threshold": 0.1,
                             "ks_p_value_floor": 0.01, "chi2_p_value_floor": 0.01,
                             "embedding_cosine_threshold": 0.1, "accuracy_decay_threshold": 0.05,
                             "batches_per_minute": 20}
    (tmp_path / "config.toml").write_text('[model_drift]\npsi_threshold = 99999\nbins = "x"\nmin_samples = 2\n'
                                          'enable = false\nbatches_per_minute = 2.5\n', encoding="utf-8")
    config.reset_config_cache()
    cfg = md.settings()
    assert cfg["psi_threshold"] == 10.0 and cfg["bins"] == 10 and cfg["min_samples"] == 10
    assert cfg["enable"] is False and cfg["batches_per_minute"] == 20
    config.reset_config_cache()
