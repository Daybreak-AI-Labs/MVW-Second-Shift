"""OTLP endpoint/headers config + OTel GenAI semconv for tool spans.

Extends the existing opt-in OTel layer (test_genai_semconv.py covers the LLM
helpers). Here we assert:

  - ``MAVERICK_OTEL_HEADERS`` is parsed from the env into the exporter, and the
    no-header default path is unchanged;
  - enabling stays opt-in / no-op by default (otel off);
  - tool spans get the standard ``execute_tool`` gen_ai.* attributes.

Hermetic: no network, no live collector. Tests that need a real tracer skip
gracefully when opentelemetry isn't importable, like the repo's other
otel-dependent tests.
"""
from __future__ import annotations

import asyncio
import contextlib
import sys
import types

import pytest
from maverick import observability as obs


@pytest.fixture(autouse=True)
def _reset_obs_state(monkeypatch):
    """Each test starts from a clean, otel-off module state."""
    monkeypatch.delenv("MAVERICK_OTEL_EXPORTER", raising=False)
    monkeypatch.delenv("MAVERICK_OTEL_ENDPOINT", raising=False)
    monkeypatch.delenv("MAVERICK_OTEL_HEADERS", raising=False)
    monkeypatch.delenv("MAVERICK_OTEL_METRICS", raising=False)
    monkeypatch.delenv("MAVERICK_PROMETHEUS_PORT", raising=False)
    monkeypatch.setattr(obs, "_initialized", False, raising=False)
    monkeypatch.setattr(obs, "_tracer", None, raising=False)
    monkeypatch.setattr(obs, "_metrics", {}, raising=False)
    monkeypatch.setattr(obs, "_otel_instruments", {}, raising=False)


def test_headers_unset_is_empty(monkeypatch):
    assert obs._otlp_headers() == {}


def test_headers_blank_is_empty(monkeypatch):
    monkeypatch.setenv("MAVERICK_OTEL_HEADERS", "   ")
    assert obs._otlp_headers() == {}


def test_headers_parsed_from_env(monkeypatch):
    monkeypatch.setenv(
        "MAVERICK_OTEL_HEADERS", "x-honeycomb-team=abc123, dd-api-key=xyz"
    )
    assert obs._otlp_headers() == {
        "x-honeycomb-team": "abc123",
        "dd-api-key": "xyz",
    }


def test_headers_skip_malformed_pairs(monkeypatch):
    # A bare token with no '=' is skipped, not crashed on.
    monkeypatch.setenv("MAVERICK_OTEL_HEADERS", "garbage,authorization=Bearer t")
    assert obs._otlp_headers() == {"authorization": "Bearer t"}


def test_trace_span_is_noop_when_disabled(monkeypatch):
    # No tracer is created, span yields None, attributes don't raise.
    with obs.trace_span("chat test-model", attributes={"gen_ai.system": "x"}) as s:
        assert s is None
    assert obs._tracer is None


def test_headers_passed_to_exporter_when_enabled(monkeypatch):
    pytest.importorskip("opentelemetry.exporter.otlp.proto.http.trace_exporter")
    from opentelemetry.exporter.otlp.proto.http import trace_exporter as te

    captured: dict[str, object] = {}

    class _SpyExporter:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def export(self, spans):  # pragma: no cover - never called in test
            return None

        def shutdown(self):  # pragma: no cover
            return None

    monkeypatch.setattr(te, "OTLPSpanExporter", _SpyExporter)
    monkeypatch.setenv("MAVERICK_OTEL_EXPORTER", "otlp")
    monkeypatch.setenv("MAVERICK_OTEL_ENDPOINT", "https://collector.example/v1/traces")
    monkeypatch.setenv("MAVERICK_OTEL_HEADERS", "x-api-key=secret")

    obs._initialize()

    assert captured.get("endpoint") == "https://collector.example/v1/traces"
    assert captured.get("headers") == {"x-api-key": "secret"}
    assert obs._tracer is not None


def test_no_headers_kwarg_omitted_when_unset(monkeypatch):
    pytest.importorskip("opentelemetry.exporter.otlp.proto.http.trace_exporter")
    from opentelemetry.exporter.otlp.proto.http import trace_exporter as te

    captured: dict[str, object] = {}

    class _SpyExporter:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def export(self, spans):  # pragma: no cover
            return None

        def shutdown(self):  # pragma: no cover
            return None

    monkeypatch.setattr(te, "OTLPSpanExporter", _SpyExporter)
    monkeypatch.setenv("MAVERICK_OTEL_EXPORTER", "otlp")

    obs._initialize()

    # default path: no headers kwarg, so the exporter keeps its own default.
    assert "headers" not in captured


class _FakeInstrument:
    """Counter stand-in: ``add`` records the way the OTel counter does."""

    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.points = []

    def add(self, amount, attributes=None, context=None):
        self.points.append((amount, dict(attributes or {})))


class _FakeHistogram(_FakeInstrument):
    """Histogram stand-in: ``record`` is the histogram's entry point."""

    def record(self, amount, attributes=None, context=None):
        self.points.append((amount, dict(attributes or {})))


@pytest.fixture
def fake_otlp_metrics(monkeypatch):
    """Stand-ins for the OTLP metric exporter and the metrics SDK.

    The venvs do not install opentelemetry-sdk, so these modules are injected
    and the real SDK path is covered by the importorskip tests below.
    """
    built: dict = {}

    class _Meter:
        def create_counter(self, name, unit="", description=""):
            instrument = _FakeInstrument(name, description)
            built[name] = instrument
            return instrument

        def create_histogram(self, name, unit="", description="", **_kwargs):
            instrument = _FakeHistogram(name, description)
            built[name] = instrument
            return instrument

    class _MeterProvider:
        def __init__(self, resource=None, metric_readers=()):
            built["readers"] = list(metric_readers)

        def get_meter(self, name, *_args, **_kwargs):
            built["meter"] = name
            return _Meter()

    class _Exporter:
        def __init__(self, **kwargs):
            built["exporter_kwargs"] = kwargs

    exporter_mod = types.ModuleType("opentelemetry.exporter.otlp.proto.http.metric_exporter")
    exporter_mod.OTLPMetricExporter = _Exporter
    sdk_mod = types.ModuleType("opentelemetry.sdk.metrics")
    sdk_mod.MeterProvider = _MeterProvider
    export_mod = types.ModuleType("opentelemetry.sdk.metrics.export")
    export_mod.PeriodicExportingMetricReader = lambda exporter, **_kw: ("reader", exporter)
    for name, module in (
        ("opentelemetry.exporter.otlp.proto.http.metric_exporter", exporter_mod),
        ("opentelemetry.sdk.metrics", sdk_mod),
        ("opentelemetry.sdk.metrics.export", export_mod),
    ):
        monkeypatch.setitem(sys.modules, name, module)
    return built


def test_metric_names_and_kinds_are_pinned():
    """Dashboards and alerts key on these names; OTel mirrors them exactly."""
    assert [(kind, name, labels) for kind, _key, name, _doc, labels in obs._METRIC_SPECS] == [
        ("counter", "maverick_llm_calls_total", ("provider", "model")),
        ("histogram", "maverick_llm_latency_seconds", ("provider", "model")),
        ("counter", "maverick_llm_tokens_total", ("provider", "model", "direction")),
        ("counter", "maverick_llm_cache_tokens_total", ("provider", "model", "kind")),
        ("counter", "maverick_tool_calls_total", ("tool", "status")),
        ("counter", "maverick_budget_dollars_spent", ()),
        ("counter", "maverick_tool_latency_budget_exceeded_total", ("tool",)),
    ]
    keys = [key for _kind, key, _name, _doc, _labels in obs._METRIC_SPECS]
    assert len(keys) == len(set(keys))


@pytest.mark.parametrize(
    ("setting", "expected"),
    [(None, False), ("", False), ("0", False), ("false", False), ("off", False),
     ("1", True), ("true", True), ("Yes", True), ("on", True)],
)
def test_otlp_metrics_knob_is_on_only_for_a_true_value(monkeypatch, setting, expected):
    # [observability] otlp_metrics = false reaches the module as "0", which a
    # plain bool() would read as on.
    monkeypatch.setattr(obs, "_setting", lambda env_name, key: setting)
    assert obs._otlp_metrics_enabled() is expected


@pytest.mark.parametrize(
    ("traces", "metrics"),
    [
        ("http://localhost:4318/v1/traces", "http://localhost:4318/v1/metrics"),
        ("https://collector.example/base/v1/traces", "https://collector.example/base/v1/metrics"),
        # No derivable metrics path: stay off rather than post to a guessed URL.
        ("https://collector.example/custom", None),
        ("https://collector.example/v1/traces/", None),
    ],
)
def test_metrics_url_replaces_only_the_signal_path(traces, metrics):
    assert obs._otlp_metrics_endpoint(traces) == metrics


def test_metrics_exporter_uses_the_span_endpoint_and_headers(fake_otlp_metrics):
    obs._initialize_otlp_metrics(
        "https://collector.example/v1/traces", {"x-api-key": "secret"}, None)
    assert fake_otlp_metrics["exporter_kwargs"] == {
        "endpoint": "https://collector.example/v1/metrics",
        "headers": {"x-api-key": "secret"},
    }


def test_metrics_exporter_omits_headers_kwarg_when_unset(fake_otlp_metrics):
    obs._initialize_otlp_metrics("http://localhost:4318/v1/traces", {}, None)
    assert fake_otlp_metrics["exporter_kwargs"] == {
        "endpoint": "http://localhost:4318/v1/metrics"}


def test_every_recorded_metric_gets_an_instrument_of_the_same_name_and_kind(
        fake_otlp_metrics):
    obs._initialize_otlp_metrics("http://localhost:4318/v1/traces", {}, None)
    assert set(obs._otel_instruments) == {key for _kind, key, *_ in obs._METRIC_SPECS}
    for kind, key, name, doc, _labels in obs._METRIC_SPECS:
        recorded_kind, instrument = obs._otel_instruments[key]
        assert recorded_kind == kind
        assert instrument.name == name
        assert instrument.description == doc
        assert isinstance(instrument, _FakeHistogram) == (kind == "histogram")


def test_metrics_knob_without_the_exporter_stays_off_and_says_why(monkeypatch, caplog):
    monkeypatch.setenv("MAVERICK_OTEL_METRICS", "1")
    obs._initialize()
    assert obs._otel_instruments == {}
    assert "MAVERICK_OTEL_METRICS" in caplog.text


def test_metrics_knob_off_loads_no_metrics_sdk(monkeypatch, caplog):
    """The default path never imports the OTel metrics SDK."""
    pytest.importorskip("opentelemetry.sdk.trace")
    for name in ("opentelemetry.sdk.metrics",
                 "opentelemetry.exporter.otlp.proto.http.metric_exporter"):
        monkeypatch.setitem(sys.modules, name, None)  # any import now raises ImportError
    monkeypatch.setenv("MAVERICK_OTEL_EXPORTER", "otlp")
    monkeypatch.setenv("MAVERICK_OTEL_ENDPOINT", "http://127.0.0.1:9/v1/traces")
    obs._initialize()
    assert obs._tracer is not None
    assert obs._otel_instruments == {}
    assert "OTLP metrics" not in caplog.text


class _SDKSpan:
    """What the span keeps: attributes, events and the status."""

    def __init__(self):
        self.attributes = {}
        self.events = []
        self.status = None

    def set_attribute(self, key, value):
        self.attributes[key] = value

    def set_status(self, status, description=None):
        self.status = (status, description)


class _SDKTracer:
    """Stand-in for the SDK tracer, with its default exception handling.

    Unless a caller turns them off, ``start_as_current_span`` records the exception
    message as an event and sets an ERROR status carrying the message, as the SDK does.
    """

    def __init__(self):
        self.spans = []
        self.options = []

    @contextlib.contextmanager
    def start_as_current_span(self, name, record_exception=True,
                              set_status_on_exception=True, **_kwargs):
        span = _SDKSpan()
        self.spans.append((name, span))
        self.options.append((record_exception, set_status_on_exception))
        try:
            yield span
        except BaseException as error:
            if record_exception:
                span.events.append(("exception", str(error)))
            if set_status_on_exception:
                span.status = ("ERROR", str(error))
            raise


@pytest.fixture
def sdk_tracer(monkeypatch):
    tracer = _SDKTracer()
    monkeypatch.setattr(obs, "_initialized", True)
    monkeypatch.setattr(obs, "_tracer", tracer)
    monkeypatch.setattr(obs, "_trace_api", types.SimpleNamespace(
        StatusCode=types.SimpleNamespace(ERROR="ERROR")))
    monkeypatch.setattr(obs, "_sentry", None)
    return tracer


def test_failed_span_records_no_message_and_names_only_the_type(sdk_tracer):
    secret = "sk-live-do-not-export"  # pragma: allowlist secret
    with pytest.raises(RuntimeError):
        with obs.trace_span("tool.run", attributes={"tool.name": "fetch"}):
            raise RuntimeError(f"upstream rejected {secret}")
    ((name, span),) = sdk_tracer.spans
    assert name == "tool.run"
    assert span.events == []
    assert span.status == ("ERROR", "RuntimeError")
    assert span.attributes["error.type"] == "RuntimeError"
    assert secret not in repr((span.events, span.status, span.attributes))


def test_every_trace_span_opens_with_sdk_exception_recording_off(sdk_tracer):
    # Tool, provider and agent spans all come through trace_span().
    with obs.trace_span("provider.call"):
        pass
    with pytest.raises(ValueError):
        with obs.trace_span("agent.turn"):
            raise ValueError("boom")
    assert sdk_tracer.options == [(False, False), (False, False)]


def test_successful_span_gets_no_error_status(sdk_tracer):
    with obs.trace_span("agent.turn") as span:
        assert span is not None
    ((_, span),) = sdk_tracer.spans
    assert span.status is None
    assert "error.type" not in span.attributes


@pytest.mark.parametrize("error", [asyncio.CancelledError("stop"), GeneratorExit()])
def test_cancelled_span_is_not_marked_as_an_error(sdk_tracer, error):
    # As the SDK does, only an Exception makes a span an error; a cancellation or a
    # GeneratorExit propagates unchanged and leaves the status unset.
    with pytest.raises(type(error)):
        with obs.trace_span("tool.run"):
            raise error
    ((_, span),) = sdk_tracer.spans
    assert span.status is None


def test_real_sdk_failed_span_exports_type_and_no_message(monkeypatch):
    pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry import trace as trace_api
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(obs, "_initialized", True)
    monkeypatch.setattr(obs, "_sentry", None)
    monkeypatch.setattr(obs, "_tracer", provider.get_tracer("test"))
    monkeypatch.setattr(obs, "_trace_api", trace_api)
    with pytest.raises(ValueError):
        with obs.trace_span("tool.run"):
            raise ValueError("token sk-live-do-not-export")
    (span,) = exporter.get_finished_spans()
    assert list(span.events) == []
    assert span.status.status_code == trace_api.StatusCode.ERROR
    assert span.status.description == "ValueError"
    assert "sk-live-do-not-export" not in repr(span.attributes)


_OFF_VALUES = [False, "false", "0", "off", "no", ""]
_ON_VALUES = [True, "1", "true", "yes", "on"]


@pytest.fixture
def no_config(monkeypatch):
    """No configuration file and no DSN in the environment; each test sets one switch."""
    import maverick.config as config_mod

    monkeypatch.setattr(config_mod, "load_config", dict)
    monkeypatch.delenv("MAVERICK_SENTRY_DSN", raising=False)
    return config_mod


def _config_switch(monkeypatch, config_mod, key, value):
    monkeypatch.setattr(config_mod, "load_config", lambda: {"observability": {key: value}})


@pytest.mark.parametrize("value", _OFF_VALUES)
def test_off_spellings_are_off_and_blank_or_off(value):
    assert obs.switch_is_on(value) is False
    assert obs.setting_is_blank_or_off(value) is True


@pytest.mark.parametrize("value", _ON_VALUES + ["  ON  ", "otlp"])
def test_on_spellings_are_on_and_not_blank(value):
    assert obs.switch_is_on(value, extra_on=frozenset({"otlp"})) is True
    assert obs.setting_is_blank_or_off(value) is False


@pytest.mark.parametrize("value", ["console", "otlp/http"])
def test_unlisted_text_is_off(value):
    # Only the documented exporter value (and the on-words) turn a switch on.
    assert obs.switch_is_on(value, extra_on=frozenset({"otlp"})) is False


# (env var, [observability] key, reader, values that turn it on)
_SWITCHES = [
    ("MAVERICK_OTEL_METRICS", "otlp_metrics", "_otlp_metrics_enabled", _ON_VALUES),
    ("MAVERICK_OTEL_EXPORTER", "otel_exporter", "_otel_enabled", ["otlp", "OTLP", True, "1"]),
]
_SWITCH_OFF = [(env, key, fn, value) for env, key, fn, _on in _SWITCHES for value in _OFF_VALUES]
_SWITCH_ON = [(env, key, fn, value) for env, key, fn, on in _SWITCHES for value in on]


@pytest.mark.parametrize(("env", "key", "fn", "value"), _SWITCH_OFF)
def test_switch_is_off_from_config(no_config, monkeypatch, env, key, fn, value):
    _config_switch(monkeypatch, no_config, key, value)
    assert getattr(obs, fn)() is False


@pytest.mark.parametrize(("env", "key", "fn", "value"), _SWITCH_ON)
def test_switch_is_on_from_config(no_config, monkeypatch, env, key, fn, value):
    _config_switch(monkeypatch, no_config, key, value)
    assert getattr(obs, fn)() is True


@pytest.mark.parametrize(("env", "key", "fn"), [(e, k, f) for e, k, f, _on in _SWITCHES])
@pytest.mark.parametrize("value", ["false", "0", "off", "no"])
def test_switch_is_off_from_env(no_config, monkeypatch, env, key, fn, value):
    # A blank env var is unset and falls through to config, so it is not listed here.
    monkeypatch.setenv(env, value)
    assert getattr(obs, fn)() is False


@pytest.mark.parametrize(("env", "key", "fn", "value"), _SWITCH_ON)
def test_switch_is_on_from_env(no_config, monkeypatch, env, key, fn, value):
    monkeypatch.setenv(env, str(value))
    assert getattr(obs, fn)() is True


@pytest.mark.parametrize(("env", "key", "fn", "value"), _SWITCH_ON)
def test_env_switch_wins_over_config_both_ways(no_config, monkeypatch, env, key, fn, value):
    _config_switch(monkeypatch, no_config, key, value)
    monkeypatch.setenv(env, "false")
    assert getattr(obs, fn)() is False
    _config_switch(monkeypatch, no_config, key, False)
    monkeypatch.setenv(env, str(value))
    assert getattr(obs, fn)() is True


@pytest.mark.parametrize("value", _OFF_VALUES)
def test_prometheus_port_off_values_do_not_publish(no_config, monkeypatch, value):
    # A config false arrives as "0": without this, the exporter would bind a random port.
    _config_switch(monkeypatch, no_config, "prometheus_port", value)
    assert obs._prometheus_enabled() is False


@pytest.mark.parametrize("value", [9100, "9100"])
def test_prometheus_port_on_from_config(no_config, monkeypatch, value):
    _config_switch(monkeypatch, no_config, "prometheus_port", value)
    assert obs._prometheus_enabled() is True


@pytest.mark.parametrize("value", ["0", "off", "false", "no"])
def test_prometheus_port_off_from_env(no_config, monkeypatch, value):
    monkeypatch.setenv("MAVERICK_PROMETHEUS_PORT", value)
    assert obs._prometheus_enabled() is False


def _fake_prometheus(monkeypatch):
    started = []
    fake = types.ModuleType("prometheus_client")

    class _Metric:
        def __init__(self, *_args, **_kwargs):
            pass

    fake.Counter = _Metric
    fake.Histogram = _Metric
    fake.start_http_server = lambda port, addr=None: started.append(port)
    monkeypatch.setitem(sys.modules, "prometheus_client", fake)
    return started


def test_false_prometheus_port_never_starts_the_server(no_config, monkeypatch):
    started = _fake_prometheus(monkeypatch)
    _config_switch(monkeypatch, no_config, "prometheus_port", False)
    obs._initialize()
    assert started == []


def test_numeric_prometheus_port_starts_the_server(no_config, monkeypatch):
    # Positive control for the test above: a real port does start the server.
    started = _fake_prometheus(monkeypatch)
    _config_switch(monkeypatch, no_config, "prometheus_port", 9100)
    obs._initialize()
    assert started == [9100]


@pytest.mark.parametrize("value", [False, "false", "0", "off", "no", ""])
def test_sentry_dsn_off_values_mean_no_sentry(no_config, monkeypatch, value):
    _config_switch(monkeypatch, no_config, "sentry_dsn", value)
    assert obs._sentry_dsn() == ""
    assert obs._sentry_enabled() is False


@pytest.mark.parametrize("value", ["false", "0", "off", "no"])
def test_sentry_dsn_off_words_from_env_mean_no_sentry(no_config, monkeypatch, value):
    monkeypatch.setenv("MAVERICK_SENTRY_DSN", value)
    assert obs._sentry_dsn() == ""


def test_sentry_dsn_from_config_and_env_are_read(no_config, monkeypatch):
    dsn = "https://k@o0.ingest.sentry.io/1"
    _config_switch(monkeypatch, no_config, "sentry_dsn", dsn)
    assert obs._sentry_dsn() == dsn
    monkeypatch.setenv("MAVERICK_SENTRY_DSN", "  " + dsn + "  ")
    assert obs._sentry_dsn() == dsn
