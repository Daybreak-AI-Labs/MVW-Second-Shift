"""Second Shift: recursive multi-agent swarm for long-horizon work."""

import os

_PRODUCT_PREFIX = "SECOND_SHIFT_"
_MAVERICK_PREFIX = "MAVERICK_"


def _mirror_product_env() -> None:
    """Mirror ``SECOND_SHIFT_*`` env vars onto their ``MAVERICK_*`` twins.

    Product-name compatibility shim: every ``MAVERICK_X`` setting can also
    be spelled ``SECOND_SHIFT_X``. ``setdefault`` means an explicitly-set
    ``MAVERICK_X`` always wins -- the mirror never overwrites, so the call
    is idempotent. Guarded so it can never break an import.
    """
    try:
        for key, value in list(os.environ.items()):
            if key.startswith(_PRODUCT_PREFIX):
                os.environ.setdefault(
                    _MAVERICK_PREFIX + key[len(_PRODUCT_PREFIX):], value
                )
    except Exception:
        pass  # never let env quirks break `import maverick`


_mirror_product_env()
_STARTUP_AUDIT_TRUSTED_PUBLIC_KEYS = os.environ.get("MAVERICK_AUDIT_TRUSTED_PUBLIC_KEYS", "")


def _install_egress_guard() -> None:
    """Wrap the HTTP client send paths so the enterprise egress lock applies.

    Installed at import rather than from each entry point on purpose: a
    boundary that depends on every connector author remembering to call
    ``enterprise_egress_denial`` is false wherever someone forgets. Wiring that
    can be forgotten is the defect, and import is the only hook every code path
    capable of making a request has necessarily run.

    A no-op unless enterprise mode (or a compliance floor) is on, so the
    default zero-config posture is unchanged. An ordinary bootstrap tolerates
    an unsupported optional HTTP client, but an explicitly asserted enterprise
    or compliance process refuses to start without its promised boundary.
    ``egress_guard.uninstall()`` reverses a successful installation.
    """
    try:
        from .egress_guard import install
        install()
    except Exception as exc:
        try:
            from .enterprise import enterprise_enabled

            boundary_required = enterprise_enabled()
        # Failure to resolve an asserted security posture is itself a reason to
        # fail closed; this branch runs only after guard installation failed.
        except Exception:  # pragma: no cover - resolver already fails closed
            boundary_required = True
        if boundary_required:
            raise RuntimeError(
                "refusing to start: the enterprise/compliance process-wide "
                "egress boundary could not be installed"
            ) from exc


_install_egress_guard()
