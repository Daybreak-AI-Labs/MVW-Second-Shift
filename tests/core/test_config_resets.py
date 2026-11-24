"""Reviewed overlay reset contracts. Authored for the deferred test run."""

import pytest
from maverick.config import _deep_merge_config
from maverick.config_resets import METADATA, merge_dashboard


def test_unreadable_reset_metadata_refuses_ambiguous_merge():
    with pytest.raises(ValueError):
        merge_dashboard({'budget': {}}, {METADATA: {'bad': {'path': ['budget']}}}, _deep_merge_config)
