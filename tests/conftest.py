"""Shared fixtures. Anything defined here is visible to every test file
under tests/, no import needed -- pytest finds conftest.py by location.
"""

import pytest

from mcp_scanner.baseline import BaselineStore
from mcp_scanner.connector import ToolInfo


@pytest.fixture
def make_tool():
    """Factory fixture: returns a function for building a ToolInfo with
    sensible defaults, so each test only spells out the fields it cares about.
    """

    def _make(name="test_tool", description="", input_schema=None):
        return ToolInfo(name=name, description=description, input_schema=input_schema or {})

    return _make


@pytest.fixture
def baseline_store_factory(tmp_path):
    """Factory fixture with teardown: every BaselineStore it hands out shares
    one temp sqlite file (so sequential scans see each other's baseline, like
    real CLI runs do) and gets closed automatically once the test finishes --
    everything after `yield` runs on teardown, pass or fail.
    """
    db_path = tmp_path / "baseline.db"
    stores = []

    def _make():
        store = BaselineStore(db_path=db_path)
        stores.append(store)
        return store

    yield _make

    for store in stores:
        store.close()
