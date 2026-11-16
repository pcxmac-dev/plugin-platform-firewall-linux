"""What every test here shares: the machine the tests run on never shows through. Not inside WSL (the library's
linux.wsl_table for the status, world.under_wsl for the World Wide Web tab), and no init known (world._init, so both ways
to the right to capture are told), so the suite reads alike inside a WSL distribution, on a Linux of any init and on
Windows. A test that wants one of them says so itself."""
from __future__ import annotations

import pytest

from liminal_libs.machines import linux, world


@pytest.fixture(autouse=True)
def _not_this_machine(monkeypatch):
    if hasattr(linux, "wsl_table"):  # a library whose check no longer refuses a WSL kernel
        monkeypatch.setattr(linux, "wsl_table", lambda *args, **kwargs: None)
    monkeypatch.setattr(world, "under_wsl", lambda *args, **kwargs: None)
    monkeypatch.setattr(world, "_init", lambda: "")
