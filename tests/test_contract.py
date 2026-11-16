"""Every plugin here conforms to the class contract (plugin API 2.2): liminal_libs.sources.conformance, read
from the plugin alone (nothing runs)."""
from __future__ import annotations

import plugin_platform_firewall_linux as module
from liminal_libs.sources.conformance import assert_module_conforms


def test_every_plugin_here_conforms_to_the_class_contract():
    found = assert_module_conforms(module)
    assert found and all(p.api == "2.2" and not p.is_record for p in found)
    assert {p.SYSTEM for p in found} == {"platform"} and {p.KIND for p in found} == {"machine"}
    assert all(p.apis and p.interface()["apis"] == [a.name for a in p.apis] for p in found)  # what it attaches to (2.2)


def test_it_is_drawn_under_the_platforms_os_plugins():
    """Its section of the platform's list (liminal-platform 0.26.0; the user, 2026-11-15: "then OS plugins"): OS plugins,
    beside the machine's own, the virtualization and the cloud plugins."""
    assert {p.SECTION for p in assert_module_conforms(module)} == {"os"}
