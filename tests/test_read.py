"""The firewall's one read over recorded machines (tests/recorded): Debian 13 with nftables of its own and Docker on
iptables-nft, Ubuntu 24.04 with ufw, Fedora 43 with firewalld on nftables, Gentoo under OpenRC with nftables, Alpine
under OpenRC with BusyBox and legacy iptables. Each part parsed as its tool prints it, whose each rule is, what is in
charge, where the distribution keeps its rules; nothing runs."""
from __future__ import annotations

import json

import pytest

from plugin_platform_firewall_linux import firewalld as fwd
from plugin_platform_firewall_linux import nftables as nft
from plugin_platform_firewall_linux import read, system, ufw, xtables
from plugin_platform_firewall_linux.model import Entry, parse_address, parse_ports, spans_of

from machines import FakeLinux, answer, recorded


def config(machine: str, **changed) -> read.Config:
    return read.parse(answer(FakeLinux(machine, **changed).sections), at=0)


def by_text(cfg, start: str) -> Entry:
    return next(e for e in cfg.entries() if e.text.startswith(start))


def test_the_script_and_its_sections():
    assert read.SCRIPT.startswith("echo '== liminal-firewall 1'") and "nft -j list ruleset" in read.SCRIPT
    assert "/proc/net/ip_tables_names" in read.SCRIPT  # the legacy x_tables read only when loaded
    for word in ("rc-service", "systemctl is-enabled", "firewall-offline-cmd", "ufw show added", "bpftool -j net show"):
        assert word in read.SCRIPT
    secs = read.sections(answer({"os": (0, "ID=x"), "nft": (1, ""), "nft.err": (0, "Operation not permitted")}))
    assert secs["os"] == (0, "ID=x") and secs["nft"] == (1, "") and secs["end"] == (0, "")
    with pytest.raises(ValueError):
        read.sections("sudo: a password is required")
    cfg = read.parse(answer({"os": (0, "ID=debian"), "nft": (1, ""), "nft.err": (0, "netlink: Error: Operation not permitted")}))
    assert cfg.nft is None and cfg.problems == ["nftables' ruleset could not be read: netlink: Error: Operation not permitted"]
    assert cfg.manager == "" and not cfg.readable


def test_debian_nftables_of_its_own_and_dockers_rules_through_iptables_nft():
    cfg = config("debian-13-nftables")
    s = cfg.system
    assert (s.family, s.init, s.kernel, s.name) == ("debian", "systemd", "6.12.57+deb13-amd64", "Debian GNU/Linux 13 (trixie)")
    assert cfg.manager == "nftables" and cfg.nft_version == "1.1.3" and (cfg.iptables_version, cfg.iptables_variant) == ("1.8.11", "nf_tables")
    assert cfg.skipped_tables() == {("ip", "nat"), ("ip", "filter")}  # iptables-nft's: read through iptables-save
    own = [e for e in cfg.entries() if e.kind == "nftables"]
    assert {e.where for e in own} == {"inet filter input"} and all(e.owner == "own" and e.removable for e in own)
    ssh = by_text(cfg, "tcp dport 22")
    assert ssh.text == 'tcp dport 22 counter accept comment "ssh"' and ssh.counted == "1204 packets, 73211 bytes"
    assert (ssh.direction, ssh.action, ssh.protocol, ssh.ports, ssh.spans) == ("in", "accept", "tcp", "22", ((22, 22),))
    lan = by_text(cfg, "ip saddr 192.168.1.0/24")
    assert (lan.source, lan.ports, lan.comment) == ("192.168.1.0/24", "9100", "node exporter from the LAN")
    assert by_text(cfg, "ct state established,related").local and by_text(cfg, 'iifname "lo"').local
    blocked = by_text(cfg, "ip saddr @blocked")
    assert (blocked.action, blocked.source) == ("drop", "@blocked")
    icmp = by_text(cfg, "meta l4proto")
    assert not icmp.covers(8765) and icmp.protocol == "{ icmp, ipv6-icmp }"  # no ports: not a TCP port's rule
    docker = [e for e in cfg.entries() if e.kind == "iptables"]
    assert docker and all(e.owner == "docker" and not e.removable for e in docker)
    masq = by_text(cfg, "-s 172.17.0.0/16")
    assert (masq.direction, masq.action, masq.target, masq.interface) == ("nat", "nat", "MASQUERADE", "not docker0")
    dnat = by_text(cfg, "! -i docker0 -p tcp -m tcp --dport 5432 -j DNAT")
    assert dnat.target == "DNAT 172.17.0.2:5432" and dnat.ports == "5432"
    assert by_text(cfg, "-j DOCKER-USER").direction == "fwd"
    assert cfg.state() == {"enabled": True, "profiles": {"inet filter input": True}}
    assert [c.key for c in cfg.own_filter_chains()] == ["inet filter input"]
    assert cfg.exposing([8765, 9100]) == [(9100, "nftables inet filter input handle 12 (node exporter from the LAN)")]
    assert s.ssh_ports == {22} and s.ssh_sessions == 1 and s.conntrack == (42, 262144)
    eth = next(i for i in s.interfaces if i.name == "enp3s0")
    assert eth.addresses[0] == "192.168.1.10/24" and eth.xdp == "XDP generic: program 42"
    assert "tc enp3s0 clsact/ingress tc_ingress id 57" in s.bpf
    assert s.service("nftables") == system.ServiceState("nftables", True, True, True, "active enabled")
    keep = s.keeping("nftables")
    assert (keep.how, keep.path, keep.service) == ("file", "/etc/nftables.conf", "nftables")
    assert [(x.name, x.type, x.elements) for x in cfg.nft.sets] == [("blocked", "ipv4_addr", 2)]


def test_ubuntu_ufw_its_rules_numbered_and_its_machinery_kept_out():
    cfg = config("ubuntu-24.04-ufw")
    assert cfg.manager == "ufw" and cfg.ufw.active and cfg.ufw.version == "0.36.2"
    assert cfg.ufw.defaults == {"incoming": "deny", "outgoing": "allow", "routed": "disabled"} and cfg.ufw.logging == "on (low)"
    entries = cfg.entries()
    assert all(e.kind == "ufw" for e in entries) and cfg.hidden == {"ufw": 9}  # ufw's chains in iptables-nft: shown through ufw
    web = by_text(cfg, "80,443/tcp")
    assert (web.number, web.ports, web.protocol, web.comment, web.owner, web.removable) == (2, "80,443", "tcp", "web", "ufw", True)
    mail = by_text(cfg, "25,587/tcp")
    assert mail.owner == "liminal" and mail.liminal_name == "mail-example-test"
    lan = by_text(cfg, "Anywhere  ALLOW IN  10.0.0.0/8")
    assert (lan.source, lan.spans, lan.covers(8765)) == ("10.0.0.0/8", (), True)
    out = by_text(cfg, "53/udp")
    assert (out.direction, out.protocol, out.text) == ("out", "udp", "53/udp  ALLOW OUT  Anywhere (out)")
    assert by_text(cfg, "22/tcp (v6)").family == "ipv6"
    assert [r.name for r in cfg.liminal_rules()] == ["mail-example-test"] and cfg.liminal_rules()[0].ports == (25, 587)
    assert cfg.state() == {"enabled": True, "profiles": {"ufw": True}}
    off = config("ubuntu-24.04-ufw", ufw_verbose="Status: inactive", ufw_numbered="Status: inactive")
    assert off.manager == "ufw" and not off.ufw.active and len(off.entries()) == 5  # as added, while ufw is off
    spec = next(e for e in off.entries() if e.comment == "liminal:mail-example-test")
    assert (spec.ports, spec.protocol, spec.where) == ("25,587", "tcp", "ufw (off)")
    assert next(e for e in off.entries() if e.text == "ufw allow out 53/udp").direction == "out"


def test_fedora_firewalld_zones_services_rich_rules_and_its_table_kept_out():
    cfg = config("fedora-43-firewalld")
    f = cfg.firewalld
    assert cfg.manager == "firewalld" and f.running and (f.version, f.default_zone, f.backend) == ("2.3.2", "FedoraServer", "nftables")
    zone = f.zone("FedoraServer")
    assert zone.active and zone.default and zone.words("services") == ["cockpit", "dhcpv6-client", "ssh"] and zone.words("ports") == ["8443/tcp"]
    assert zone.rich == ['rule family="ipv4" source address="10.0.0.0/8" port port="9100" protocol="tcp" accept']
    assert f.zone("docker").target == "ACCEPT" and not f.zone("public").active and f.services["ssh"] == ["22/tcp"]
    assert [p.name for p in f.policies] == ["allow-host-ipv6", "docker-forwarding"]
    assert cfg.hidden == {"firewalld": 4}  # firewalld's own nftables table: shown through its zones
    assert zone.words("forward-ports") == ["port=80:proto=tcp:toport=8080:toaddr="]  # its own line, after a TAB
    fp = by_text(cfg, "forward-port")
    assert (fp.direction, fp.action, fp.ports, fp.target) == ("nat", "nat", "80", "8080")
    ssh = by_text(cfg, "service ssh")
    assert (ssh.where, ssh.ports, ssh.protocol, ssh.owner, ssh.removable) == ("zone FedoraServer", "22", "tcp", "firewalld", True)
    rich = by_text(cfg, 'rule family="ipv4"')
    assert (rich.source, rich.ports, rich.action) == ("10.0.0.0/8", "9100", "accept")
    assert not by_text(cfg, 'rule family="ipv6" icmp-type').covers(22)
    assert cfg.exposing([22, 8765]) == [(22, "firewalld's zone FedoraServer: service ssh (22/tcp)")]  # Docker's ACCEPT zone: its bridge only
    assert cfg.state() == {"enabled": True, "profiles": {"FedoraServer": True}}
    assert cfg.system.keeping("nftables").path == "/etc/sysconfig/nftables.conf"
    stopped = config("fedora-43-firewalld", firewalld_state=(252, "not running"))
    assert stopped.manager == "firewalld" and not stopped.firewalld.running


def test_gentoo_openrc_nftables_saved_by_its_service():
    cfg = config("gentoo-openrc-nftables")
    s = cfg.system
    assert (s.family, s.init, s.init_words) == ("gentoo", "openrc", "OpenRC") and cfg.manager == "nftables" and cfg.nft_version == "1.1.5"
    assert s.service("nftables") == system.ServiceState("nftables", True, True, True, "started default")
    keep = s.keeping("nftables")
    assert (keep.how, keep.command, keep.path) == ("command", ("rc-service", "nftables", "save"), "/var/lib/nftables/rules-save")
    vmap = by_text(cfg, "ct state vmap")
    assert vmap.text == "ct state vmap { established : accept, related : accept, invalid : drop }" and vmap.local
    assert vmap.action == "vmap" and vmap.state == "established,related"
    mine = by_text(cfg, "tcp dport { 25, 587 }")
    assert mine.owner == "liminal" and mine.liminal_name == "mail-example-test" and mine.spans == ((25, 25), (587, 587))
    mosh = by_text(cfg, "udp dport 60000-61000")
    assert mosh.spans == ((60000, 61000),) and mosh.covers(60500, "udp") and not mosh.covers(60500)
    last = by_text(cfg, "counter reject")
    assert last.text == "counter reject with icmpx port-unreachable" and nft.catch_all(cfg.nft.rules[-1])
    assert by_text(cfg, "tcp dport 22 ct state new limit rate 10/minute burst 5 packets accept").comment == "ssh, limited"
    systemd = system.keeping("nftables", "gentoo", "systemd", {}, {}, {})  # nftables-load and nftables-store since 1.1.1-r1
    assert (systemd.how, systemd.command, systemd.service) == ("command", ("systemctl", "start", "nftables-store.service"), "nftables-load")
    old = system.keeping("nftables", "gentoo", "systemd", {}, {"nftables-restore": system.ServiceState("nftables-restore", True)}, {})
    assert (old.how, old.service) == ("file", "nftables-restore")
    loader = system.parse_services("systemd", "nftables-load yes inactive enabled")["nftables-load"]
    assert (loader.running, loader.at_boot) == (None, True)  # a one-shot that has run reads inactive: its boot place says


def test_alpine_openrc_busybox_and_legacy_iptables():
    cfg = config("alpine-3.22-iptables")
    s = cfg.system
    assert (s.family, s.init) == ("alpine", "openrc") and cfg.nft is None and cfg.manager == "iptables"
    assert (cfg.iptables_version, cfg.iptables_variant) == ("1.8.11", "nf_tables")  # xtables-nft-multi, without nft's tool
    assert [(i.name, i.addresses) for i in s.interfaces] == [("lo", ("127.0.0.1/8",)), ("eth0", ("10.0.2.15/24",))]  # BusyBox's ip
    assert s.ssh_ports == {22}  # BusyBox's netstat
    assert cfg.state() == {"enabled": True, "profiles": {"iptables filter INPUT": True, "ip6tables filter INPUT": True}}
    ssh = by_text(cfg, "-p tcp -m tcp --dport 22")
    assert (ssh.kind, ssh.number, ssh.removable) == ("iptables", 3, True)
    assert not by_text(cfg, "-p icmp").covers(22)
    keep = s.keeping("iptables")
    assert (keep.how, keep.command) == ("command", ("rc-service", "iptables", "save"))
    nft_keep = s.keeping("nftables")  # its own `rc-service nftables save` keeps counters and quotas, not the rules
    assert (nft_keep.how, nft_keep.path) == ("file", "/etc/nftables.nft")


def test_each_tool_parsed_as_it_prints():
    assert xtables.version_of("iptables v1.8.11 (nf_tables)") == ("1.8.11", "nf_tables")
    assert xtables.version_of("iptables v1.8.7 (legacy)") == ("1.8.7", "legacy")
    assert xtables.version_of("iptables v1.6.1") == ("1.6.1", "legacy") and xtables.version_of("") == ("", "")
    saved = xtables.parse_save('# Table `filter\' is incompatible, use \'nft\' tool.\n*nat\n:POSTROUTING ACCEPT [0:0]\n'
                               '[10:600] -A POSTROUTING -o eth0 -m comment --comment "liminal:nat out" -j MASQUERADE\nCOMMIT\n', "iptables")
    assert saved.incompatible == ["filter"] and saved.rules[0].args[-4:] == ("--comment", "liminal:nat out", "-j", "MASQUERADE")
    e = xtables.entries(saved)[0]
    assert e.owner == "liminal" and e.text == "-o eth0 -m comment --comment 'liminal:nat out' -j MASQUERADE"
    sets = xtables.parse_ipsets("Name: blocklist\nType: hash:net\nRevision: 7\nHeader: family inet hashsize 1024 maxelem 65536\n"
                                "Size in memory: 1234\nReferences: 1\nNumber of entries: 3\n\nName: v6\nType: hash:ip\nHeader: family inet6\n"
                                "References: 0\nNumber of entries: 0\n")
    assert [(x.name, x.type, x.family, x.entries, x.references) for x in sets] == [("blocklist", "hash:net", "inet", 3, 1), ("v6", "hash:ip", "inet6", 0, 0)]
    blocks = fwd.parse_blocks("public (default, active)\n  target: default\n  interfaces: eth0\n  services: ssh\n  rich rules: \n\n"
                              "work\n  target: ACCEPT\n  sources: 10.0.0.0/8\n")
    assert [(z.name, z.active, z.default, z.target) for z in blocks] == [("public", True, True, "default"), ("work", False, False, "ACCEPT")]
    view = fwd.rich_view('rule family="ipv4" source address="192.168.0.0/16" service name="liminal-office" drop')
    assert (view["source"], view["service"], view["action"]) == ("192.168.0.0/16", "liminal-office", "drop")
    st = ufw.parse_status("Status: active\nDefault: reject (incoming), allow (outgoing), deny (routed)\n",
                          "[ 1] OpenSSH                    LIMIT IN    Anywhere\n[ 2] Anywhere on wg0            ALLOW FWD   Anywhere on eth0\n")
    assert st.defaults == {"incoming": "reject", "outgoing": "allow", "routed": "deny"}
    ssh, fwd_rule = ufw.entries(st)
    assert (ssh.action, ssh.spans, ssh.protocol) == ("limit", ((22, 22),), "tcp")  # OpenSSH's profile: what the lockout check needs
    assert (fwd_rule.direction, fwd_rule.interface) == ("fwd", "wg0")
    assert system.family_of({"ID": "rocky", "ID_LIKE": "rhel centos fedora"}) == "fedora"
    assert system.family_of({"ID": "opensuse-tumbleweed", "ID_LIKE": "opensuse suse"}) == "suse"
    assert system.family_of({"ID": "artix", "ID_LIKE": "arch"}) == "arch" and system.family_of({"ID": "plan9"}) == ""
    assert system.parse_os_release('ID="linuxmint"\nID_LIKE="ubuntu debian"\n# a comment\n') == {"ID": "linuxmint", "ID_LIKE": "ubuntu debian"}
    assert system.keeping("nftables", "nixos", "systemd", {}, {}, {}).how == "none"
    assert system.keeping("iptables", "debian", "systemd", {}, {}, {}).how == "none"  # no iptables-persistent
    assert system.service_command("openrc", "firewalld", "start") == [["rc-update", "add", "firewalld", "default"], ["rc-service", "firewalld", "start"]]
    assert system.service_command("systemd", "nftables", "stop") == [["systemctl", "disable", "--now", "nftables"]]
    multi = system.parse_addresses(json.dumps([{"ifname": "eth1", "operstate": "UP", "addr_info": [],
                                                "xdp": {"mode": 4, "attached": [{"mode": 1, "prog": {"id": 7}}, {"mode": 2, "prog": {"id": 8}}]}}]))
    assert multi[0].xdp == "XDP multiple: programs 7 (driver), 8 (generic)"


def test_nftables_written_out_again():
    r = nft.Rule("inet", "filter", "input", 1, tuple([
        {"match": {"op": "!=", "left": {"payload": {"protocol": "ip6", "field": "saddr"}}, "right": {"prefix": {"addr": "fe80::", "len": 10}}}},
        {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "wg0"}},
        {"log": {"prefix": "dropped: ", "level": "info"}}, {"limit": {"rate": 3, "per": "minute", "burst": 5}},
        {"dnat": {"addr": "10.0.0.2", "port": 8080, "family": "ip"}}]))
    assert nft.rule_text(r) == 'ip6 saddr != fe80::/10 oifname "wg0" log prefix "dropped: " level info limit rate 3/minute burst 5 packets dnat ip to 10.0.0.2:8080'
    v = nft.view(r)
    assert (v["source"], v["interface"], v["action"]) == ("not fe80::/10", "wg0", "nat")
    assert nft.statement_text({"quota": {"val": 10, "val_unit": "mbytes", "used": 1234, "inv": True}}) == "quota over 10 mbytes"
    assert nft.statement_text({"weird": 1}) == '{"weird":1}'
    with pytest.raises(ValueError):
        nft.parse('{"no": []}')
    assert nft.parse("").tables == []


def test_what_a_form_types_is_checked():
    assert parse_ports("22, 80 443,8000-8100") == ((22, 22), (80, 80), (443, 443), (8000, 8100)) and parse_ports("") == ()
    for bad in ("http", "0", "70000", "90-80"):
        with pytest.raises(ValueError):
            parse_ports(bad)
    assert parse_address("10.1.2.3/8") == "10.0.0.0/8" and parse_address("any") == "" and parse_address("2001:db8::1") == "2001:db8::1"
    with pytest.raises(ValueError):
        parse_address("example.com")
    assert spans_of("8000:8100,22") == ((8000, 8100), (22, 22))
    assert recorded("gentoo-openrc-nftables")["init"] == (0, "openrc init\n")


def test_firewalld_blocks_of_every_version():
    """2.4+: a policy's `disable:` line and (disabled); 2.5.1+: no empty line between blocks; 1.x: no priorities."""
    text = ("allow-host-ipv6 (active)\n  disable: no\n  priority: -15000\n  target: CONTINUE\n  ingress-zones: ANY\n"
            "  egress-zones: HOST\n  services: \n  rich rules: \n\trule family=\"ipv6\" icmp-type name=\"redirect\" accept\n"
            "gateway-lan-to-world (disabled)\n  disable: yes\n  priority: 1000\n  target: ACCEPT\n  ingress-zones: internal home\n"
            "  egress-zones: external public\n  services: ftp tftp\n  rich rules: \n")
    pols = fwd.parse_blocks(text, policy=True)
    assert [(p.name, p.active, p.disabled, p.target) for p in pols] == [("allow-host-ipv6", True, False, "CONTINUE"),
                                                                         ("gateway-lan-to-world", False, True, "ACCEPT")]
    st = fwd.FirewalldState(installed=True, running=True, policies=pols)
    assert [e.where for e in fwd.entries(st)] == ["policy allow-host-ipv6"]  # a disabled policy has no rules in force
    zones = fwd.parse_blocks("public (default, active)\n  target: default\n  interfaces: eth0\n  forward-ports: \n"
                             "\tport=2222:proto=tcp:toport=22:toaddr=10.0.0.5\n  rich rules: \n"
                             "\trule priority=\"-100\" family=\"ipv4\" source address=\"203.0.113.7\" drop\n"
                             "trusted\n  target: ACCEPT\n  sources: 10.0.0.0/8\n")
    assert [z.name for z in zones] == ["public", "trusted"] and zones[0].words("forward-ports") == ["port=2222:proto=tcp:toport=22:toaddr=10.0.0.5"]
    assert zones[0].rich == ['rule priority="-100" family="ipv4" source address="203.0.113.7" drop']
    v = fwd.rich_view(zones[0].rich[0])
    assert (v["source"], v["action"], v["family"]) == ("203.0.113.7", "drop", "ipv4")


def test_the_legacy_x_tables_beside_nf_tables():
    legacy = ("# Generated by iptables-legacy-save v1.8.11 on Sun Nov  8 10:12:01 2026\n*filter\n:INPUT ACCEPT [0:0]\n"
              ":FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -s 198.51.100.0/24 -j DROP\nCOMMIT\n")
    cfg = config("debian-13-nftables", iptables_legacy=legacy)
    old = next(e for e in cfg.entries() if e.where == "filter INPUT (legacy)")
    assert (old.kind, old.action, old.source, old.ref.split("|")[1]) == ("iptables", "drop", "198.51.100.0/24", "iptables-legacy")
    assert config("debian-13-nftables", iptables_legacy="").legacy == {}  # loaded but empty: nothing of its own


def test_ufw_rows_as_its_format_prints_them():
    st = ufw.parse_status("Status: active\n", "[ 1] 10.0.0.0/8                 ALLOW OUT   Anywhere on eth1           (out)\n"
                          "[ 2] 10.0.0.5 22/tcp            ALLOW IN    Anywhere                  \n"
                          "[ 3] 23 (v6)                    DENY IN     Anywhere (v6)              # telnet\n")
    out, to_host, telnet = ufw.entries(st)
    assert (out.direction, out.destination, out.ports, out.interface) == ("out", "10.0.0.0/8", "", "eth1")
    assert (to_host.destination, to_host.ports, to_host.protocol) == ("10.0.0.5", "22", "tcp")
    assert (telnet.action, telnet.ports, telnet.protocol, telnet.comment, telnet.family) == ("drop", "23", "", "telnet", "ipv6")
    assert telnet.covers(23, "udp") and telnet.covers(23)  # any protocol: ufw shows the port alone


def test_what_the_netfilter_research_found():
    # bpftool's net JSON: XDP single and multi, classic tc by "id" and tcx by "prog_id", netfilter links, and a flow
    # dissector written as ["id":N] (not JSON) mended before it is read
    bpf = ('[{"xdp":[{"devname":"eth0","ifindex":2,"mode":"driver","id":42},{"devname":"eth1","ifindex":3,"multi_attachments":'
           '[{"mode":"generic","id":43},{"mode":"driver","id":44}]}],"tc":[{"devname":"eth0","ifindex":2,"kind":"clsact/ingress",'
           '"name":"tc_ingress.o:[tc]","id":51},{"devname":"eth1","ifindex":3,"kind":"tcx/ingress","name":"tcx_ingress","prog_id":60,'
           '"prog_flags":[],"link_id":7,"link_flags":[]}],"flow_dissector":["id":9],"netfilter":[{"pf":2,"hook":1,"prio":-128,"flags":0,"id":15}]}]')
    assert system.parse_bpf_net(bpf) == ["xdp eth0 driver id 42", "xdp eth1 generic id 43", "xdp eth1 driver id 44",
                                         "tc eth0 clsact/ingress tc_ingress.o:[tc] id 51", "tc eth1 tcx/ingress tcx_ingress id 60",
                                         "flow dissector id 9", "netfilter ip input prio -128 id 15"]
    assert system.parse_bpf_net('[{"xdp":[],"tc":[],"flow_dissector":[],"netfilter":[]}]') == []
    # nft's JSON as its versions write it: flags a word or a list, a chain's devices a list, a set's typeof, an owned table
    rs = nft.parse(json.dumps({"nftables": [
        {"metainfo": {"version": "1.1.7", "release_name": "Commodore Bullmoose #8", "json_schema_version": 1}},
        {"table": {"family": "inet", "name": "daemon", "handle": 4, "flags": ["owner", "persist"]}},
        {"table": {"family": "netdev", "name": "edge", "handle": 5, "flags": "dormant"}},
        {"chain": {"family": "netdev", "table": "edge", "name": "in", "handle": 1, "dev": ["eth0", "eth1"], "type": "filter",
                   "hook": "ingress", "prio": -500, "policy": "accept"}},
        {"set": {"family": "inet", "name": "seen", "table": "daemon", "type": {"typeof": {"payload": {"protocol": "ip", "field": "saddr"}}},
                 "handle": 2, "flags": "timeout"}},
        {"rule": {"family": "inet", "table": "daemon", "chain": "c", "handle": 3, "expr": [
            {"match": {"op": "==", "left": {"ct": {"key": "state"}}, "right": {"set": ["established", "related"]}}},
            {"counter": None}, {"log": None}, {"accept": None}]}}]}))
    assert [t.flags for t in rs.tables] == [("owner", "persist"), ("dormant",)]
    assert rs.chains[0].dev == "eth0, eth1" and rs.sets[0].type == "typeof ip saddr" and rs.sets[0].flags == ("timeout",)
    assert nft.table_owner(rs.tables[0], rs.chains) == "owned"
    e = nft.entries(rs)[0]
    assert e.owner == "owned" and not e.removable and e.local  # a state in braces is the replies' still
    assert e.text == "ct state { established, related } counter log accept"
    # iptables-nft could not read every base chain of a table: nftables' JSON stands for it, not half of it twice
    saved = xtables.parse_save("# Table `filter' contains incompatible base-chains, use 'nft' tool to list them.\n*filter\n"
                               ":INPUT ACCEPT [0:0]\n-A INPUT -j ACCEPT\nCOMMIT\n", "iptables")
    assert saved.incompatible == ["filter"] and xtables.entries(saved) == []
    # the read never loads a module: legacy iptables only when its tables are loaded, ipset only when ip_set is
    assert "*) if [ -s /proc/net/ip_tables_names ]; then sec iptables.save iptables-save; fi" in read.SCRIPT
    assert "if [ -d /sys/module/ip_set ]; then sec ipset ipset list -t; fi" in read.SCRIPT
    assert "conntrack -" not in read.SCRIPT  # its counts from /proc, never through netlink (which would load it)
