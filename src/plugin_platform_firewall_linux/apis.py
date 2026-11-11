"""What the Linux firewall attaches to (plugin API 2.2, liminal_libs.sources.apis; the user, 2026-11-11: "each plugin
should reflect the the API its attached to, and present links that provide documentation ... it should also expose more
of what the API is about"): nftables, iptables and ip6tables, ebtables and arptables, ipset, firewalld, ufw, conntrack,
eBPF through bpftool, iproute2's ip and ss, the init's firewall services, and sudo (how root's rights are had), each as
its makers' pages describe it. Every address was read on 2026-11-11 (`VERIFIED`). `facts` says what the last read
found of them (the tools' versions, what each holds), asking nothing."""
from __future__ import annotations

import time

from liminal_libs.sources.apis import Api, Area, Call, Link

VERIFIED = "2026-11-11"
NFT_WIKI = "https://wiki.nftables.org/wiki-nftables/index.php/"
NFT_MAN = "https://www.netfilter.org/projects/nftables/manpage.html"
NFT_JSON = "https://manpages.debian.org/unstable/libnftables1/libnftables-json.5.en.html"
MAN7 = "https://man7.org/linux/man-pages/"
DEBIAN = "https://manpages.debian.org/unstable/"
FIREWALLD = "https://firewalld.org/documentation/"
UFW_MAN = "https://manpages.ubuntu.com/manpages/resolute/man8/ufw.8.html"
SYSTEMD = "https://www.freedesktop.org/software/systemd/man/latest/"
OPENRC = "https://github.com/OpenRC/openrc/blob/master/"

NFTABLES = Api(
    name="nftables (nft)",
    maker="the netfilter project",
    about=("nftables is the Linux kernel's packet classification framework (nf_tables) and nft its command line: tables "
           "of chains hooked into the network stack, rules matching packets, sets and maps, the whole ruleset listed as "
           "JSON. The plugin reads the ruleset in one listing, makes and removes Liminal's rules and this machine's own, "
           "sets a base chain's policy, and saves the machine's own tables where the distribution loads them at boot."),
    kind="command",
    base="nft, as root (through sudo -n)",
    version="nftables 1.1.7 (its JSON's flags as words on 1.1.3 and older, as lists on 1.1.7: both read)",
    auth="root (CAP_NET_ADMIN), had through sudo without a password",
    limits="",
    costs="",
    links=(
        Link("The nftables wiki", NFT_WIKI + "Main_Page", "docs"),
        Link("nft(8)", NFT_MAN, "reference"),
        Link("libnftables-json(5)", NFT_JSON, "spec"),
        Link("Quick reference: nftables in 10 minutes", NFT_WIKI + "Quick_reference-nftables_in_10_minutes", "guide"),
        Link("Moving from iptables to nftables", NFT_WIKI + "Moving_from_iptables_to_nftables", "guide"),
        Link("The nftables project", "https://www.netfilter.org/projects/nftables/", "tool"),
        Link("netfilter's news", "https://www.netfilter.org/news.html", "changelog"),
        Link("nftables' source", "https://git.netfilter.org/nftables/", "source"),
    ),
    areas=(
        Area("The ruleset", "every table, chain, rule, set and map, listed whole (as JSON with -j)", NFT_WIKI + "Operations_at_ruleset_level",
             covered="read in one listing (nft -j list ruleset); each rule written again in nft's own words"),
        Area("Tables", "a family's tables (ip, ip6, inet, arp, bridge, netdev) and their flags (dormant, owner, persist)",
             NFT_WIKI + "Configuring_tables",
             covered="each table's owner found (this machine, Liminal, a program); a dormant one shown turned off; an owned one read only"),
        Area("Chains", "base chains on a hook with a priority and a policy, and regular chains", NFT_WIKI + "Configuring_chains",
             covered="the input, forward and output base chains and their policies; a policy set; a table of Liminal's own made when needed"),
        Area("Rules", "rules added, inserted at a place, deleted by their handle", NFT_WIKI + "Simple_rule_management",
             covered="Liminal's rules and this machine's made and removed (never a program's that makes its own)"),
        Area("Netfilter hooks", "where in the stack a chain sees packets", NFT_WIKI + "Netfilter_hooks",
             covered="what comes in, goes out or passes through, by the chains' hooks"),
        Area("Sets and maps", "named groups of addresses, ports and verdicts", NFT_WIKI + "Sets", covered="counted"),
        Area("Saving and restoring", "a ruleset written to a file and loaded with nft -f, checked with -c", NFT_WIKI + "Scripting",
             covered="the machine's own tables saved (nft -s list table), checked (nft -c -f) before they replace the file"),
        Area("Connection tracking in rules", "ct state, ct helpers and stateful objects", NFT_WIKI + "Matching_connection_tracking_stateful_metainformation"),
        Area("Flowtables", "a fast path for established flows", NFT_WIKI + "Flowtables", covered="counted"),
        Area("Atomic replacement", "a whole ruleset replaced at once", NFT_WIKI + "Atomic_rule_replacement"),
        Area("iptables' tables in nftables", "the xtables tools writing into nf_tables (iptables-nft)", NFT_WIKI + "Legacy_xtables_tools",
             covered="iptables-nft's tables read through iptables-save rather than as nftables JSON"),
    ),
    calls=(
        Call("nft --version", "nft's version", "The ruleset", used="the Firewall table's version", docs=NFT_MAN),
        Call("nft -j list ruleset", "the whole ruleset as JSON", "The ruleset", used="the read", docs=NFT_JSON),
        Call("nft insert rule <family> <table> <chain> [position <handle>] <rule> comment <words>",
             "a rule put at a chain's head, or before a rule", "Rules", used="Make… (a block at the head; an allow before the drop)",
             docs=NFT_WIKI + "Simple_rule_management", writes=True),
        Call("nft add rule <family> <table> <chain> <rule> comment <words>", "a rule put at a chain's end", "Rules",
             used="Make… (an allow where nothing drops after it)", docs=NFT_WIKI + "Simple_rule_management", writes=True),
        Call("nft delete rule <family> <table> <chain> handle <n>", "a rule removed by its handle", "Rules", used="Remove…",
             docs=NFT_WIKI + "Simple_rule_management", writes=True),
        Call("nft add table inet liminal", "a table of Liminal's own", "Tables",
             used="Make… a block where this machine has no chain of its own", docs=NFT_WIKI + "Configuring_tables", writes=True),
        Call("nft add chain <family> <table> <chain> { type filter hook <hook> priority 0; policy accept; }",
             "a base chain on a hook", "Chains", used="the same: Liminal's own chain", docs=NFT_WIKI + "Configuring_chains",
             writes=True),
        Call("nft add chain <family> <table> <chain> { policy <policy>; }", "a base chain's policy set", "Chains",
             used="Set… (a default policy; dropping by default asked twice when SSH would be cut)",
             docs=NFT_WIKI + "Configuring_chains", writes=True),
        Call("nft -s list table <family> <table>", "a table listed without its counters", "Saving and restoring",
             used="Save: the machine's own tables written to the file the boot loads", docs=NFT_MAN),
        Call("nft -c -f <file>", "a ruleset file checked, not applied", "Saving and restoring",
             used="Save: the new file checked before it replaces the old", docs=NFT_MAN),
        Call("nft -f <file>", "a ruleset file loaded", "Saving and restoring", docs=NFT_WIKI + "Scripting", writes=True),
        Call("nft flush ruleset", "every table removed", "The ruleset", docs=NFT_WIKI + "Operations_at_ruleset_level", writes=True),
        Call("nft monitor", "the ruleset's changes as they happen", "The ruleset", docs=NFT_MAN),
        Call("nft add set <family> <table> <set> { type <type>; }", "a named set", "Sets and maps", docs=NFT_WIKI + "Sets",
             writes=True),
    ),
    verified=VERIFIED,
)

IPTABLES = Api(
    name="iptables and ip6tables",
    maker="the netfilter project",
    about=("iptables and ip6tables, the older rule tools: tables of built-in and user chains of rules, written out whole "
           "by iptables-save. Since 1.8 each comes in two variants: nf_tables (iptables-nft, writing into nftables' "
           "tables, the default on most distributions now) and legacy (the kernel's x_tables). The plugin reads both, "
           "makes and removes rules where iptables is in charge, sets a built-in chain's policy, and saves the rules "
           "where the distribution loads them at boot."),
    kind="command",
    base="iptables, ip6tables and their -save, as root (through sudo -n)",
    version=("iptables 1.8.13; the legacy x_tables read only when the kernel has them loaded (optional since Linux 6.17: "
             "reading them otherwise would load them)"),
    auth="root (CAP_NET_ADMIN), had through sudo without a password",
    limits="",
    costs="",
    links=(
        Link("The iptables project", "https://www.netfilter.org/projects/iptables/", "docs"),
        Link("iptables(8) and ip6tables(8)", MAN7 + "man8/iptables.8.html", "reference"),
        Link("iptables-save(8)", MAN7 + "man8/iptables-save.8.html", "reference"),
        Link("iptables-extensions(8)", MAN7 + "man8/iptables-extensions.8.html", "reference"),
        Link("xtables-nft(8): the nf_tables variant", DEBIAN + "iptables/xtables-nft.8.en.html", "guide"),
        Link("xtables-legacy(8)", DEBIAN + "iptables/xtables-legacy.8.en.html", "guide"),
        Link("netfilter-persistent(8)", DEBIAN + "netfilter-persistent/netfilter-persistent.8.en.html", "tool"),
        Link("netfilter's news", "https://www.netfilter.org/news.html", "changelog"),
        Link("iptables' source", "https://git.netfilter.org/iptables/", "source"),
    ),
    areas=(
        Area("Rules in chains", "rules appended, inserted at a number, deleted by their words", MAN7 + "man8/iptables.8.html",
             covered="Liminal's rules and this machine's made and removed where iptables is in charge"),
        Area("Policies", "a built-in chain's default (ACCEPT, DROP)", MAN7 + "man8/iptables.8.html",
             covered="INPUT, FORWARD and OUTPUT's policies set (dropping by default asked twice when SSH would be cut)"),
        Area("Saving", "the whole of a variant's tables written out", MAN7 + "man8/iptables-save.8.html",
             covered="read with iptables-save; saved where the distribution loads them at boot"),
        Area("Restoring", "a saved set of tables loaded back, at once", MAN7 + "man8/iptables-restore.8.html"),
        Area("User chains", "chains of one's own, jumped to from others", MAN7 + "man8/iptables.8.html"),
        Area("The two variants", "nf_tables (iptables-nft) and legacy (x_tables)", DEBIAN + "iptables/xtables-nft.8.en.html",
             covered="the variant read from iptables -V; the legacy tables beside an nf_tables iptables, when loaded"),
        Area("Matches and targets", "the extensions a rule uses: comment, conntrack, multiport...", MAN7 + "man8/iptables-extensions.8.html",
             covered="Liminal's rules carry a comment liminal:<name>"),
        Area("Keeping rules across a restart", "the distributions' own services and files (netfilter-persistent, iptables-services...)",
             DEBIAN + "netfilter-persistent/netfilter-persistent.8.en.html",
             covered="netfilter-persistent save, rc-service iptables save, iptables-store, or the file written"),
    ),
    calls=(
        Call("iptables -V", "iptables' version and variant", "The two variants", used="the read", docs=MAN7 + "man8/iptables.8.html"),
        Call("iptables-save", "IPv4's rules, whole", "Saving", used="the read; Save to a file",
             docs=MAN7 + "man8/iptables-save.8.html"),
        Call("ip6tables-save", "IPv6's rules, whole", "Saving", used="the read; Save to a file",
             docs=MAN7 + "man8/iptables-save.8.html"),
        Call("iptables-legacy-save", "the legacy x_tables' IPv4 rules", "The two variants",
             used="the read, when the kernel has them loaded", docs=DEBIAN + "iptables/xtables-legacy.8.en.html"),
        Call("ip6tables-legacy-save", "the legacy x_tables' IPv6 rules", "The two variants",
             used="the read, when the kernel has them loaded", docs=DEBIAN + "iptables/xtables-legacy.8.en.html"),
        Call("iptables|ip6tables -t filter -I <chain> <n> <rule> -j <target>", "a rule inserted at a number", "Rules in chains",
             used="Make… (a block first; an allow before the drop)", docs=MAN7 + "man8/iptables.8.html",
             writes=True),
        Call("iptables|ip6tables -t filter -A <chain> <rule> -j <target>", "a rule appended", "Rules in chains",
             used="Make… (an allow where nothing drops after it)", docs=MAN7 + "man8/iptables.8.html", writes=True),
        Call("iptables|ip6tables -t <table> -D <chain> <rule>", "a rule deleted by its words", "Rules in chains", used="Remove…",
             docs=MAN7 + "man8/iptables.8.html", writes=True),
        Call("iptables|ip6tables -t filter -P <chain> <policy>", "a built-in chain's policy", "Policies", used="Set…",
             docs=MAN7 + "man8/iptables.8.html", writes=True),
        Call("netfilter-persistent save", "the rules saved where Debian's boot loads them", "Keeping rules across a restart",
             used="Save on Debian and Ubuntu (it says nothing when it fails)",
             docs=DEBIAN + "netfilter-persistent/netfilter-persistent.8.en.html", writes=True),
        Call("iptables-restore", "a saved table loaded back", "Restoring", docs=MAN7 + "man8/iptables-restore.8.html",
             writes=True),
        Call("iptables -N <chain>", "a user chain made", "User chains", docs=MAN7 + "man8/iptables.8.html", writes=True),
    ),
    verified=VERIFIED,
)

EBTABLES = Api(
    name="ebtables and arptables",
    maker="the netfilter project",
    about=("ebtables filters Ethernet frames crossing a Linux bridge and arptables filters ARP, each in an nf_tables "
           "variant (beside iptables-nft) and a legacy one. The plugin reads only which variant and version each is, for "
           "the Firewall table; it neither lists nor changes their rules."),
    kind="command",
    base="ebtables -V and arptables -V, as root (through sudo -n)",
    version="the nf_tables variants (ebtables-nft, arptables-nft) and the legacy tools alike",
    auth="root, had through sudo without a password",
    limits="",
    costs="",
    links=(
        Link("ebtables", "https://ebtables.netfilter.org/", "docs"),
        Link("ebtables-nft(8)", MAN7 + "man8/ebtables-nft.8.html", "reference"),
        Link("arptables-nft(8)", MAN7 + "man8/arptables-nft.8.html", "reference"),
        Link("ebtables-legacy(8)", DEBIAN + "ebtables/ebtables-legacy.8.en.html", "reference"),
        Link("arptables-legacy(8)", DEBIAN + "arptables/arptables-legacy.8.en.html", "reference"),
    ),
    areas=(
        Area("Their variants and versions", "nf_tables or legacy, and each tool's version", MAN7 + "man8/ebtables-nft.8.html",
             covered="read for the Firewall table"),
        Area("Bridge filtering", "frames crossing a bridge filtered by MAC, protocol, VLAN", MAN7 + "man8/ebtables-nft.8.html"),
        Area("The broute table", "frames routed instead of bridged", DEBIAN + "ebtables/ebtables-legacy.8.en.html"),
        Area("ARP filtering", "ARP packets filtered, mangled", MAN7 + "man8/arptables-nft.8.html"),
    ),
    calls=(
        Call("ebtables -V", "ebtables' version and variant", "Their variants and versions", used="the read",
             docs=MAN7 + "man8/ebtables-nft.8.html"),
        Call("arptables -V", "arptables' version and variant", "Their variants and versions", used="the read",
             docs=MAN7 + "man8/arptables-nft.8.html"),
        Call("ebtables -L", "the bridge's rules", "Bridge filtering", docs=MAN7 + "man8/ebtables-nft.8.html"),
        Call("arptables -L", "the ARP rules", "ARP filtering", docs=MAN7 + "man8/arptables-nft.8.html"),
    ),
    verified=VERIFIED,
)

IPSET = Api(
    name="ipset",
    maker="the netfilter project",
    about=("ipset keeps sets of addresses, networks, ports and their pairs in the kernel, which iptables rules match "
           "against in one step. The plugin lists the sets (their names, types and sizes, never their members) for the "
           "Sets table, and only when the kernel has ip_set loaded: listing them otherwise would load it."),
    kind="command",
    base="ipset, as root (through sudo -n)",
    version="ipset as current distributions ship it (list -t: the headers alone)",
    auth="root, had through sudo without a password",
    limits="",
    costs="",
    links=(
        Link("ipset", "https://ipset.netfilter.org/", "docs"),
        Link("ipset(8)", "https://ipset.netfilter.org/ipset.man.html", "reference"),
        Link("The ipset project", "https://www.netfilter.org/projects/ipset/", "tool"),
    ),
    areas=(
        Area("Listing sets", "each set's header and, without -t, its members", "https://ipset.netfilter.org/ipset.man.html",
             covered="every set's name, type and size, members left out (-t)"),
        Area("Making and removing sets", "sets created, destroyed, renamed, swapped", "https://ipset.netfilter.org/ipset.man.html"),
        Area("Members", "entries added, deleted, tested", "https://ipset.netfilter.org/ipset.man.html"),
        Area("Saving and restoring", "every set written out and read back", "https://ipset.netfilter.org/ipset.man.html"),
    ),
    calls=(
        Call("ipset -v", "ipset's version", "Listing sets", used="the read", docs="https://ipset.netfilter.org/ipset.man.html"),
        Call("ipset list -t", "every set's header, no members", "Listing sets", used="the read, when ip_set is loaded",
             docs="https://ipset.netfilter.org/ipset.man.html"),
        Call("ipset create <set> <type>", "a set made", "Making and removing sets", docs="https://ipset.netfilter.org/ipset.man.html",
             writes=True),
        Call("ipset add <set> <entry>", "an entry added", "Members", docs="https://ipset.netfilter.org/ipset.man.html", writes=True),
        Call("ipset save", "every set written out", "Saving and restoring", docs="https://ipset.netfilter.org/ipset.man.html"),
    ),
    verified=VERIFIED,
)

FIREWALLD_API = Api(
    name="firewalld",
    maker="the firewalld project",
    about=("firewalld, the default firewall manager of RHEL, Fedora, SUSE and openSUSE: interfaces and sources bound to "
           "zones, each zone "
           "letting in services, ports and rich rules, policies between zones, and a runtime beside the permanent "
           "configuration, with nftables (or iptables) beneath it. The plugin reads every zone and policy, makes Liminal's "
           "rules as firewalld services, removes rules, sets a zone's target, and turns firewalld on or off."),
    kind="command",
    base="firewall-cmd while the daemon runs, firewall-offline-cmd while it is stopped; as root (through sudo -n)",
    version="firewalld 2 (from 2.4.3 firewall-cmd waits for D-Bus when the daemon is stopped: the offline tool is used then)",
    auth="root, had through sudo without a password",
    limits="",
    costs="",
    links=(
        Link("firewalld's documentation", FIREWALLD, "docs"),
        Link("firewall-cmd(1)", FIREWALLD + "man-pages/firewall-cmd.html", "reference"),
        Link("firewall-offline-cmd(1)", FIREWALLD + "man-pages/firewall-offline-cmd.html", "reference"),
        Link("firewalld.zones(5)", FIREWALLD + "man-pages/firewalld.zones.html", "reference"),
        Link("firewalld.policies(5)", FIREWALLD + "man-pages/firewalld.policies.html", "reference"),
        Link("firewalld.richlanguage(5)", FIREWALLD + "man-pages/firewalld.richlanguage.html", "reference"),
        Link("Concepts", FIREWALLD + "concepts.html", "guide"),
        Link("firewalld's releases", "https://github.com/firewalld/firewalld/releases", "changelog"),
        Link("firewalld's source", "https://github.com/firewalld/firewalld", "source"),
    ),
    areas=(
        Area("Its state", "whether the daemon runs, its version, its backend", FIREWALLD + "man-pages/firewall-cmd.html",
             covered="asked of the service first (a stopped daemon is read offline)"),
        Area("Zones", "interfaces and sources bound to zones, each with its target, services, ports and rich rules",
             FIREWALLD + "man-pages/firewalld.zones.html",
             covered="every zone read; the default zone takes the interfaces bound to none; a zone's target set"),
        Area("Policies", "rules for traffic between zones, out and forwarded", FIREWALLD + "man-pages/firewalld.policies.html",
             covered="every policy read; one not in force shown turned off"),
        Area("Services", "named sets of ports and protocols", FIREWALLD + "service/",
             covered="the zones' services' ports read; Liminal's rules made as services liminal-<name>"),
        Area("Rich rules", "rules by source, port, service, with log and limits", FIREWALLD + "man-pages/firewalld.richlanguage.html",
             covered="a rule from one address or network, or a block, made as a rich rule"),
        Area("Runtime and permanent", "the running configuration and the one kept across a reload", FIREWALLD + "concepts.html",
             covered="each change made permanent, then reloaded (offline: the permanent one alone)"),
        Area("Its configuration", "firewalld.conf: the default zone, the backend", FIREWALLD + "man-pages/firewalld.conf.html",
             covered="FirewallBackend and DefaultZone read"),
        Area("Direct rules and lockdown", "passthrough rules and who may change the firewall", FIREWALLD + "man-pages/firewall-cmd.html"),
    ),
    calls=(
        Call("firewall-cmd --state", "whether the daemon runs", "Its state", used="the read",
             docs=FIREWALLD + "man-pages/firewall-cmd.html"),
        Call("firewall-cmd --version", "its version", "Its state", used="the read (firewall-offline-cmd when stopped)",
             docs=FIREWALLD + "man-pages/firewall-cmd.html"),
        Call("firewall-cmd --get-default-zone", "the default zone", "Zones", used="the read",
             docs=FIREWALLD + "man-pages/firewall-cmd.html"),
        Call("firewall-cmd --list-all-zones", "every zone and all it holds", "Zones", used="the read",
             docs=FIREWALLD + "man-pages/firewall-cmd.html"),
        Call("firewall-cmd --list-all-policies", "every policy and all it holds", "Policies", used="the read",
             docs=FIREWALLD + "man-pages/firewall-cmd.html"),
        Call("firewall-cmd --info-service=<service>", "a service's ports and protocols", "Services",
             used="the read: the ports of each service the zones use", docs=FIREWALLD + "man-pages/firewall-cmd.html"),
        Call("firewall-cmd --permanent --new-service=<service>", "a service made", "Services", used="Make… (liminal-<name>)",
             docs=FIREWALLD + "man-pages/firewall-cmd.html", writes=True),
        Call("firewall-cmd --permanent --service=<service> --set-description=<words>", "what a service is for", "Services",
             used="Make… (the rule in words)", docs=FIREWALLD + "man-pages/firewall-cmd.html", writes=True),
        Call("firewall-cmd --permanent --service=<service> --add-port=<port>/<protocol>", "a port added to a service", "Services",
             used="Make…", docs=FIREWALLD + "man-pages/firewall-cmd.html", writes=True),
        Call("firewall-cmd --permanent --zone=<zone> --add-service=<service>", "a service let into a zone", "Zones",
             used="Make… (an allow from everywhere)", docs=FIREWALLD + "man-pages/firewall-cmd.html", writes=True),
        Call("firewall-cmd --permanent --zone=<zone> --add-rich-rule=<rule>", "a rich rule added to a zone", "Rich rules",
             used="Make… (from an address, or a block)", docs=FIREWALLD + "man-pages/firewalld.richlanguage.html", writes=True),
        Call("firewall-cmd [--permanent] --zone=<zone> --remove-<what>=<value>", "a service, port, source or rich rule taken out",
             "Zones",
             used="Remove… (in the runtime and the permanent configuration)", docs=FIREWALLD + "man-pages/firewall-cmd.html",
             writes=True),
        Call("firewall-cmd --permanent --delete-service=<service>", "a service deleted", "Services",
             used="Remove… of Liminal's", docs=FIREWALLD + "man-pages/firewall-cmd.html", writes=True),
        Call("firewall-cmd --permanent --zone=<zone> --set-target=<target>", "a zone's target set", "Zones", used="Set…",
             docs=FIREWALLD + "man-pages/firewall-cmd.html", writes=True),
        Call("firewall-cmd --reload", "the permanent configuration made the running one", "Runtime and permanent",
             used="after each change while it runs", docs=FIREWALLD + "man-pages/firewall-cmd.html", writes=True),
        Call("firewall-offline-cmd <options>", "the same, on the permanent configuration, while the daemon is stopped",
             "Runtime and permanent", used="the read and every change while it is stopped",
             docs=FIREWALLD + "man-pages/firewall-offline-cmd.html", writes=True),
        Call("firewall-cmd --zone=<zone> --change-interface=<interface>", "an interface bound to a zone", "Zones",
             docs=FIREWALLD + "man-pages/firewall-cmd.html", writes=True),
        Call("firewall-cmd --panic-on", "every packet dropped", "Its state", docs=FIREWALLD + "man-pages/firewall-cmd.html",
             writes=True),
    ),
    verified=VERIFIED,
)

UFW = Api(
    name="ufw",
    maker="Canonical (the Uncomplicated Firewall)",
    about=("ufw, Ubuntu's front end to iptables (and, through iptables-nft, nftables): rules in plain words (allow, "
           "deny, reject, limit a port or a service from somewhere), defaults for what comes in, goes out and is routed, "
           "and application profiles. The plugin reads its state and every rule (also while it is off), makes Liminal's "
           "rules with a comment, removes rules, sets its defaults and turns it on (SSH kept open first) or off."),
    kind="command",
    base="ufw, as root (through sudo -n)",
    version="ufw 0.36.2, Ubuntu's",
    auth="root, had through sudo without a password",
    limits="",
    costs="",
    links=(
        Link("ufw(8)", UFW_MAN, "reference"),
        Link("Firewalls (Ubuntu Server)", "https://ubuntu.com/server/docs/how-to/security/firewalls/", "docs"),
        Link("UFW (Ubuntu's wiki)", "https://wiki.ubuntu.com/UncomplicatedFirewall", "guide"),
        Link("ufw-framework(8)", "https://manpages.ubuntu.com/manpages/resolute/man8/ufw-framework.8.html", "reference"),
        Link("ufw on Launchpad", "https://launchpad.net/ufw", "source"),
    ),
    areas=(
        Area("Its state", "on or off, its logging, its defaults", UFW_MAN, covered="read with every rule"),
        Area("Rules", "allow, deny, reject or limit, in or out, on an interface, from and to, a port or an app", UFW_MAN,
             covered="every rule read, numbered (also while off); Liminal's made with a comment liminal:<name>"),
        Area("Routed rules", "rules for traffic passing through (ufw route)", UFW_MAN, covered="made for forwarded traffic"),
        Area("Deleting", "a rule removed by its number or its words", UFW_MAN, covered="Remove…"),
        Area("Defaults", "what comes in, goes out or is routed when no rule says", UFW_MAN, covered="Set…"),
        Area("On and off", "ufw enabled (at boot too) or disabled", UFW_MAN, covered="turned on (SSH kept open first) or off"),
        Area("Application profiles", "named ports apps declare (ufw app list)", UFW_MAN),
        Area("Logging", "what it logs, and how much", UFW_MAN),
        Area("Its framework", "its own rule files and chains beneath it", "https://manpages.ubuntu.com/manpages/resolute/man8/ufw-framework.8.html",
             covered="its chains in iptables are its machinery: read through ufw, not twice"),
    ),
    calls=(
        Call("ufw version", "its version", "Its state", used="the read", docs=UFW_MAN),
        Call("ufw status verbose", "on or off, logging, defaults, rules", "Its state", used="the read", docs=UFW_MAN),
        Call("ufw status numbered", "the rules, numbered", "Rules", used="the read", docs=UFW_MAN),
        Call("ufw show added", "the rules added, also while it is off", "Rules", used="the read", docs=UFW_MAN),
        Call("ufw allow|deny|reject [route] [in|out] [on <interface>] [proto <p>] from <source> to any [port <ports>] comment <words>",
             "a rule made", "Rules", used="Make…; SSH kept open before ufw is turned on", docs=UFW_MAN, writes=True),
        Call("ufw --force delete <number>", "a rule removed by its number", "Deleting", used="Remove…", docs=UFW_MAN, writes=True),
        Call("ufw --force delete <rule>", "a rule removed by its words (while off)", "Deleting", used="Remove…", docs=UFW_MAN,
             writes=True),
        Call("ufw default <policy> <direction>", "a default set", "Defaults", used="Set…", docs=UFW_MAN, writes=True),
        Call("ufw --force enable", "ufw turned on, and at boot", "On and off", used="Turn on…", docs=UFW_MAN, writes=True),
        Call("ufw disable", "ufw turned off", "On and off", used="Turn off… (asked twice)", docs=UFW_MAN, writes=True),
        Call("ufw limit <port>", "a port let in, too many connections from one address refused", "Rules", docs=UFW_MAN,
             writes=True),
        Call("ufw app list", "the application profiles", "Application profiles", docs=UFW_MAN),
        Call("ufw logging <level>", "how much it logs", "Logging", docs=UFW_MAN, writes=True),
    ),
    verified=VERIFIED,
)

CONNTRACK = Api(
    name="Connection tracking (conntrack)",
    maker="the Linux kernel (netfilter), and the conntrack-tools project",
    about=("The kernel tracks every connection the firewall sees, so a rule can let in the answers to what went out; "
           "its table has a limit, and when it is full new connections are dropped. The plugin reads how many are tracked "
           "and the limit from /proc/sys/net/netfilter, never through netlink (which would load a module); "
           "conntrack-tools' conntrack command lists, watches and deletes the entries."),
    kind="kernel",
    base="/proc/sys/net/netfilter/nf_conntrack_count and nf_conntrack_max",
    version="the nf_conntrack sysctls of current kernels",
    auth="read as root, with the rest of the read; nothing is changed",
    limits="",
    costs="",
    links=(
        Link("Netfilter conntrack sysfs variables", "https://docs.kernel.org/networking/nf_conntrack-sysctl.html", "reference"),
        Link("conntrack-tools", "https://conntrack-tools.netfilter.org/", "docs"),
        Link("The conntrack-tools user manual", "https://conntrack-tools.netfilter.org/manual.html", "guide"),
        Link("conntrack(8)", DEBIAN + "conntrack/conntrack.8.en.html", "reference"),
    ),
    areas=(
        Area("The table's size", "the connections tracked now and the most there may be",
             "https://docs.kernel.org/networking/nf_conntrack-sysctl.html", covered="both read, for the Firewall table"),
        Area("Its settings", "timeouts, helpers, accounting, the hash table", "https://docs.kernel.org/networking/nf_conntrack-sysctl.html"),
        Area("The entries", "each tracked connection listed, watched as it changes, deleted", DEBIAN + "conntrack/conntrack.8.en.html"),
        Area("Keeping state between machines", "conntrackd: the table copied to a standby firewall",
             "https://conntrack-tools.netfilter.org/manual.html"),
    ),
    calls=(
        Call("/proc/sys/net/netfilter/nf_conntrack_count", "the connections tracked now", "The table's size", used="the read",
             docs="https://docs.kernel.org/networking/nf_conntrack-sysctl.html"),
        Call("/proc/sys/net/netfilter/nf_conntrack_max", "the most that may be tracked", "The table's size", used="the read",
             docs="https://docs.kernel.org/networking/nf_conntrack-sysctl.html"),
        Call("conntrack -L", "every tracked connection", "The entries", docs=DEBIAN + "conntrack/conntrack.8.en.html"),
        Call("conntrack -E", "the table's changes as they happen", "The entries", docs=DEBIAN + "conntrack/conntrack.8.en.html"),
        Call("conntrack -D", "tracked connections deleted", "The entries", docs=DEBIAN + "conntrack/conntrack.8.en.html",
             writes=True),
    ),
    verified=VERIFIED,
)

BPF = Api(
    name="eBPF on the network (bpftool)",
    maker="the Linux kernel's BPF maintainers (bpftool)",
    about=("eBPF programs can filter packets without being in any firewall's ruleset: XDP at the network driver, tc at "
           "the traffic control layer, the flow dissector, and netfilter's own BPF links since Linux 6.4. bpftool shows "
           "and manages them. The plugin lists those on the network's hooks (from bpftool and ip), read only, so a "
           "filter outside nftables is never missed."),
    kind="command",
    base="bpftool -j net show, as root (through sudo -n)",
    version="bpftool 7 (7.8.1 the newest), its JSON's flow dissector mended where it is not JSON",
    auth="root (CAP_BPF and CAP_NET_ADMIN), had through sudo without a password",
    limits="",
    costs="",
    links=(
        Link("BPF documentation", "https://docs.kernel.org/bpf/", "docs"),
        Link("bpftool-net(8)", DEBIAN + "bpftool/bpftool-net.8.en.html", "reference"),
        Link("bpftool(8)", DEBIAN + "bpftool/bpftool.8.en.html", "reference"),
        Link("bpftool's releases", "https://github.com/libbpf/bpftool/releases", "changelog"),
        Link("bpftool's source", "https://github.com/libbpf/bpftool", "source"),
        Link("AF_XDP", "https://docs.kernel.org/networking/af_xdp.html", "guide"),
    ),
    areas=(
        Area("Programs on the network's hooks", "XDP, tc (cls_bpf, tcx, netkit), the flow dissector, netfilter links",
             DEBIAN + "bpftool/bpftool-net.8.en.html", covered="listed, read only, beside the interfaces"),
        Area("Programs and maps", "every BPF program and map loaded", DEBIAN + "bpftool/bpftool.8.en.html"),
        Area("Attaching and detaching", "a program attached to an interface's hook, or detached", DEBIAN + "bpftool/bpftool-net.8.en.html"),
        Area("XDP sockets", "packets handed to user space at the driver", "https://docs.kernel.org/networking/af_xdp.html"),
    ),
    calls=(
        Call("bpftool -j net show", "the programs on the network's hooks, as JSON", "Programs on the network's hooks",
             used="the read", docs=DEBIAN + "bpftool/bpftool-net.8.en.html"),
        Call("bpftool prog show", "every program loaded", "Programs and maps", docs=DEBIAN + "bpftool/bpftool.8.en.html"),
        Call("bpftool map show", "every map", "Programs and maps", docs=DEBIAN + "bpftool/bpftool.8.en.html"),
        Call("bpftool net detach <type> dev <interface>", "a program detached", "Attaching and detaching",
             docs=DEBIAN + "bpftool/bpftool-net.8.en.html", writes=True),
    ),
    verified=VERIFIED,
)

IPROUTE2 = Api(
    name="iproute2 (ip and ss)",
    maker="the Linux kernel's networking maintainers (iproute2)",
    about=("iproute2's ip shows and changes the network's interfaces, addresses and routes, and ss the sockets: what "
           "listens on which port, and the connections. The plugin reads the interfaces and their addresses (with any "
           "XDP program on them) and what listens, so it knows a rule's interface, which program a port is for, and "
           "whether a change would cut off SSH (net-tools' netstat where ss is not there)."),
    kind="command",
    base="ip -j addr show and ss, as root (through sudo -n)",
    version="iproute2's ip and ss (BusyBox's ip without JSON on Alpine, read in words)",
    auth="root, so ss can name every socket's program",
    limits="",
    costs="",
    links=(
        Link("ip(8)", MAN7 + "man8/ip.8.html", "docs"),
        Link("ip-address(8)", MAN7 + "man8/ip-address.8.html", "reference"),
        Link("ss(8)", MAN7 + "man8/ss.8.html", "reference"),
        Link("netstat(8)", MAN7 + "man8/netstat.8.html", "reference"),
        Link("iproute2's source", "https://git.kernel.org/pub/scm/network/iproute2/iproute2.git", "source"),
    ),
    areas=(
        Area("Interfaces and addresses", "each interface, its state, its addresses, its bridge or bond, its XDP program",
             MAN7 + "man8/ip-address.8.html", covered="read for the Interfaces table and firewalld's zones"),
        Area("Sockets", "what listens on which port, and the connections", MAN7 + "man8/ss.8.html",
             covered="the TCP and UDP listeners (a rule's program), SSH's port and sessions (what a change must not cut)"),
        Area("Routes", "the routing tables and rules", MAN7 + "man8/ip.8.html"),
        Area("Links", "interfaces made, changed, brought up and down", MAN7 + "man8/ip.8.html"),
    ),
    calls=(
        Call("ip -j addr show", "every interface and its addresses, as JSON", "Interfaces and addresses", used="the read",
             docs=MAN7 + "man8/ip-address.8.html"),
        Call("ip addr show", "the same, in words", "Interfaces and addresses", used="the read, where ip has no JSON (BusyBox)",
             docs=MAN7 + "man8/ip-address.8.html"),
        Call("ss -ltnpH", "the TCP listeners and their programs", "Sockets", used="the read", docs=MAN7 + "man8/ss.8.html"),
        Call("ss -lunpH", "the UDP listeners and their programs", "Sockets", used="the read", docs=MAN7 + "man8/ss.8.html"),
        Call("ss -tnH state established", "the established TCP connections", "Sockets", used="the read: SSH's sessions",
             docs=MAN7 + "man8/ss.8.html"),
        Call("netstat -ltnp", "the TCP listeners (net-tools)", "Sockets", used="the read, where ss is not there",
             docs=MAN7 + "man8/netstat.8.html"),
        Call("netstat -lunp", "the UDP listeners (net-tools)", "Sockets", used="the read, where ss is not there",
             docs=MAN7 + "man8/netstat.8.html"),
        Call("ip route show", "the routes", "Routes", docs=MAN7 + "man8/ip.8.html"),
        Call("ip link set <interface> up|down", "an interface brought up or down", "Links", docs=MAN7 + "man8/ip.8.html", writes=True),
    ),
    verified=VERIFIED,
)

SERVICES = Api(
    name="The firewall's services (systemd, OpenRC, SysV)",
    maker="the systemd and OpenRC projects, and the distributions' SysV scripts",
    about=("The init system starts the firewall at boot: the nftables service loading its file, iptables' and ip6tables' "
           "(or Debian's netfilter-persistent), ipset's, firewalld, ufw, and Gentoo's nftables-store and -restore. The "
           "plugin reads which of them are there, running and on at boot, under systemd, OpenRC or SysV scripts, turns "
           "one on or off (and at boot), and runs the distribution's own save where it has one."),
    kind="command",
    base="systemctl, rc-service and rc-update, or service, as root (through sudo -n)",
    version="systemd, OpenRC or SysV scripts, as the machine runs",
    auth="root, had through sudo without a password",
    limits="",
    costs="",
    links=(
        Link("systemctl(1)", SYSTEMD + "systemctl.html", "reference"),
        Link("rc-service(8)", OPENRC + "man/rc-service.8", "reference"),
        Link("rc-update(8)", OPENRC + "man/rc-update.8", "reference"),
        Link("service(8)", "https://manpages.ubuntu.com/manpages/resolute/man8/service.8.html", "reference"),
        Link("systemd's manual pages", SYSTEMD, "docs"),
        Link("OpenRC's user guide", OPENRC + "user-guide.md", "guide"),
        Link("nftables on Gentoo", "https://wiki.gentoo.org/wiki/Nftables", "guide"),
    ),
    areas=(
        Area("Which services are there", "each firewall service known to the init, running or not, on at boot or not",
             SYSTEMD + "systemctl.html", covered="read for the Firewall table, under systemd, OpenRC or SysV scripts"),
        Area("On and off", "a service started and enabled at boot, or stopped and disabled", SYSTEMD + "systemctl.html",
             covered="Turn on… and Turn off… (a stop that flushes others' rules asked twice)"),
        Area("The distribution's own save", "a service's save action (Gentoo's, Alpine's) or its store unit",
             "https://wiki.gentoo.org/wiki/Nftables", covered="Save, where the distribution has one"),
        Area("Runlevels", "OpenRC's boot and default runlevels", OPENRC + "man/rc-update.8",
             covered="whether a service starts at boot (/etc/runlevels)"),
        Area("Masking", "a unit nothing can start, not even by hand", SYSTEMD + "systemctl.html"),
        Area("SysV scripts at boot", "a script's links in the runlevels (update-rc.d)",
             DEBIAN + "init-system-helpers/update-rc.d.8.en.html"),
    ),
    calls=(
        Call("systemctl cat <service>.service", "whether systemd knows the service", "Which services are there", used="the read",
             docs=SYSTEMD + "systemctl.html"),
        Call("systemctl is-active <service>.service", "whether it runs", "Which services are there", used="the read",
             docs=SYSTEMD + "systemctl.html"),
        Call("systemctl is-enabled <service>.service", "whether it starts at boot", "Which services are there", used="the read",
             docs=SYSTEMD + "systemctl.html"),
        Call("systemctl enable --now <service>", "a service started and on at boot", "On and off", used="Turn on…",
             docs=SYSTEMD + "systemctl.html", writes=True),
        Call("systemctl disable --now <service>", "a service stopped and off at boot", "On and off", used="Turn off…",
             docs=SYSTEMD + "systemctl.html", writes=True),
        Call("systemctl start <service>-store.service", "Gentoo's store unit run: the rules saved", "The distribution's own save",
             used="Save on Gentoo with systemd", docs=SYSTEMD + "systemctl.html", writes=True),
        Call("rc-service <service> status", "whether an OpenRC service runs", "Which services are there", used="the read",
             docs=OPENRC + "man/rc-service.8"),
        Call("rc-service <service> start", "an OpenRC service started", "On and off", used="Turn on…",
             docs=OPENRC + "man/rc-service.8", writes=True),
        Call("rc-service <service> stop", "an OpenRC service stopped", "On and off", used="Turn off…",
             docs=OPENRC + "man/rc-service.8", writes=True),
        Call("rc-service <service> save", "the rules saved by the service", "The distribution's own save",
             used="Save on Gentoo and Alpine with OpenRC", docs=OPENRC + "man/rc-service.8", writes=True),
        Call("rc-update add <service> default", "a service on at boot", "Runlevels", used="Turn on…",
             docs=OPENRC + "man/rc-update.8", writes=True),
        Call("rc-update del <service> default", "a service off at boot", "Runlevels", used="Turn off…",
             docs=OPENRC + "man/rc-update.8", writes=True),
        Call("service <service> start|stop", "a SysV service started or stopped", "On and off",
             used="Turn on… and Turn off…, without systemd or OpenRC",
             docs="https://manpages.ubuntu.com/manpages/resolute/man8/service.8.html", writes=True),
        Call("systemctl mask <service>", "a service nothing can start", "Masking", docs=SYSTEMD + "systemctl.html",
             writes=True),
        Call("update-rc.d <service> defaults", "a SysV script started at boot", "SysV scripts at boot",
             docs=DEBIAN + "init-system-helpers/update-rc.d.8.en.html", writes=True),
    ),
    verified=VERIFIED,
)

SUDO = Api(
    name="sudo",
    maker="the sudo project",
    about=("sudo runs a command as root, as the sudoers policy allows. The firewall is read and changed as root: the "
           "plugin runs its read and each change through sudo -n when the platform is not root, so where sudo would ask "
           "for a password the command fails at once, and the page says the firewall cannot be read."),
    kind="command",
    base="sudo -n <command>",
    version="sudo 1.9 (its -n, --non-interactive)",
    auth="the platform's user, as /etc/sudoers allows: no password, or nothing is read or changed",
    limits="",
    costs="",
    links=(
        Link("sudo(8)", "https://www.sudo.ws/docs/man/sudo.man/", "reference"),
        Link("sudoers(5)", "https://www.sudo.ws/docs/man/sudoers.man/", "reference"),
        Link("sudo", "https://www.sudo.ws/", "docs"),
        Link("sudo's changes", "https://www.sudo.ws/releases/changelog/", "changelog"),
    ),
    areas=(
        Area("Running as root", "a command run as root, refused at once where a password would be asked",
             "https://www.sudo.ws/docs/man/sudo.man/", covered="the read and every change, through sudo -n"),
        Area("The policy", "who may run what as whom", "https://www.sudo.ws/docs/man/sudoers.man/",
             covered="the plugin's rights come from it: no password, or no read"),
        Area("Asking what is allowed", "the commands the user may run (sudo -l)", "https://www.sudo.ws/docs/man/sudo.man/"),
    ),
    calls=(
        Call("sudo -n sh -c <script>", "a shell script as root, never asking a password", "Running as root",
             used="the read (one script); a saved file written whole", docs="https://www.sudo.ws/docs/man/sudo.man/"),
        Call("sudo -n <command>", "a command as root, never asking a password", "Running as root", used="each change",
             docs="https://www.sudo.ws/docs/man/sudo.man/", writes=True),
        Call("sudo -l", "what the user may run", "Asking what is allowed", docs="https://www.sudo.ws/docs/man/sudo.man/"),
    ),
    verified=VERIFIED,
)

APIS = (NFTABLES, IPTABLES, EBTABLES, IPSET, FIREWALLD_API, UFW, CONNTRACK, BPF, IPROUTE2, SERVICES, SUDO)


def ago(when: float) -> str:
    s = max(0.0, time.time() - when)
    return f"{s:.0f} s ago" if s < 90 else f"{s / 60:.0f} min ago" if s < 5400 else f"{s / 3600:.0f} h ago"


def facts(plugin) -> dict[str, dict[str, str]]:
    """What the last read found of its APIs, asking nothing (a read under way is not waited for): each tool's version
    and what it holds, the connections tracked, the programs on the network's hooks, the machine read and when."""
    kept = getattr(plugin, "_read", None)  # (when, Config): the last read, kept READ_S
    if not kept:
        return {}
    cfg = kept[1]
    out: dict[str, dict[str, str]] = {}
    tools = cfg.tools or {}
    sysm = cfg.system
    if cfg.nft is not None or "nft" in tools:
        tables = cfg.nft.tables if cfg.nft is not None else []
        dormant = len(cfg.dormant_tables()) if cfg.nft is not None else 0
        out[NFTABLES.name] = {"nft": cfg.nft_version or "version not read",
                              "Tables": f"{len(tables)}" + (f" ({dormant} turned off)" if dormant else "")}
    if cfg.iptables_version or cfg.saved:
        out[IPTABLES.name] = {"iptables": f"{cfg.iptables_version or '?'} ({cfg.iptables_variant or 'variant not said'})",
                              "Legacy tables loaded": ", ".join(sorted(cfg.legacy)) or "none"}
    eb, arp = cfg.ebtables, cfg.arptables
    if eb[0] or arp[0]:
        out[EBTABLES.name] = {k: f"{v} ({variant})" if variant else v for k, (v, variant) in
                              (("ebtables", eb), ("arptables", arp)) if v}
    if cfg.ipset_version or "ipset" in tools:
        out[IPSET.name] = {"ipset": cfg.ipset_version or "version not read", "Sets": str(len(cfg.ipsets))}
    f = cfg.firewalld
    if f.installed:
        out[FIREWALLD_API.name] = {"firewalld": (f.version or "version not read") + (", running" if f.running else ", stopped"),
                                   "Backend": f.backend or "not said", "Default zone": f.default_zone or "not said"}
    u = cfg.ufw
    if u.installed:
        out[UFW.name] = {"ufw": (u.version or "version not read") + (", on" if u.active else ", off")}
    count, most = sysm.conntrack
    if count is not None:
        out[CONNTRACK.name] = {"Tracked": f"{count:,} of {most:,}"}
    if "bpftool" in tools:
        out[BPF.name] = {"Programs on the network's hooks": str(len(sysm.bpf))}
    out[SERVICES.name] = {"Read": f"{sysm.name}, kernel {sysm.kernel or '?'}, {sysm.init_words}, {ago(cfg.at)}"}
    if cfg.problems:
        out[SERVICES.name]["Not read"] = "; ".join(cfg.problems)
    return out
