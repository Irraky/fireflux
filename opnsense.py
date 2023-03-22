# import libraries
import ipaddress
import json
import requests
from common import IpVer, Rule, Action, Protocol, NetworkFilter, PortRange

__ipSenseToRule = {"inet46": IpVer.Both, "inet": IpVer.V4, "inet6": IpVer.V6}
__protocolSenseToRule = {
    "any": None,
    "udp": Protocol.UDP,
    "tcp": Protocol.TCP,
    "tcp/udp": Protocol.TPC_UDP,
    "pfsync": Protocol.PFSYNC,
    "carp": Protocol.CARP,
    "sctp": Protocol.SCTP,
    "ospf": Protocol.OSPF,
    "pim": Protocol.PIM,
    "igmp": Protocol.IGMP,
    "ipv6": Protocol.IPV6,
    "etherip": Protocol.ETHERIP,
    "gre": Protocol.GRE,
    "ah": Protocol.AH,
    "esp": Protocol.ESP,
    "icmp": Protocol.ICMP,
}

__ipRuleToSense = {v: k for k, v in __ipSenseToRule.items()}
__protocolRuleToSense = {v: k for k, v in __protocolSenseToRule.items()}


def __parse_selected(enum: dict) -> str:
    """Parse selection option from OPNsense JSON"""
    return next(k for k, v in enum.items() if v["selected"])


def __parse_network_filter(rule: dict, prefix: str) -> tuple[NetworkFilter, PortRange]:
    """Parse network filter from OPNsense JSON"""
    addr = rule[f"{prefix}_net"]
    try:
        network = ipaddress.ip_network(addr, strict=False)
    except:
        network = addr if addr != "any" else None
    network = NetworkFilter(inverted=rule[f"{prefix}_not"], network=network)
    port = PortRange.from_str(rule[f"{prefix}_port"])
    return (network, port)


def __parse_rule(rule: dict) -> Rule:
    """Parse firewall rule from OPNsense JSON"""
    [source, source_ports] = __parse_network_filter(rule, "source")
    [destination, destination_port] = __parse_network_filter(rule, "destination")
    return Rule(
        description=rule["description"],
        action=Action(__parse_selected(rule["action"])),
        interface=__parse_selected(rule["interface"]),
        ip_ver=__ipSenseToRule[__parse_selected(rule["ipprotocol"])],
        protocol=__protocolSenseToRule[__parse_selected(rule["protocol"]).lower()],
        source=source,
        source_ports=source_ports,
        destination=destination,
        destination_port=destination_port,
    )


def __parse_rules(input: str) -> list[Rule]:
    """Parse firewall rules from OPNsense JSON"""
    rules = json.loads(input)["filter"]["rules"]["rule"]
    if rules != []:
        rules = [v for _, v in rules.items()]
        return [__parse_rule(r) for r in rules if r != None]
    else:
        return []


def __fmt_network_filter(network: NetworkFilter, port: PortRange, prefix: str) -> dict:
    """Parse network filter into OPNsense JSON"""
    port_str = port.to_str()
    return {
        f"{prefix}_net": f"{network.network}" if network.network != None else "any",
        f"{prefix}_not": 1 if network.inverted else 0,
        f"{prefix}_port": port_str if port_str != "*" else "",
    }


def __fmt_rule(rule: Rule) -> dict:
    """Format firewall rule into OPNsense JSON"""
    return (
        {
            "description": rule.description,
            "action": rule.action,
            "interface": rule.interface,
            "ipprotocol": __ipRuleToSense[rule.ip_ver],
            "protocol": __protocolRuleToSense[rule.protocol].upper()
            if rule.protocol != None
            else "any",
        }
        | __fmt_network_filter(rule.source, rule.source_ports, "source")
        | __fmt_network_filter(rule.destination, rule.destination_port, "destination")
    )


def pull(url: str, key: str, secret: str) -> list[Rule]:
    """Extract firewall rules from OPNsense service"""
    r = requests.get(
        f"{url}api/firewall/filter/get",
        auth=(key, secret),
        verify=False,
        timeout=5,
    )
    assert r.status_code == 200
    return __parse_rules(r.text)


def push(url: str, key: str, secret: str, rules: list[Rule]):
    """Apply firewall rules to OPNsense service"""
    # List old rules
    r = requests.post(
        f"{url}api/firewall/filter/searchRule",
        auth=(key, secret),
        verify=False,
        timeout=5,
    )
    assert r.status_code == 200
    old = [r["uuid"] for r in json.loads(r.text)["rows"]]
    # Add new rules
    for r in rules:
        data = {"rule": __fmt_rule(r)}
        r = requests.post(
            f"{url}api/firewall/filter/addRule",
            auth=(key, secret),
            verify=False,
            headers={"Content-type": "application/json"},
            data=json.dumps(data),
            timeout=5,
        )
        assert r.status_code == 200
        assert json.loads(r.text)["result"] == "saved"
    # Delete olds rules
    for uuid in old:
        r = requests.post(
            f"{url}api/firewall/filter/delRule/{uuid}",
            auth=(key, secret),
            verify=False,
            timeout=5,
        )
        assert r.status_code == 200
        assert json.loads(r.text)["result"] == "deleted"
