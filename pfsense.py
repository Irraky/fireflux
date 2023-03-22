import requests
from lxml import html
import xmltodict
import ipaddress
import os
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
__actionSenseToRule = {
    "Action.Pass": Action.Pass,
    "Action.Block": Action.Block,
    "Action.Reject": Action.Reject,
}
__ipRuleToSense = {v: k for k, v in __ipSenseToRule.items()}
__protocolRuleToSense = {v: k for k, v in __protocolSenseToRule.items()}


def __parse_network_filter(xml: dict) -> tuple[NetworkFilter, PortRange]:
    """Parse network filter from pfSense XML"""
    addr = xml.get("address")
    network = ipaddress.ip_network(addr, strict=False) if addr != None else None
    network = network if network != None else xml.get("network")
    network = NetworkFilter(inverted="not" in xml, network=network)
    port = PortRange.from_str(xml.get("port", "*"))
    return (network, port)


def __parse_rule(xml: dict) -> Rule:
    """Parse firewall rule from pfSense XML"""
    [source, source_ports] = __parse_network_filter(xml["source"])
    [destination, destination_port] = __parse_network_filter(xml["destination"])
    return Rule(
        description=xml["descr"],
        action=__actionSenseToRule[xml["type"]],
        interface=xml["interface"],
        ip_ver=__ipSenseToRule[xml["ipprotocol"]],
        protocol=__protocolSenseToRule[xml.get("protocol", "any")],
        source=source,
        source_ports=source_ports,
        destination=destination,
        destination_port=destination_port,
    )


def __parse_rules(input: str) -> list[Rule]:
    """Parse firewall rules from pfSense XML"""
    rules = xmltodict.parse(input)["pfsense"]["filter"]["rule"]
    if rules != None:
        return [__parse_rule(r) for r in rules if r != None]
    else:
        return []


def __fmt_network_filter(network: NetworkFilter, port: PortRange):
    """Format network filter into pfSense backup XML"""
    xml = ""
    if network.network == None:
        xml += "<any></any>"
    elif isinstance(network.network, str):
        xml = f"<network>{network.network}</network>"
    else:
        xml = f"<address>{network.network}</address>"
    if network.inverted:
        xml += f"<not></not>"
    if port.range != None:
        xml += f"<port>{port.to_str()}</port>"
    return xml


def __fmt_rule(rule: Rule) -> str:
    """Format firewall rule into pfSense backup XML"""
    protocol = (
        f"<protocol>{__protocolRuleToSense[rule.protocol]}</protocol>"
        if rule.protocol != None
        else ""
    )
    return f"""
        <rule>
            <type>{rule.action}</type>
            <interface>{rule.interface}</interface>
            <ipprotocol>{__ipRuleToSense[rule.ip_ver]}</ipprotocol>
            {protocol}
            <source>{__fmt_network_filter(rule.source, rule.source_ports)}</source>
            <destination>{__fmt_network_filter(rule.destination, rule.destination_port)}</destination>
            <descr><![CDATA[{rule.description}]]></descr>
        </rule>
    """


def __fmt_rules(rules: list[Rule]) -> str:
    """Format firewall rules into pfSense backup XML"""
    xml = '<?xml version="1.0"?><filter>'
    for rule in rules:
        xml += __fmt_rule(rule)
    else:
        xml += "<rule></rule>"
    xml += "</filter>"
    return os.linesep.join([s for s in xml.splitlines() if s.strip()])


def __login(s, url, username, password):
    """Login for the given session"""

    # Get original token
    r = s.get(f"{url}index.php", verify=False, timeout=7)
    try:
        token = html.fromstring(r.text).xpath("//input[@name='__csrf_magic']/@value")[0]
    except:
        token = ""
    # Login into Firewall Webinterface
    r = s.post(
        f"{url}index.php",
        data={
            "__csrf_magic": token,
            "usernamefld": username,
            "passwordfld": password,
            "login": "Login",
        },
        verify=False,
        timeout=7,
    )

    # Get new csrf token
    token = html.fromstring(r.text).xpath("//input[@name='__csrf_magic']/@value")[0]
    if html.fromstring(r.text).xpath("//title/text()")[0].startswith("Login"):
        # TODO how to handle error gracefully
        exit("Login was not Successful!")
    return token


def pull(url: str, username: str, password: str) -> list[Rule]:
    """Extract firewall rules from pfsense service"""
    s = requests.session()
    token = __login(s, url, username, password)
    r = s.post(
        f"{url}diag_backup.php",
        data={
            "__csrf_magic": token,
            "download": "Download configuration as XML",
            "encrypt_password": "",
            "backuparea": "",
            "donotbackuprrd": "yes",
        },
        verify=False,
        timeout=7,
    )
    return __parse_rules(r.text)


def push(url: str, username: str, password: str, rules: list[Rule]):
    """Apply firewall rules to pfsense service"""
    xml = __fmt_rules(rules)

    s = requests.session()
    token = __login(s, url, username, password)

    r = s.post(
        f"{url}diag_backup.php",
        data={
            "__csrf_magic": token,
            "restore": "Restore configuration as XML",
            "restorearea": "filter",
            "decrypt": "",
        },
        files={"conffile": ("backup.xml", xml)},
        verify=False,
        timeout=7,
    )

    if "The configuration area has been restored" not in r.text:
        exit("Something went wrong! failed to upload")
