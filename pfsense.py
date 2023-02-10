import requests
from lxml import html
import xmltodict
import dicttoxml
import ipaddress
import os
from common import IpVer, Rule, Action, Protocol, NetworkFilter, PortRange


def __login(s, url, username, password):
    """Login for the given session"""

    # Get original token
    r = s.get("%sindex.php" % url, verify=False)
    try:
        token = html.fromstring(r.text).xpath("//input[@name='__csrf_magic']/@value")[0]
    except:
        token = ""
    # Login into Firewall Webinterface
    r = s.post(
        "%sindex.php" % url,
        data={
            "__csrf_magic": token,
            "usernamefld": username,
            "passwordfld": password,
            "login": "Login",
        },
        verify=False,
    )

    # Get new csrf token
    token = html.fromstring(r.text).xpath("//input[@name='__csrf_magic']/@value")[0]
    if html.fromstring(r.text).xpath("//title/text()")[0].startswith("Login"):
        # TODO how to handle error gracefully
        exit("Login was not Successful!")
    return token


def __parse_src_dst(dict):
    addr = dict.get("address")
    network = ipaddress.ip_network(addr, strict=False) if addr != None else None
    network = network if network != None else dict.get("network")
    network = NetworkFilter(inverted="not" in dict, network=network)
    port = PortRange.from_str(dict.get("port", "*"))
    return (network, port)


def __format_src_dst(network: NetworkFilter, port: PortRange):
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


def __parse_filter(filter) -> Rule:
    """Parse firewall rule from pfSense filter"""
    [source, source_ports] = __parse_src_dst(filter["source"])
    [destination, destination_port] = __parse_src_dst(filter["destination"])
    return Rule(
        description=filter["descr"],
        action=Action(filter["type"]),
        interface=filter["interface"],
        ip_ver=__ipSenseToRule[filter["ipprotocol"]],
        protocol=__protocolSenseToRule[filter.get("protocol", "any")],
        source=source,
        source_ports=source_ports,
        destination=destination,
        destination_port=destination_port,
    )


def __parser(input: str) -> list[Rule]:
    return list(
        map(__parse_filter, xmltodict.parse(input)["pfsense"]["filter"]["rule"])
    )


def __format(rule: Rule):
    """Format firewall rule into pfSense filter"""
    protocol = f"<protocol>{__protocolRuleToSense[rule.protocol]}</protocol>" if rule.protocol != None else ""
    return f"""
        <rule>
            <type>{rule.action}</type>
            <interface>{rule.interface}</interface>
            <ipprotocol>{__ipRuleToSense[rule.ip_ver]}</ipprotocol>
            {protocol}
            <source>{__format_src_dst(rule.source, rule.source_ports)}</source>
            <destination>{__format_src_dst(rule.destination, rule.destination_port)}</destination>
            <descr><![CDATA[{rule.description}]]></descr>
        </rule>
    """


def __formatter(rules: list[Rule]) -> str:
    """Format firewall rules into pfSense backup XML"""
    xml = "<filter>"
    for rule in rules:
        xml += __format(rule)
    xml += "</filter>"
    return os.linesep.join([s for s in xml.splitlines() if s.strip()])


def extract(url: str, username: str, password: str) -> list[Rule]:
    """Extract firewall rules from pfsense service"""
    s = requests.session()
    token = __login(s, url, username, password)
    r = s.post(
        "%sdiag_backup.php" % url,
        data={
            "__csrf_magic": token,
            "download": "Download configuration as XML",
            "encrypt_password": "",
            "backuparea": "",
            "donotbackuprrd": "yes",
        },
        verify=False,
    )
    return __parser(r.text)


def apply(url: str, username: str, password: str, rules: list[Rule]):
    """Apply firewall rules from pfsense service"""
    xml = __formatter(rules)

    s = requests.session()
    token = __login(s, url, username, password)

    r = s.post(
        "%sdiag_backup.php" % url,
        data={
            "__csrf_magic": token,
            "restore": "Restore configuration as XML",
            "restorearea": "filter",
            "decrypt": "",
        },
        files={"conffile": ("backup.xml", xml)},
        verify=False,
    )

    if "The configuration area has been restored" not in r.text:
        exit("Something went wrong! failed to upload")
