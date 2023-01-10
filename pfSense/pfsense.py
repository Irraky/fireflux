import requests
from lxml import html
import xmltodict
from common import IpVer, Rule, Action, Protocol, NetworkFilter, PortRange


def __login(s, url, username, password):
    """Login for the gicen session"""

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
    network = NetworkFilter(inverted="not" in dict, address=dict.get("address"))
    port = PortRange(range=dict.get("port"))
    return (network, port)

def __parser(input):
    """Parse firewall rules from pfsense backup XML"""
    input = xmltodict.parse(input)
    filters = input["pfsense"]["filter"]["rule"]
    rules = []
    for filter in filters:
        ipprotocol = {"inet46": IpVer.Both, "inet": IpVer.V4, "inet6": IpVer.V6}
        protocol = {
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
        [source, source_ports] = __parse_src_dst(filter["source"])
        [destination, destination_port] = __parse_src_dst(filter["destination"])
        rule = Rule(
            description=filter["descr"],
            action=Action(filter["type"]),
            interface=filter["interface"],
            ip_ver=ipprotocol[filter["ipprotocol"]],
            protocol=protocol[filter.get("protocol", "any")],
            source=source,
            source_ports=source_ports,
            destination=destination,
            destination_port=destination_port,
        )
        rules.append(rule)
    return rules


def extract(url, username, password):
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

    if html.fromstring(r.text).xpath("count(//pfsense)") != 1.0:
        # TODO how to handle error gracefully
        exit(
            "Something went wrong! the returned Content was not a PfSense Configuration File!"
        )
    return __parser(r.text)
