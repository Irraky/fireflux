from enum import Enum
from pydantic import BaseModel
import json
import csv
import ipaddress
from io import TextIOWrapper
from typing import Iterable, Tuple


# --- https://docs.opnsense.org/manual/firewall.html#the-basics


class Action(str, Enum):
    """Firewall actions"""

    Pass = "pass"
    Block = "block"
    Reject = "reject"


class IpVer(str, Enum):
    """Internet Protocol verions"""

    V4 = "IPv4"
    V6 = "IPv6"
    Both = "IPv4+IPv6"


class Protocol(str, Enum):
    """Network protocols"""

    TCP = "TCP"
    UDP = "UDP"
    TPC_UDP = "TCP/UDP"
    # I added all protocols supported by pfSense bu I am unsure if we can/want to support all of them
    ICMP = "ICMP"
    ESP = "ESP"
    AH = "AH"
    GRE = "GRE"
    EoIP = "EoIP"
    IPV6 = "IPV6"
    IGMP = "IGMP"
    PIM = "PIM"
    OSPF = "OSPF"
    SCTP = "SCTP"
    CARP = "CARP"
    PFSYNC = "PFSYNC"
    ETHERIP = "ETHERIP"


class NetworkFilter(BaseModel):
    """Network filter"""

    inverted: bool
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None

    def to_str(self) -> str:
        inverted = "!" if self.inverted else ""
        address = self.network if self.network != None else "*"
        return f"{inverted}{address}"

    @staticmethod
    def from_str(value):
        inverted = False
        if value.startswith("!"):
            inverted = True
            value = value[1:]
        if value == "*":
            network = None
        else:
            network = ipaddress.ip_network(value)
        return NetworkFilter(inverted=inverted, network=network)


class PortRange(BaseModel):
    """Port range filter"""

    range: int | Tuple[int, int] | None

    def to_str(self) -> str:
        if self.range == None:
            return "*"
        elif type(self.range) is tuple:
            return f"{self.range[0]}-{self.range[1]}"
        else:
            return f"{self.range}"

    @staticmethod
    def from_str(value):
        if value == "*":
            range = None
        else:
            range = list(map(lambda nb: int(nb), value.split("-", 1)))
            if len(range) == 1:
                range = range[0]
            else:
                range = (range[0], range[1])

        return PortRange(range=range)


class Rule(BaseModel):
    """Generic firewall rule"""

    description: str | None
    action: Action
    interface: str  # TODO interface type
    ip_ver: IpVer
    protocol: Protocol | None
    source: NetworkFilter
    source_ports: PortRange
    destination: NetworkFilter
    destination_port: PortRange


# --- Rules serialization


def __ugly_hack(dict):
    dict.source = dict.source.to_str()
    dict.destination = dict.destination.to_str()
    dict.source_ports = dict.source_ports.to_str()
    dict.destination_port = dict.destination_port.to_str()
    return dict.dict()


def __ugly_hack2(dict):
    dict["source"] = NetworkFilter.from_str(dict["source"])
    dict["destination"] = NetworkFilter.from_str(dict["destination"])
    dict["source_ports"] = PortRange.from_str(dict["source_ports"])
    dict["destination_port"] = PortRange.from_str(dict["destination_port"])
    if dict["protocol"] == "":
        dict["protocol"] = None
    return dict


def rules_to_json(dst: TextIOWrapper, rules: Iterable[Rule]):
    """Serialize rules into a JSON stream"""
    json.dump(list(map(lambda r: __ugly_hack(r), rules)), dst)


def rules_from_json(src: TextIOWrapper) -> list[Rule]:
    """Deserialize rules from a JSON stream"""
    return list(map(lambda dict: Rule.parse_obj(__ugly_hack2(dict)), json.load(src)))


def rules_to_csv(dst: TextIOWrapper, rules: Iterable[Rule]):
    """Serialize rules into a CSV stream"""
    fieldnames = list(Rule.schema()["properties"].keys())
    w = csv.DictWriter(dst, fieldnames=fieldnames)
    w.writeheader()
    for r in rules:
        w.writerow(__ugly_hack(r))


def rules_from_csv(src: TextIOWrapper) -> list[Rule]:
    """Deserialize rules from a CSV stream"""
    return list(
        map(lambda dict: Rule.parse_obj(__ugly_hack2(dict)), csv.DictReader(src))
    )
