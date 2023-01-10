from enum import Enum
from pydantic import BaseModel
import json
import csv
from io import TextIOWrapper
from typing import Iterable


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
    """Ip range filter"""

    # TODO improve
    inverted: bool
    address: str | None

    def to_str(self) -> str:
        inverted = "!" if self.inverted else ""
        address = self.address if self.address != None else "*"
        return f"{inverted}{address}"

    @staticmethod
    def from_str(value):
        inverted = False
        if value.startswith('!'):
            inverted = True
            value = value[1:]
        value if value != "*" else None
        return NetworkFilter(inverted=inverted, address=value)


class PortRange(BaseModel):
    """Port range filter"""

    range: str | None

    def to_str(self) -> str:
        return self.range if self.range != None else "*"

    @staticmethod
    def from_str(value):
        return PortRange(range=value if value != "*" else None)


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
    dict.source = dict.source.to_str();
    dict.destination = dict.destination.to_str();
    dict.source_ports = dict.source_ports.to_str();
    dict.destination_port = dict.destination_port.to_str();
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
    return list(map(lambda dict: Rule.parse_obj(__ugly_hack2(dict)), csv.DictReader(src)))
