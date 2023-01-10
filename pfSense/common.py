from enum import Enum
import random
from pydantic import BaseModel
import json
import csv
import string
from io import StringIO, TextIOWrapper
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
    Both = "TCP/UDP"


class Rule(BaseModel):
    """Generic firewall rule"""
    description: str | None
    action: Action
    interface: str                          # TODO interface type
    ip_ver: IpVer = IpVer.Both
    protocol: Protocol = Protocol.Both
    source: str                             # TODO ip range type
    source_ports: str                       # TODO port range type
    destination: str                        # TODO ip range type
    destination_port: str                   # TODO port range type

    @staticmethod
    def random():
        return Rule(
            description=rng_str(23),
            action=rng_enum(Action),
            interface=rng_str(8),
            ip_ver=rng_enum(IpVer),
            protocol=rng_enum(Protocol),
            source=rng_str(12),
            source_ports=rng_str(12),
            destination=rng_str(12),
            destination_port=rng_str(12),
        )


# --- Rules serialization

def rules_to_json(dst: TextIOWrapper, rules: Iterable[Rule]):
    """Serialize rules into a JSON stream"""
    json.dump(list(map(lambda r: r.dict(), rules)), dst)


def rules_from_json(src: TextIOWrapper) -> list[Rule]:
    """Deserialize rules from a JSON stream"""
    return list(map(lambda dict: Rule.parse_obj(dict), json.load(src)))


def rules_to_csv(dst: TextIOWrapper, rules: Iterable[Rule]):
    """Serialize rules into a CSV stream"""
    fieldnames = list(Rule.schema()["properties"].keys())
    w = csv.DictWriter(dst, fieldnames=fieldnames)
    w.writeheader()
    for rule in rules:
        w.writerow(rule.dict())

def rules_from_csv(src: TextIOWrapper) -> list[Rule]:
    """Deserialize rules from a CSV stream"""
    return list(map(lambda dict: Rule.parse_obj(dict), csv.DictReader(src)))


# --- Random data generation


def rng_str(len: int) -> str:
    """Generate random string"""
    return ''.join(random.choice(string.ascii_letters) for _ in range(len))


def rng_enum(it):
    """Generate enum variant"""
    return random.choice(list(it))


# --- Serialization test


rules = list(Rule.random() for _ in range(120))
buff = StringIO()
rules_to_json(buff, rules)
buff = StringIO(buff.getvalue())
json_as_rules = rules_from_json(buff)
buff = StringIO()
rules_to_csv(buff, json_as_rules)
buff = StringIO(buff.getvalue())
csv_as_rules = rules_from_csv(buff)
assert (csv_as_rules == rules)
