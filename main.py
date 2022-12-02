from enum import Enum
import random
from pydantic import BaseModel
import json
import csv
import string
from io import StringIO
from typing import Iterable


# --- https://docs.opnsense.org/manual/firewall.html#the-basics


class Action(str, Enum):
    """Firewall actions"""
    Pass = "Pass"
    Block = "Block"
    Reject = "Reject"


class IpVer(str, Enum):
    """Internet Protocol verions"""
    V4 = "IPv4"
    V6 = "IPv6"
    All = "All"


class Protocol(str, Enum):
    """Network protocols"""
    TCP = "TCP"
    UDP = "UDP"
    # More ?


class Rule(BaseModel):
    """Generic firewall rule"""
    description: str
    action: Action
    interface: str          # TODO interface type
    ip_ver: IpVer
    protocol: Protocol
    source: str             # TODO ip range type
    source_ports: str       # TODO port range type
    destination: str        # TODO ip range type
    destination_port: str   # TODO port range type

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

def rules_to_json(rules: Iterable[Rule]) -> str:
    """Serialize rules into json string"""
    return json.dumps(list(map(lambda r: r.dict(), rules)))


def rules_from_json(input: str) -> list[Rule]:
    """Deserialize rules into json string"""
    return list(map(lambda dict: Rule.parse_obj(dict), json.loads(input)))


def rules_to_csv(rules: Iterable[Rule]) -> str:
    """Serialize rules into csv string"""
    fieldnames = list(Rule.schema()["properties"].keys())
    buff = StringIO()
    w = csv.DictWriter(buff, fieldnames=fieldnames)
    w.writeheader()
    for rule in rules:
        w.writerow(rule.dict())
    return buff.getvalue()


def rules_from_csv(input: str) -> list[Rule]:
    """Deserialize rules into csv string"""
    return list(map(lambda dict: Rule.parse_obj(dict), csv.DictReader(StringIO(input))))


# --- Random data generation


def rng_str(len) -> str:
    """Generate random string"""
    return ''.join(random.choice(string.ascii_letters) for i in range(len))


def rng_enum(it):
    """Generate enum variant"""
    return random.choice(list(it))


# --- Serialization test


rules = list(Rule.random() for _ in range(120))
rules_as_json = rules_to_json(rules)
json_as_rules = rules_from_json(rules_as_json)
rules_as_csv = rules_to_csv(json_as_rules)
csv_as_rules = rules_from_csv(rules_as_csv)

assert (csv_as_rules == rules)
