import sys
from typing import Iterable, List
import click
import pfsense
import common

from urllib.parse import urlparse


@click.command()
@click.argument("src")
@click.argument("dst", required=False)
def cli(src, dst):
    """Cross platform firewall rules tool"""
    rules = pull(src)
    if dst is None:
        visualize(rules)
    else:
        push(dst, rules)


def parseHttpEndpoint(str: str) -> tuple[str, str, str] | None:
    """Extract username, password and host from an http endpoint, return None if not an url"""
    url = urlparse(str)
    if not url.netloc:
        return None
    [urserinfo, host] = url.netloc.split("@", 1)
    [username, password] = urserinfo.split(":", 1)
    return (f"{url.scheme}://{host}/", username, password)


def pull(src: str) -> List[common.Rule]:
    """Pull rules from file or http endpoints"""
    httpEndpoint = parseHttpEndpoint(src)
    if httpEndpoint != None:
        [url, username, password] = httpEndpoint
        return pfsense.extract(url, username, password)
    else:
        if src.endswith(".json"):
            with open(src, "r") as f:
                return common.rules_from_json(f)
        elif src.endswith(".csv"):
            with open(src, "r") as f:
                return common.rules_from_csv(f)
        else:
            sys.exit(f"Unsupported file format ${src}")


def push(dst: str, rules: List[common.Rule]):
    """Push rules to file or http endpoints"""
    # TODO handle http endpoints
    if dst.endswith(".json"):
        with open(dst, "w") as f:
            common.rules_to_json(f, rules)
    elif dst.endswith(".csv"):
        with open(dst, "w") as f:
            common.rules_to_csv(f, rules)
    else:
        sys.exit(f"Unsupported file format ${dst}")


def visualize(rules: Iterable[common.Rule]):
    """Visualize firewall rules using a flow matrix"""
    # TODO visualization
    print(rules)


if __name__ == "__main__":
    cli()
