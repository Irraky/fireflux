from base64 import b64decode
import os
import sys
import tempfile
from typing import Iterable
import click
import pfsense
import opnsense
import common
import getpass

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
        print(f"Pushed {len(rules)} rules")


def parseHttpEndpoint(str: str) -> tuple[str, str, str, str] | None:
    """Extract username, password and host from an http endpoint, return None if not an url"""
    url = urlparse(str)
    if not url.netloc:
        return None
    if not "+" in url.scheme:
        exit(
            f"Incomplete scheme got '{url.scheme}' expect 'FIREWALL_NAME+HTTP_SCHEME' like 'pfsense+http'"
        )
    if "@" in url.netloc:
        [auth, host] = url.netloc.split("@", 1)
        try:
            decoded = b64decode(auth).decode()
            [user, pswd] = decoded.split(":", 1)
        except:
            exit(
                f"Malformed auth token '{auth}' expected RFC7617 Basic HTTP Authentication Scheme"
            )
    else:
        host = url.netloc
        if sys.stdin.isatty():
            print(f"Auth for {str}")
            user = input("Username: ")
            pswd = getpass.getpass("Password: ")
        else:
            user = sys.stdin.readline().rstrip()
            pswd = sys.stdin.readline().rstrip()
    [scheme, http] = url.scheme.split("+", 1)
    return (f"{http}://{host}/", scheme, user, pswd)


def pull(src: str) -> list[common.Rule]:
    """Pull rules from file or http endpoints"""
    httpEndpoint = parseHttpEndpoint(src)
    if httpEndpoint is not None:
        [url, scheme, username, password] = httpEndpoint
        if scheme == "opnsense":
            return opnsense.pull(url, username, password)
        elif scheme == "pfsense":
            return pfsense.pull(url, username, password)
        else:
            exit(f"Unknown firewall scheme '{scheme}' support opnsense and pfsense")
    else:
        if src.endswith(".json"):
            with open(src, "r") as f:
                return common.rules_from_json(f)
        elif src.endswith(".csv"):
            with open(src, "r") as f:
                return common.rules_from_csv(f)
        else:
            exit(f"Unsupported file format '{src}'")


def push(dst: str, rules: list[common.Rule]):
    """Push rules to file or http endpoints"""
    httpEndpoint = parseHttpEndpoint(dst)
    if httpEndpoint is not None:
        [url, scheme, username, password] = httpEndpoint
        if scheme == "opnsense":
            return opnsense.push(url, username, password, rules)
        elif scheme == "pfsense":
            return pfsense.push(url, username, password, rules)
        else:
            exit(f"Unknown firewall scheme '{scheme}' support opnsense and pfsense")
    else:
        if dst.endswith(".json"):
            with open(dst, "w") as f:
                common.rules_to_json(f, rules)
        elif dst.endswith(".csv"):
            with open(dst, "w") as f:
                common.rules_to_csv(f, rules)
        elif dst.endswith(".xlsx"):
            common.rules_to_excel(dst, rules)
        else:
            sys.exit(f"Unsupported file format '{dst}'")


def visualize(rules: list[common.Rule]):
    """Visualize firewall rules using a flow matrix"""
    with tempfile.TemporaryDirectory() as dir:
        path = os.path.join(dir, "out.xlsx")
        common.rules_to_excel(path, rules)
        common.visualize(path)



if __name__ == "__main__":
    cli()
