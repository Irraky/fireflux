from click.testing import CliRunner
from cli import cli
import tempfile
import os

runner = CliRunner()


def call(args):
    result = runner.invoke(cli, args)
    if result.exit_code != 0:
        exit(f"FAILURE: python3 cli.py {' '.join(args)}")


def filecmp(a, b):
    with open(a, "r") as a:
        with open(b, "r") as b:
            a = a.read()
            b = b.read()
            assert a == b


def routine(rule: str, endpoint: str):
    print(f"Test: {rule}")
    with tempfile.TemporaryDirectory() as dir:
        out_csv = os.path.join(dir, "out.csv")
        out_json = os.path.join(dir, "out.json")
        print("rule > endpoint")
        call([rule, endpoint])
        print("endpoint > json")
        call([endpoint, out_json])
        print("json > endpoint")
        call([out_json, endpoint])
        print("endpoint > csv")
        call([endpoint, out_csv])
        print("rule == csv")
        filecmp(rule, out_csv)
        print("csv > json")
        call([out_csv, out_json])
        print("json > csv")
        call([out_json, out_csv])
        print("rule == csv")
        filecmp(rule, out_csv)
    pass


endpoint = "http://admin:pfsense@10.37.129.2"
routine("resources/full.csv", endpoint)
routine("resources/empty.csv", endpoint)
