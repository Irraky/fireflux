from click.testing import CliRunner
from cli import cli
import tempfile
import os

runner = CliRunner()


def call(args):
    result = runner.invoke(cli, args)
    if result.exit_code != 0:
        print(f"FAILURE: python3 cli.py {' '.join(args)}")
        exit(result.output)


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

print("## PFsense")
endpoint = "pfsense+http://YWRtaW46cGZzZW5zZQ==@10.37.129.2"
routine("resources/empty.csv", endpoint)
routine("resources/full.csv", endpoint)
print("## OPNsense")
endpoint = "opnsense+http://bzVUREM1bHZEenVJMzNCT09Yb1p2bitGbUJPR3JqVmdPbitQaXQ3SnpySzdVcDlTU0c5eDVDMXUyYnVQOE5aZ0RNc213NXo5SlkyN2hRZys6TFk3WnZMMWVBejFVelFaNU9oSStxRkRxM3VlU1hyMmhZRXJDQUM1SHFSR2ZoMTR2VWlnVWFRTVFUMEpVRXplWi9VYUpITWdoRFlna3hzTnU=@192.168.64.17"
routine("resources/empty.csv", endpoint)
routine("resources/full.csv", endpoint)