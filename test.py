from click.testing import CliRunner
from cli import cli
from base64 import b64encode
import tempfile
import os


class Firewall:
    user: str
    pswd: str
    name: str
    scheme: str
    ip: str

    def __init__(self, name: str, scheme: str, ip: str, user: str, pswd: str):
        self.name = name
        self.scheme = scheme
        self.ip = ip
        self.user = user
        self.pswd = pswd

    def auth_url(self) -> str:
        auth = b64encode(f"{self.user}:{self.pswd}".encode()).decode()
        return f"{self.name}+{self.scheme}://{auth}@{self.ip}"
    
    def url(self) -> str:
        return f"{self.name}+{self.scheme}://{self.ip}"


runner = CliRunner()

def raw_call(args, input = None):
    return runner.invoke(cli, args, input)

def call(args, input = None):
    result = raw_call(args, input)
    if result.exit_code != 0:
        print(f"FAILURE: python3 cli.py {' '.join(args)}")
        exit(f"{result}")


def filecmp(a, b):
    with open(a, "r") as a:
        with open(b, "r") as b:
            a = a.read()
            b = b.read()
            assert a == b


def firewall_routine(rules: str, fw: Firewall):
    print(f"# {rules}")
    url = fw.auth_url()
    with tempfile.TemporaryDirectory() as dir:
        out_csv = os.path.join(dir, "out.csv")
        out_json = os.path.join(dir, "out.json")
        print("rule > firewall")
        call([rules, url])
        print("firewall > json")
        call([url, out_json])
        print("json > firewall")
        call([out_json, url])
        print("firewall > csv")
        call([url, out_csv])
        print("rule == csv")
        filecmp(rules, out_csv)

def file_routine(rules: str):
    print(f"# {rules}")
    with tempfile.TemporaryDirectory() as dir:
        out_csv = os.path.join(dir, "out.csv")
        out_json = os.path.join(dir, "out.json")
        print("rule > json")
        call([rules, out_json])
        print("json > csv")
        call([out_json, out_csv])
        print("rule == csv")
        filecmp(rules, out_csv)


def auth(fw: Firewall):
    print("# auth")
    call([fw.url()], f"{fw.user}\n{fw.pswd}\n")

def err(fw: Firewall):
    print("# err")

    r = raw_call(["img.jpg"])
    assert r.exit_code == 1
    assert r.output == f"Unsupported file format 'img.jpg'\n", r.output

    r = raw_call([fw.auth_url(), "img.png"])
    assert r.exit_code == 1
    assert r.output == f"Unsupported file format 'img.png'\n", r.output

    r = raw_call([f"unknown+{fw.scheme}://{fw.ip}"])
    assert r.exit_code == 1
    assert r.output == f"Unknown firewall scheme 'unknown' support opnsense and pfsense\n", r.output

    r = raw_call([fw.auth_url(), f"unknown+{fw.scheme}://{fw.ip}"])
    assert r.exit_code == 1
    assert r.output == f"Unknown firewall scheme 'unknown' support opnsense and pfsense\n", r.output

    r = raw_call([f"{fw.name}://{fw.ip}"])
    assert r.exit_code == 1
    assert r.output == f"Incomplete scheme got '{fw.name}' expect 'FIREWALL_NAME+HTTP_SCHEME' like 'pfsense+http'\n", r.output

    r = raw_call([f"{fw.name}+{fw.scheme}://12345@{fw.ip}"])
    assert r.exit_code == 1
    assert r.output == f"Malformed auth token '12345' expected RFC7617 Basic HTTP Authentication Scheme\n", r.output

PF_SENSE = Firewall("pfsense", "http", "10.37.129.2", "admin", "pfsense")
OPN_SENSE = Firewall(
    "opnsense",
    "http",
    "192.168.64.17",
    "o5TDC5lvDzuI33BOOXoZvn+FmBOGrjVgOn+Pit7JzrK7Up9SSG9x5C1u2buP8NZgDMsmw5z9JY27hQg+",
    "LY7ZvL1eAz1UzQZ5OhI+qFDq3ueSXr2hYErCAC5HqRGfh14vUigUaQMQT0JUEzeZ/UaJHMghDYgkxsNu",
)


fixtures = ["resources/empty.csv", "resources/full.csv"]
for rules in fixtures:
    file_routine(rules)
print()
for fw in [PF_SENSE, OPN_SENSE]:
    print(f"## {fw.name} - {fw.auth_url()}")
    auth(fw)
    for rules in fixtures:
        firewall_routine(rules, fw)
    err(fw)
    print()