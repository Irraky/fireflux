import click
import pfsense
import common

from urllib.parse import urlparse

class HttpEndpoint:
    url: str
    username: str
    password: str

    def __init__(self, str):
        url = urlparse(str)
        [urserinfo, host] = url.netloc.split("@", 1)
        [username, password] = urserinfo.split(":", 1)
        self.username = username
        self.password = password
        self.url = f"{url.scheme}://{host}/"

    def __str__(self):
        return f"HttpEndpoint: {self.url} {self.username} {self.password}"


@click.command()
@click.argument("src")
@click.argument("dst", required=False)
def cli(src, dst):
    """Cross platform firewall rules tool"""
    src = HttpEndpoint(src)
    rules = pfsense.extract(src.url, src.username, src.password)

    if dst is None:
        # TODO visualization
        print(rules)
    elif dst.endswith(".json"):
        with open(dst, "w") as f:
            f.write(common.rules_to_json(rules))
    else:
        with open(dst, "w") as f:
            f.write(common.rules_to_csv(rules))


if __name__ == "__main__":
    cli()
