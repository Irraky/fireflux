import requests
from lxml import html
import xml.etree.ElementTree as ET
import xmltodict
from common import IpVer, Rule, Action


def __login(s, url, username, password):
    """Login for the gicen session"""

    # Get original token
    r = s.get("%sindex.php" % url, verify=False)
    try:
        token = html.fromstring(r.text).xpath(
            '//input[@name=\'__csrf_magic\']/@value')[0]
    except:
        token = ""
    # Login into Firewall Webinterface
    r = s.post("%sindex.php" % url,
               data={
                   "__csrf_magic": token,
                   "usernamefld": username,
                   "passwordfld": password,
                   "login": "Login"
               },
               verify=False)

    # Get new csrf token
    token = html.fromstring(r.text).xpath(
        '//input[@name=\'__csrf_magic\']/@value')[0]
    if html.fromstring(r.text).xpath('//title/text()')[0].startswith("Login"):
        # TODO how to handle error gracefully
        exit("Login was not Successful!")
    return token


def __parser(input):
    """Parse firewall rules from pfsense backup XML"""
    input = xmltodict.parse(input)
    filters = input['pfsense']['filter']['rule']
    rules = []
    for filter in filters:
        ipprotocol = {
            "inet": IpVer.Both,
            "inet4": IpVer.V4,  # TODO check
            "inet6": IpVer.V6
        }
        rule = Rule(
            description=filter['descr'],
            action=Action(filter['type']),
            interface=filter['interface'],
            ip_ver=ipprotocol[filter['ipprotocol']],
            source="TODO any",
            source_ports="TODO",
            destination="TODO any",
            destination_port="TODO")
        rules.append(rule)
    return rules


def extract(url, username, password):
    """Extract firewall rules from pfsense service"""
    s = requests.session()
    token = __login(s, url, username, password)
    r = s.post("%sdiag_backup.php" % url,
               data={
                   "__csrf_magic": token,
                   "download": "Download configuration as XML",
                   "encrypt_password": "",
                   "backuparea": "",
                   "donotbackuprrd": "yes"},
               verify=False)

    if html.fromstring(r.text).xpath('count(//pfsense)') != 1.0:
        # TODO how to handle error gracefully
        exit(
            "Something went wrong! the returned Content was not a PfSense Configuration File!")
    return __parser(r.text)
