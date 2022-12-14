import requests
from lxml import html


def csrf_token(url, username, password):
    """Get magic token to access the api"""

    # Get original token
    r = requests.get("%sindex.php" % url, verify=False)
    try:
        token = html.fromstring(r.text).xpath(
            '//input[@name=\'__csrf_magic\']/@value')[0]
    except:
        token = ""
    # Login into Firewall Webinterface
    r = requests.post("%sindex.php" % url,
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


def extract(url, username, password):
    token = csrf_token(url, username, password)
    r = requests.post("%sdiag_backup.php" % url,
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
    # TODO parsing here
    return r.text
