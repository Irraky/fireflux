import pfsense

url = "http://192.168.140.250"
username = "admin"
password = "pfsense"

data = pfsense.extract(url, username, password)