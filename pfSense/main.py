import pfsense

url = "http://192.168.1.1/"
username = "admin"
password = "pfsense"

data = pfsense.extract(url, username, password)
print(data)
