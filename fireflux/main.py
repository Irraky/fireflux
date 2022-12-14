import pfsense

url = "http://172.16.143.2/"
username = "admin"
password = "pfsense"

data = pfsense.extract(url, username, password)
print(data)