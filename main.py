from readCredentials import ReadCredentials
from pfsenseConnector import PfsenseConnector
from pfsenseParser import PfsenseParser
import pandas as pd

# GET CREDENTIALS
reader = ReadCredentials("./resources/credentials.txt")
reader.read()

# print(reader.get_success())
credentials = reader.get_credentials()

# CONNECT TO THE FIREWALL
pfsense = PfsenseConnector(credentials[0])
pfsense.connect()

# print(pfsense.get_login_success())
# print(pfsense)

# RETRIVE BACKUP FILE
backup = pfsense.retrieve()

# PARSE THE BACKUP XML
parser = PfsenseParser()
parser.parse(backup)

# print(parser.get_success())
print(parser.get_rules()[0])

# BUILD THE MATRIX
pd.DataFrame(parser.get_rules_list()).to_excel('output.xlsx', header=False, index=False)
