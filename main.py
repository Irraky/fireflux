from cred_reader import Cred_Reader
from connector_pfsense import Connector_PfSense
from parser_pfsense import Parser_PfSense

#GET CREDENTIALS
reader = Cred_Reader("credentials")
reader.read()

#print(reader.get_success())
credentials = reader.get_credentials()

#CONNECT TO THE FIREWALL
pfsense = Connector_PfSense(credentials[0])
pfsense.connect()

#print(pfsense.get_login_success())
#print(pfsense)

#RETRIVE BACKUP FILE
backup = pfsense.retrieve()

#PARSE THE BACKUP XML
parser = Parser_PfSense()
parser.parse(backup)

#print(parser.get_success())
#print(parser.get_rules()[0])

#BUILD THE MATRIX
