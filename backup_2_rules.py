from parser_pfsense import Parser_PfSense

with open("./backup_pfsense.xml", "r") as f:
  backup = f.read()

parser = Parser_PfSense()
parser.parse(backup)

print(parser.get_rules()[0])