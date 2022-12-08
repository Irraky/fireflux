import xml.etree.ElementTree as ET
import csv

# parse the XML file using ElementTree
tree = ET.parse('config-pfSense.home.arpa-20221208151732.xml')
root = tree.getroot()

# iterate over the firewall rules in the XML file
for rule in root.findall('./filter/'):
    try:
        src = rule.find('source').find('network').text
        dst = rule.find('destination').find('network').text
        protocol = rule.find('protocol').text
        port = rule.find('source').find('port').text
        print("rule")
        print("\t"+src)
        print("\t"+dst)
        print("\t"+protocol)
    except:
        pass