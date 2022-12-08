import xml.etree.ElementTree as ET
from rule import Rule

class Parser_PfSense :  

    def __init__(self):
        self.parse_success = False 
        self.rules = []
    
    def parse(self, xml):
        tree = ET.fromstring(xml)
        
        for rule in tree.findall('./filter/'):
            try:
                src = rule.find('source').find('network').text
                dst = rule.find('destination').find('network').text
                protocol = rule.find('protocol').text
                try:
                    port_src = rule.find('source').find('port').text
                except:
                    port_src = None
                
                try:
                    port_dst = rule.find('destination').find('port').text
                except:
                    port_dst = None
                self.rules.append(Rule(src,dst,protocol,port_src,port_dst))
            except:
                pass
        if len(self.rules) > 0:
            self.parse_success = True

    def get_rules(self):
        return self.rules

    def get_success(self):
        return self.parse_success

    #Display the informations
    def __str__(self):
        pass
