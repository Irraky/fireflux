import xml.etree.ElementTree as Et
from rule import Rule
from parser import Parser


class PfsenseParser(Parser):

    def parse(self, xml):
        tree = Et.fromstring(xml)

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
                self.rules.append(Rule(src, dst, protocol, port_src, port_dst))

            except:
                pass

        if len(self.rules) > 0:
            self.parse_success = True

    # Display the information
    def __str__(self):
        pass
