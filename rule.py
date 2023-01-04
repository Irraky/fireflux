import json


class Rule:

    def __init__(self, src, dst, protocol, port_src, port_dst):
        self.parse_success = False
        self.src = src
        self.dst = dst
        self.protocol = protocol

        with open('resources/ports.json', 'r') as f:
            self.ports = json.load(f)

        self.port_src = port_src
        self.service_src = self.find_service(port_src, protocol)
        self.port_dst = port_dst
        self.service_dst = self.find_service(port_dst, protocol)

    def get_protocol(self):
        return self.protocol

    def get_src(self):
        return self.src

    def get_dst(self):
        return self.dst

    def get_port_src(self):
        return self.port_src

    def get_port_dst(self):
        return self.port_dst

    def find_service(self, port, protocol):
        try:
            name = port + "/" + protocol
            service = self.ports[name]
            return service['name']
        except:
            return None

    def __str__(self):
        """
        Display the information
        :return:
        """
        return f"SRC:{self.src};DST:{self.dst};PROTOCOL:{self.protocol};PORT_SRC:{self.port_src};PORT_DST:" \
               f"{self.port_dst}"

    def to_string(self):
        return f"SRC:{self.src};DST:{self.dst};PROTOCOL:{self.protocol};PORT_SRC:{self.port_src};PORT_DST:" \
               f"{self.port_dst}"

    def get_csv_rule(self):
        return f"{self.src};{self.dst};{self.protocol};{self.port_src};{self.port_dst}"
