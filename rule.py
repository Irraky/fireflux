class Rule :  

    def __init__(self,src,dst,protocol,port_src, port_dst):
        self.parse_success = False 
        self.src = src
        self.dst = dst
        self.protocol = protocol
        self.port_src = port_src
        self.port_dst = port_dst
    
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

    #Display the informations
    def __str__(self):
        return f"SRC : {self.src} ; DST : {self.dst} ; PROTOCOL : {self.protocol} ; PORT_SRC : {self.port_src} ; PORT_DST : {self.port_dst}"