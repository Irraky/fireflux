class Rule :  

    def __init__(self,src,dest,protocol,port):
        self.parse_success = False 
        self.src = src
        self.dest = dest
        self.protocol = protocol
        self.port = port
    
    def get_protocol(self):
        return self.protocol
    
    def get_src(self):
        return self.src

    def get_dest(self):
        return self.dest

    def get_port(self):
        return self.port

    #Display the informations
    def __str__(self):
        pass