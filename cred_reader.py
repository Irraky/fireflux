from credential import Credential

class Cred_Reader :  

    def __init__(self, path):
        self.path = path 
        self.creds = []
    
    #Connect to the interface
    def read(self):
        f = open(self.path, "r")
        for line in f:
            data = line.split(";")
            if data[2] == "http":
                ssl = False
            else:
                ssl = True
            self.creds.append(Credential(data[0],data[1],ssl,data[3],data[4]))

    def get_credentials(self):
        return self.creds

"""
EXAMPLE
r = Cred_Reader("credentials")
r.read()
print(r.get_credentials()[0])
"""
