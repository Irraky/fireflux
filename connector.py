class Connector :  

    def __init__(self, credential):
        self.credential = credential
        self.login_success = False 
    
    #Connect to the interface
    def login(self):
        pass
    
    #Retrive the firewall information
    def retrieve(self):
        pass

    def get_login_success(self):
        return login_success

    #Display the informations
    def __str__(self):
        pass
