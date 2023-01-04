class Connector:

    def __init__(self, credential):
        self.credential = credential
        self.login_success = False

    def login(self):
        """
        Connect to the interface
        """
        pass

    def retrieve(self):
        """
        Retrieve the firewall information
        """
        pass

    def get_login_success(self):
        pass

    def get_credential(self):
        pass

    def __str__(self):
        """
        Display the information
        """
        pass
