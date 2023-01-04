from abc import ABC, abstractmethod


class Connector(ABC):

    def __init__(self, credential):
        self.credential = credential
        self.login_success = False

    @abstractmethod
    def login(self):
        """
        Connect to the interface
        """
        pass

    @abstractmethod
    def retrieve(self):
        """
        Retrieve the firewall information
        """
        pass

    @abstractmethod
    def get_login_success(self):
        pass

    @abstractmethod
    def get_credential(self):
        pass

    @abstractmethod
    def __str__(self):
        """
        Display the information
        """
        pass
