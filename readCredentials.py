from credentials import Credential


class ReadCredentials:

    def __init__(self, path):
        self.path = path
        self.parse_success = False
        self.creds = []

    # Connect to the interface
    def read(self):
        f = open(self.path, "r")
        for line in f:
            try:
                data = line.split(";")
                if data[2] == "http":
                    ssl = False
                else:
                    ssl = True
                self.creds.append(Credential(data[0], data[1], ssl, data[3], data[4]))
            except:
                pass
        if len(self.creds) > 0:
            self.parse_success = True

    def get_credentials(self):
        return self.creds

    def get_success(self):
        return self.parse_success
