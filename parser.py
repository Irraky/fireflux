from abc import ABC, abstractmethod


class Parser(ABC):

    def __init__(self):
        self.parse_success = False
        self.rules = []

    @abstractmethod
    def parse(self, xml):
        pass

    def get_rules(self):
        return self.rules

    def get_success(self):
        return self.parse_success

    def get_rules_list(self):
        return [r.to_string() for r in self.rules]

    def write_csv(self, filename):
        with open("./resources/" + filename, "w") as f:
            f.write("SRC;DST;PROTOCOL;SRC PORT;DST PORT\n")
            for r in self.get_rules_list_as_csv():
                f.write(r + "\n")

    def get_rules_list_as_csv(self):
        return [r.get_csv_rule() for r in self.rules]

    @abstractmethod
    def __str__(self):
        pass
