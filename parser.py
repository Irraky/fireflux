import csv


class Parser:

    def __init__(self):
        self.parse_success = False
        self.rules = []

    def parse(self, xml):
        pass

    def get_rules(self):
        pass

    def get_success(self):
        return self.parse_success

    def get_rules_list(self):
        return [r.to_string() for r in self.rules]

    def write_csv(self, filename):
        with open("./resources/" + filename, "w") as f:
            f.write("SRC;DST;PROTOCOL;SOURCE PORT;DESTINATION PORT\n")
            for r in self.get_rules_list_as_csv():
                f.write(r + "\n")

    def get_rules_list_as_csv(self):
        return [r.get_csv_rule() for r in self.rules]

    def __str__(self):
        pass
