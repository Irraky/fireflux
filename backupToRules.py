from pfsenseParser import PfsenseParser
import pandas as pd
import openpyxl
import xlsxwriter
import pprint
import numpy as np
import json
from tabulate import tabulate

if __name__ == '__main__':
    with open("./resources/test.xml", "r") as f:
        backup = f.read()

    parser = PfsenseParser()
    parser.parse(backup)

    rules_dict = parser.get_dict()
    pprint.pprint(rules_dict)

    sources = []
    destinations = []
    for key in rules_dict.keys():
        if key[0] not in sources:
            sources.append(key[0])
        if key[1] not in destinations:
            destinations.append(key[1])

    flow_matrix = np.empty((len(sources) + 1, len(destinations) + 1), dtype=object)
    pprint.pprint(flow_matrix)

    flow_matrix[0][0] = "Source / Destination"

    for y in range(len(flow_matrix)):
        for x in range(len(flow_matrix[y])):
            if y == 0 and x > 0:
                flow_matrix[y][x] = destinations[x - 1]
            elif y > 0 and x == 0:
                flow_matrix[y][x] = sources[y - 1]
            elif (sources[y - 1], destinations[x - 1]) in rules_dict:
                rules = rules_dict[(sources[y - 1], destinations[x - 1])]
                res = ""
                print(rules)
                for protocol in rules.keys():
                    for rule in rules[protocol]:
                        res += "(" + protocol + ") " + rule[2] + " : " + rule[1] + "\n"
                    flow_matrix[y][x] = res[:-1]

    pprint.pprint(flow_matrix)
    print(flow_matrix)

    data_frame = pd.DataFrame(flow_matrix)
    print(tabulate(data_frame, headers = 'keys', tablefmt = 'simple_grid'))

    writer = pd.ExcelWriter("./resources/output.xlsx")
    data_frame.to_excel(writer, sheet_name="Flow matrix", header=False, index=False, na_rep="")

    # for column in data_frame[0]:
    #     print(type(column))
    #     print(column)
    #     column_length = max(data_frame[column].astype(str).map(len).max(), len(column)) + 2
    #     col_idx = data_frame.columns.get_loc(column)
    #     writer.sheets["Flow matrix"].set_column(col_idx, col_idx, column_length)

    writer.close()

    df = pd.DataFrame(rules_dict)
    df.to_json("./resources/output.json", orient = 'records', indent = 4)