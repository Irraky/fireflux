from pfsenseParser import PfsenseParser
import pandas as pd
import openpyxl
import xlsxwriter


def convert(file):
    with open(file, "r") as f:
        backup = f.read()

    parser = PfsenseParser()
    parser.parse(backup)

    return parser.get_rules_list_as_csv()


if __name__ == '__main__':
    with open("./resources/test.xml", "r") as f:
        backup = f.read()

    parser = PfsenseParser()
    parser.parse(backup)
    parser.write_csv("rules.csv")

    data_frame = pd.read_csv("./resources/rules.csv", delimiter=";")
    print(data_frame)

    writer = pd.ExcelWriter("./resources/output.xlsx")
    data_frame.to_excel(writer, sheet_name="Flow matrix", header=True, index=False, na_rep="NaN")

    for column in data_frame:
        column_length = max(data_frame[column].astype(str).map(len).max(), len(column)) + 2
        col_idx = data_frame.columns.get_loc(column)
        writer.sheets["Flow matrix"].set_column(col_idx, col_idx, column_length)

    writer.close()
