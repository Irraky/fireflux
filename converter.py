import csv 
import json
import pandas as pd

def csv_to_json(csvFilePath, jsonFilePath):
    jsonArray = []
    with open(csvFilePath, encoding='utf-8') as csvf: 
        csvReader = csv.DictReader(csvf, delimiter=';') 
        for row in csvReader: 
            jsonArray.append(row)
    with open(jsonFilePath, 'w', encoding='utf-8') as jsonf: 
        jsonString = json.dumps(jsonArray, indent=4)
        jsonf.write(jsonString)

def excel_to_json(xlsxFilePath, jsonFilePath):
    excelfile = pd.read_excel(xlsxFilePath)
    csvf = excelfile.to_csv(index = None, header=True)
    jsonArray = []
    csvReader = csv.DictReader(csvf.splitlines()) 
    for row in csvReader: 
        jsonArray.append(row)
    with open(jsonFilePath, 'w', encoding='utf-8') as jsonf: 
        jsonString = json.dumps(jsonArray, indent=4)
        jsonf.write(jsonString)

xlsxFilePath=r'resources/output.xlsx'
csvFilePath = r'resources/rules.csv'
jsonFilePath = r'resources/test.json'
excel_to_json(xlsxFilePath, jsonFilePath)
