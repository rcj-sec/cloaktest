import json

def read_json_file(filepath):
    with open(filepath, 'r') as f:
        data = json.load(f)
    return data