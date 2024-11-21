import json
from pathlib import Path


def dict_to_json(data_to_be_saved: dict, path: Path):
    with open(path, 'w') as json_file:
        json_object = json.dumps(data_to_be_saved, indent=4)
        json_file.write(json_object)
