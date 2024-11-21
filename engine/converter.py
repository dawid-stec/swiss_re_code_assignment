import csv

from collections import namedtuple
from pathlib import Path
from typing import Iterable

Log = namedtuple(
    'Log',
    [
        'timestamp', 'header_size', 'client_ip', 'response_code', 'response_size',
        'request_method', 'url', 'username', 'destination_ip', 'response_type'
    ]
)


def log_entries_from_csv(path: Path) -> Iterable[Log]:
    with open(path, 'r', encoding='utf-8') as csv_file:
        reader = csv.reader(csv_file)
        next(reader)  # skip first row

        for row in reader:

            _row = row[0]
            if isinstance(_row, list):
                _row = ' '.join(_row)

            __row: list = _row.split()
            # skip incorrect logs
            if len(__row) == 10:
                yield Log(*__row)


def log_entries_from(paths: Iterable[str]) -> Iterable[Log]:
    for path in paths:
        path = Path(path)
        file_extension = path.suffix
        if file_extension == '.log':
            return log_entries_from_csv(path)
        else:
            raise ValueError(f"File extension: '{file_extension}' not supported yet. Only csv is supported")
