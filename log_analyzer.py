import argparse

from engine.analyzer import Analyzer
from engine.utils import dict_to_json


def main():
    parser = argparse.ArgumentParser(description='Logs engine.')

    parser.add_argument(
        '--input',
        type=str,
        nargs='+',
        help='Path to one or more input files.',
        required=True
    )

    parser.add_argument(
        '--output',
        type=str,
        help='Path to a file to save output in plain text JSON format.',
        required=True
    )

    parser.add_argument(
        '--mfip',
        action=argparse.BooleanOptionalAction,
        help='Most frequent IP'
    )
    parser.add_argument(
        '--lfip',
        action=argparse.BooleanOptionalAction,
        help='Least frequent IP'
    )
    parser.add_argument(
        '--eps',
        action=argparse.BooleanOptionalAction,
        help='Events per second'
    )
    parser.add_argument(
        '--bytes',
        action=argparse.BooleanOptionalAction,
        help='Total amount of bytes exchanged'
    )

    args = parser.parse_args()

    if not args.mfip and not args.lfip and not args.eps and not args.bytes:
        raise Exception("At least one of arguments --mfip, --lfip, --eps, --bytes needs to be used.")

    output = Analyzer(
        input=args.input,
        options={
            'mfip': args.mfip,
            'lfip': args.lfip,
            'eps': args.eps,
            'bts': args.bytes
        }
    ).analyze()
    dict_to_json(output, 'output.json')


if __name__ == "__main__":
    main()
