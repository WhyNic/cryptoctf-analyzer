import argparse
import os

from detector import analyze_parameters, detect_primitive
from parser import parse_files


VERSION = "0.1"


def display_files(file_paths):
    print("Files:")
    for file_path in file_paths:
        print(f"[+] {file_path}")
    print()


def display_parameters(data):
    print("Detected parameters:")

    if not data:
        print("[-] No RSA-style parameters found")
        print()
        return

    for parameter_name in ("n", "e", "c"):
        if parameter_name in data:
            print(f"[+] {parameter_name}")
        else:
            print(f"[-] {parameter_name}")

    print()


def display_analysis(results):
    print("Analysis:")
    print()

    if not results:
        print("[INFO] No v0.1 RSA attack patterns detected.")
        print("This does not prove the challenge is safe; it only means the current rules did not match.")
        return

    for result in results:
        print(f"[{result['confidence']}] {result['attack']}")
        print()

        print("Evidence:")
        for item in result["evidence"]:
            print(f"- {item}")
        print()

        if result.get("note"):
            print("Note:")
            print(result["note"])
            print()

        if result.get("possible_condition"):
            print("Possible condition:")
            print(result["possible_condition"])
            print()

        print("Recommended next step:")
        print(result["recommendation"])
        print()


def build_argument_parser():
    parser = argparse.ArgumentParser(
        description="Analyze beginner RSA CTF challenge files and recommend attack templates."
    )
    parser.add_argument(
        "files",
        nargs="+",
        help="Challenge files to analyze, such as samples/chall.py samples/output.txt",
    )
    return parser


def main():
    argument_parser = build_argument_parser()
    args = argument_parser.parse_args()

    print(f"=== CryptoCTF Analyzer v{VERSION} ===")
    print()

    display_files(args.files)

    try:
        data = parse_files(args.files)
    except FileNotFoundError as error:
        missing_file = os.fspath(error.filename)
        print(f"[ERROR] Could not find file: {missing_file}")
        return

    display_parameters(data)

    primitive = detect_primitive(data)
    print("Primitive:")
    print(f"[+] {primitive}")
    print()

    results = analyze_parameters(data)
    display_analysis(results)


if __name__ == "__main__":
    main()
