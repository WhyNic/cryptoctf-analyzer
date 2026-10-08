import re


# This pattern looks for simple assignments such as:
# n = 12345
# e = 3
# c = 99999
RSA_PARAMETER_PATTERN = re.compile(
    r"\b(n|e|c)\s*=\s*(0x[0-9a-fA-F]+|\d+)"
)


def read_file(file_path):
    """Read one challenge file as plain text."""
    with open(file_path, "r", encoding="utf-8") as challenge_file:
        return challenge_file.read()


def extract_parameters_from_text(text):
    """Extract n, e, and c values from one text blob."""
    parameters = {}

    for match in RSA_PARAMETER_PATTERN.finditer(text):
        name = match.group(1)
        value_text = match.group(2)

        # int(value, 0) understands normal decimal values and 0x-prefixed hex.
        parameters[name] = int(value_text, 0)

    return parameters


def parse_files(file_paths):
    """Read all provided files and return one dictionary of RSA parameters."""
    all_parameters = {}

    for file_path in file_paths:
        text = read_file(file_path)
        file_parameters = extract_parameters_from_text(text)

        # Later files can fill in values that earlier files did not contain.
        # If the same parameter appears again, the later value replaces it.
        all_parameters.update(file_parameters)

    return all_parameters
