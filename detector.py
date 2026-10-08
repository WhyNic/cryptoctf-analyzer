from rules.rsa_rules import analyze_rsa


def detect_primitive(data):
    """Decide which crypto primitive might be present."""
    required_rsa_parameters = ("n", "e", "c")

    if all(parameter in data for parameter in required_rsa_parameters):
        return "Possible RSA"

    return "Unknown"


def analyze_parameters(data):
    """Run attack-pattern rules for the detected primitive."""
    primitive = detect_primitive(data)

    if primitive == "Possible RSA":
        return analyze_rsa(data)

    return []
