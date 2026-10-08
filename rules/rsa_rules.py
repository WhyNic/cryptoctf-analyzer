from math import isqrt


def check_low_exponent(data):
    """Detect suspiciously small RSA public exponents."""
    e = data.get("e")

    if e not in (3, 5):
        return None

    return {
        "attack": "Small RSA Public Exponent",
        "confidence": "HIGH",
        "evidence": [
            f"e = {e}",
            "Small RSA public exponent detected",
        ],
        "note": (
            "A small exponent alone is an observation, not a confirmed break. "
            "The classic attack usually needs weak or missing padding and a small plaintext."
        ),
        "recommendation": (
            "Check whether the plaintext was used without sufficient padding and whether c has an exact e-th root."
        ),
    }


def check_perfect_square_modulus(data):
    """Detect an RSA modulus that is a perfect square."""
    n = data.get("n")

    if n is None or n <= 0:
        return None

    square_root = isqrt(n)

    if square_root * square_root != n:
        return None

    return {
        "attack": "Perfect Square Modulus",
        "confidence": "HIGH",
        "evidence": [
            "n is a perfect square",
            f"sqrt(n) = {square_root}",
        ],
        "possible_condition": f"p = q = {square_root}",
        "recommendation": "Investigate direct factorization of n.",
    }


def analyze_rsa(data):
    """Run all RSA v0.1 recognition rules."""
    checks = [
        check_low_exponent,
        check_perfect_square_modulus,
    ]

    results = []

    for check in checks:
        result = check(data)
        if result is not None:
            results.append(result)

    return results
