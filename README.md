# CryptoCTF Analyzer

CryptoCTF Analyzer is a beginner-friendly Python project for recognizing attack patterns in legal cryptography CTF challenges.

The goal is not to automatically solve flags. The goal is to extract useful parameters, explain suspicious patterns, and recommend the next attack template to investigate.

## Current Features

v0.1 supports RSA challenge recognition only.

- Reads challenge files from command-line arguments
- Extracts simple RSA parameters: `n`, `e`, and `c`
- Detects when the files look like possible RSA
- Detects small public exponents, currently `e = 3` and `e = 5`
- Detects perfect-square RSA moduli, such as `n = 37 * 37`
- Prints evidence, notes, and recommended next steps

## Installation

This version uses only the Python standard library.

```bash
cd cryptoctf-analyzer
python3 --version
```

No package installation is required for v0.1.

## Usage

Run the analyzer with one or more challenge files:

```bash
python3 main.py samples/chall.py samples/output.txt
```

Do not hardcode file names in the program. Pass the challenge files as command-line arguments.

## Example Output

```text
=== CryptoCTF Analyzer v0.1 ===

Files:
[+] samples/chall.py
[+] samples/output.txt

Detected parameters:
[+] n
[+] e
[+] c

Primitive:
[+] Possible RSA

Analysis:

[HIGH] Small RSA Public Exponent

Evidence:
- e = 3
- Small RSA public exponent detected

Note:
A small exponent alone is an observation, not a confirmed break. The classic attack usually needs weak or missing padding and a small plaintext.

Recommended next step:
Check whether the plaintext was used without sufficient padding and whether c has an exact e-th root.

[HIGH] Perfect Square Modulus

Evidence:
- n is a perfect square
- sqrt(n) = 37

Possible condition:
p = q = 37

Recommended next step:
Investigate direct factorization of n.
```

## Project Structure

```text
cryptoctf-analyzer/
|
|-- main.py
|-- parser.py
|-- detector.py
|
|-- rules/
|   |-- __init__.py
|   `-- rsa_rules.py
|
|-- samples/
|   |-- chall.py
|   `-- output.txt
|
|-- templates/
|
|-- README.md
|-- requirements.txt
`-- .gitignore
```

## Current Limitations

- Only RSA is supported.
- Parsing is intentionally simple and regex-based.
- The tool recognizes attack patterns but does not solve challenges.
- Small exponent detection does not prove a vulnerability by itself.
- Perfect-square modulus detection only checks the direct `sqrt(n) * sqrt(n) == n` case.
- The analyzer does not yet inspect padding, message size, repeated moduli, or multiple ciphertexts.

## Planned Roadmap

```text
v0.1
- RSA parameter parser
- RSA primitive detection
- Small exponent detection
- Perfect square modulus detection

v0.2
- Fermat factorization detection
- Common modulus detection

v0.3
- Hastad broadcast detection
- Wiener attack heuristics

Future
- XOR
- AES misuse
- PRNG
- ECC
- integration/recommendation for crypto-attacks templates
```

## Program Flow

```text
chall.py + output.txt
        |
        v
parser.py
        |
        v
detector.py
        |
        v
rsa_rules.py
        |
        v
analysis results
        |
        v
main.py displays output
```
