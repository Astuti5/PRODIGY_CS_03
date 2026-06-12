# Password Strength Analyzer

A Python desktop tool that checks password strength in real time.
Built during my Prodigy InfoTech cybersecurity internship.

## Strength criteria checked
- Minimum length (NIST recommends at least 8, ideally 12+)
- Uppercase and lowercase characters
- Digits and special characters
- Detection of common weak passwords (password123, qwerty, etc.)

## What I learned
NIST SP 800-63B actually discourages mandatory complexity rules in favour of longer passphrases.
This project made me research why "P@ssw0rd" scores high on most checkers but is still weak.

## How to run
python PasswordCheck.py

## Planned improvements
- [ ] Add HaveIBeenPwned API integration to check if password appears in breach databases
- [ ] Export results to a report file
