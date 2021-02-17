#!/bin/env python
import binascii
import getpass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from create_tests import extract_protected_text

key_folder = Path('keys')
priv_key_path = key_folder / 'id_ed25519'

private_key = serialization.load_pem_private_key(
    priv_key_path.read_bytes(),
    password=getpass.getpass('Enter signing password: ').encode())

test_path = Path('original_tests')
signed_path = Path('assigned_tests')
signed_path.mkdir(exist_ok=True)

for test in test_path.iterdir():
    text = extract_protected_text(test)
    print(text)
    sig = private_key.sign(text.encode())

    # Copy the file, replacing passwords with "password" and then sign it:
    with test.open() as t, (signed_path / test.name).open('w') as f:
        for line in t:
            # Lines that have exactly three ':' chars are password sets:
            s = line.split(':')

            # If the line is a password line, replace the password part with "password"
            if len(line) and not line.startswith('#') and (len(s) == 3):
                f.write('password:' + ':'.join(s[1:]))
            else:
                # Just copy the line if it isn't a password
                f.write(line)

        # Write the signature
        f.write('# Signature = ' + binascii.b2a_base64(sig).decode())