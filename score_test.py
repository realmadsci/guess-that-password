#!/bin/env python
import binascii
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from create_tests import extract_protected_text

key_folder = Path('keys')
pub_key_path  = key_folder / 'id_ed25519.pub'

public_key = serialization.load_pem_public_key(pub_key_path.read_bytes())

text = extract_protected_text('signed_tests/realmadsci.txt')
sig_line = [l for l in Path('signed_tests/realmadsci.txt').read_text().splitlines(keepends=False) if l.startswith('# Signature')][0]
sig = binascii.a2b_base64(sig_line.split('=', maxsplit=1)[1])

try:
    public_key.verify(sig, text.encode())
    print('Signature is GOOD')
except InvalidSignature:
    print('Signature verification FAILED')
