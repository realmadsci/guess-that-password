#!/bin/env python
import getpass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

key_folder = Path('keys')
pub_key_path  = key_folder / 'id_ed25519.pub'

public_key = serialization.load_pem_public_key(
    pub_key_path.read_bytes())

with Path("testfile").open() as t:
    for line in t:
        (message, sig) = line.split(':')

        try:
            public_key.verify(bytes.fromhex(sig), message.encode())
        except InvalidSignature:
            print('Signature verification FAILED')
            raise
