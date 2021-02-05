#!/bin/env python
import getpass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

key_folder = Path('keys')
priv_key_path = key_folder / 'id_ed25519'

private_key = serialization.load_pem_private_key(
    priv_key_path.read_bytes(),
    password=getpass.getpass('Enter signing password: ').encode())

message = 'hello'
sig = private_key.sign(message.encode())

with Path("testfile").open('w') as t:
    t.write(message + ":" + sig.hex())