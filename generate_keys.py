#!/bin/env python
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

key_folder = Path('keys')
key_folder.mkdir(exist_ok=True)
pub_key_path  = key_folder / 'id_ed25519.pub'
priv_key_path = key_folder / 'id_ed25519'

password = input('Enter signing password: ').encode()
password2 = input('Repeat signing password: ').encode()
if password != password2:
    print('Passwords did not match!')
    quit()

# Generate the private key
private_key = ed25519.Ed25519PrivateKey.generate()

# Encrypt and save the private key
priv_key_path.write_bytes(
    private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)))

# Save the public key
pub_key_path.write_bytes(
    private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
