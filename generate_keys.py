#!/bin/env python
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

key_folder = Path('.keys')
key_folder.mkdir(exist_ok=True)
pub_key_path  = key_folder / 'id_ed25519.pub'
priv_key_path = key_folder / 'id_ed25519'

password = input('Enter private key password: ').encode()
private_key = ed25519.Ed25519PrivateKey.generate()

priv_key_path.write_bytes(
    private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
)

pub_key_path.write_bytes(
    private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
)


read_private_bytes = Path('.keys/id_ed25519').read_bytes()

private_key_readback = serialization.load_pem_private_key(
    read_private_bytes,
    password=password,
)

#private_key_readback = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes2)
sig1 = private_key.sign(b'hello')
sig2 = private_key_readback.sign(b'hello')

print(f"they are equal: {sig1 == sig2}")