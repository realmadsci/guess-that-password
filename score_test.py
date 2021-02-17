#!/bin/env python
import binascii
import logging
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from create_tests import extract_protected_text, verify_bcrypt, gen_md5

# Set up root logger to default to STDERR output and log anything that gets to it
logging.basicConfig(level=logging.DEBUG)

# Set up logger for "__main__" and select INFO level unless we are debugging:
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def verify_signature(f):
    try:
        # Pull in the keys:
        key_folder = Path('keys')
        pub_key_path  = key_folder / 'id_ed25519.pub'
        public_key = serialization.load_pem_public_key(pub_key_path.read_bytes())

        text = extract_protected_text(testfile)
        sig_line = [l for l in testfile.read_text().splitlines(keepends=False) if l.startswith('# Signature')][0]
        sig = binascii.a2b_base64(sig_line.split('=', maxsplit=1)[1])

        public_key.verify(sig, text.encode())
        logger.debug('Signature is GOOD')
        return True
    except InvalidSignature:
        logger.exception('Signature is INVALID')
        return False
    except Exception:
        logger.exception('Unknown failure in signature verification')
        return False


for testfile in Path('completed_tests').glob('*.txt'):
    logger.info(f'Processing: {testfile}')
    if verify_signature(testfile):
        # Now that we know the file is valid, we need to check the expiration date, extract the assigned-to name, and start grading hashes!
        assigned = ""
        expired = True
        total_points = 0
        with testfile.open() as f:
            for line in f:
                line = line.strip()
                # Ignore lines that are blank or start with a comment character
                if len(line) and not line.startswith('#'):
                    if line.startswith(":Assigned_to ="):
                        assigned = line.split('=')[1].strip()
                        logger.debug(f'Assigned to: {assigned}')
                    elif line.startswith(":Expiration_date ="):
                        expiration = datetime.strptime(line.split('=')[1].strip(), '%Y.%m.%d')
                        logger.debug(f'Expires on {expiration.strftime("%Y.%m.%d")}')
                        expired = (expiration < datetime.now())
                        logger.debug('EXPIRED' if expired else 'Still good!')
                    else:
                        # This is a password line, because we don't allow anything else in the file and the signature is already verified!
                        (password, expected_hash, points) = [x.strip() for x in line.split(':')]
                        expected_hash = expected_hash.encode()
                        password = password.encode()
                        points = int(points)

                        logger.debug(f'{password=}, {expected_hash=}, {points=}')

                        if expected_hash.startswith(b'$2b'):
                            password_is_good = verify_bcrypt(password, expected_hash)
                        else:
                            actual_hash = gen_md5(password).hex().encode()
                            password_is_good = (actual_hash == expected_hash)

                        if password_is_good:
                            total_points += points
                        else:
                            logger.warning(f'Hashes did not match! {password.decode()}:{expected_hash.decode()}')

        print(f'{assigned}: {total_points} points{" EXPIRED" if expired else ""}')