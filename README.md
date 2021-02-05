# guess-that-password
Password hash reversing challenge, complete with cryptographically signed assignments for automatic grading.

## Dependencies
'''
python -m pip install cryptography
'''

## Usage

Use generate_keys.py to create a new key pair for your own testing.
The key pair that is uploade to the server was used for a class assignment, and is protected by a 128-character random password.
This is fairly secure, but in the real world, you shouldn't actually upload even an encrypted private key into a git repository!
