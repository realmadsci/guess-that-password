#!/bin/env python
# This creates a single test file that is *not* signed so it will not be accepted as a solution.
import hashlib
import secrets
from pathlib import Path

import bcrypt

def load_wordle_list(filename):
    '''
    Word list extracted from https://www.nytimes.com/games/wordle/index.html
    '''
    return Path(filename).read_text().splitlines()

def choose_n_words(wordlist, num):
    '''
    Return N words randomly from the word list

    NOTE: This uses secrets.choice() rather than random.choice() so that it
          creates cryptographically random choices from os.urandom() instead
          of pseudorandom choices. We don't want to make the challenge any easier
          by making only "pseudo" random choices, now do we?
    '''
    words = []
    for i in range(num):
        words.append(secrets.choice(wordlist))
    return words


def make_hyphen_password(wordlist, num_words):
    '''Generate a simple hyphenated password'''
    return "-".join(choose_n_words(wordlist, num_words)).encode('ascii')


def simple_password_mutate(password):
    '''Maybe capitalize the first letter, and maybe add a digit'''
    if secrets.choice([True, False]):
        password = password.decode().capitalize().encode('ascii')

    digit = bytes([secrets.choice(b'\x000123456789')])
    if digit == b'\x00':
        return password
    else:
        return password + digit


def gen_md5(password):
    '''Create an md5 hash from the given password string'''
    m = hashlib.md5()
    m.update(password)
    return m.digest()


def gen_bcrypt(password):
    '''Create a salted bcrypt hash from the given password string'''
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password, salt)


def verify_bcrypt(password, hashed):
    '''Verify a salted bcrypt hash from the given password string'''
    return bcrypt.checkpw(password, hashed)


def extract_protected_text(filename):
    '''
    Extract the text from a test file which we want to safeguard with a signature.

    Since we want to allow removing the passwords and still having the signature
    be valid even if they are not *all* reconstructed, we have to be careful that
    the signing and verifying functions both see the same "important bytes" in the file!
    '''
    text = ''
    with Path(filename).open() as f:
        for line in f:
            line = line.strip()
            # Ignore lines that are blank or start with a comment character
            if len(line) and not line.startswith('#'):
                # Ignore everything before the first ':' character.
                # This allows the signature algorithm to ignore the actual password text.
                line = line.split(':', maxsplit=1)[-1].strip()
                text += line
    return text


if __name__ == '__main__':
    import sys

    words = load_wordle_list('wordle_list.txt')
    #print(f'Got {len(words)} words from the list!')

    test_path = Path('original_tests')
    test_path.mkdir(exist_ok=True)

    expiration = '2022.05.06'
    for user in sys.argv[1:]:
        with (test_path / f'{user}.txt').open('w') as f:
            f.write(f':Assigned_to = {user}\n')
            f.write(f':Expiration_date = {expiration}\n')

            f.write(f'\n# Level 0: MD5 hash, one single word. All lowercase, nothing special.\n')
            password = make_hyphen_password(words, 1)
            hash = gen_md5(password)
            f.write(f'{password.decode()}:{hash.hex()}:2\n')

            f.write('\n# Level 1: MD5 hash, one single word.\n')
            f.write('# The first letter *might* be capitalized, and it *might* have a single decimal digit appended.\n')
            f.write('# IMPORTANT NOTE: THIS IS THE ONLY LEVEL THAT HAS ANYTHING OTHER THAN ALL-LOWERCASE WORDS!\n')
            for i in range(4):
                password = simple_password_mutate(make_hyphen_password(words, 1))
                hash = gen_md5(password)
                f.write(f'{password.decode()}:{hash.hex()}:2\n')

            f.write('\n# Level 2: MD5 hashes. These are 2-word passwords with a hyphen in between.\n')
            for i in range(5):
                password = make_hyphen_password(words, 2)
                hash = gen_md5(password)
                f.write(f'{password.decode()}:{hash.hex()}:3\n')

            f.write('\n# Level 3: Salted bcrypt hash. This is a 2-word password with a hyphen in between.\n')
            password = make_hyphen_password(words, 2)
            hash = gen_bcrypt(password)
            f.write(f'{password.decode()}:{hash.decode()}:10\n')

            f.write('\n# Level 4: MD5 hashes. These are 3-word passwords with hyphens in between.\n')
            for i in range(4):
                password = make_hyphen_password(words, 3)
                hash = gen_md5(password)
                f.write(f'{password.decode()}:{hash.hex()}:1\n')

            f.write('\n# Level 5: MD5 hashes. This is a 4-word password with hyphens in between.\n')
            password = make_hyphen_password(words, 4)
            hash = gen_md5(password)
            f.write(f'{password.decode()}:{hash.hex()}:1\n')

            f.write('\n# Level 6: "Impossible extra credit level". MD5 hashes. This is a 5-word password with hyphens in between.\n')
            password = make_hyphen_password(words, 5)
            hash = gen_md5(password)
            f.write(f'{password.decode()}:{hash.hex()}:5\n')