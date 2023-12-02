#!/usr/bin/env python3
import subprocess
import string
import itertools
import time
from more_itertools import distinct_permutations

alph = string.digits + string.ascii_letters

NAME = "gabbypray"
LAST_RUN_LAST_HIT = ""
iterator = itertools.combinations_with_replacement(alph, 3)
if LAST_RUN_LAST_HIT is not None and LAST_RUN_LAST_HIT != '':
    for combo in iterator:
        if ''.join(combo) == LAST_RUN_LAST_HIT:
            print("skipped to last run")
            break

with open("hashes", "wb") as f:
    # whoops, definitely duplicates here
    for combo in iterator:
        for permutation in distinct_permutations(combo):
            id_vals = ''.join(permutation)
            key = NAME + id_vals
            print("trying %s" % key)
            command = "echo -n '%s' | openssl sha1" % key
            p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            while p.poll() is None:
                time.sleep(0.1)

            stdout = b''
            if not p.stdout.readable():
                print("no stdout readable")
                break

            stdout = p.stdout.read()

            try:
                p.kill()
            except:
                pass
            f.write(key.encode() + b' ' + stdout + b'\n')
            continue

"""
# In retrospect, the following loop would have generated these hases in
# around a second...
hashes_with_passwords = []
hostname = b'gabbypray'
for comb in itertools.product(alph, repeat=3):
    id_first_3 = ''.join(comb).encode()
    password = hostname + id_first_3
    hashstr = hashlib.sha1(password).hexdigest()
    hashes_with_passwords.append("%s %s" % (hashstr, str(password)))

"""
