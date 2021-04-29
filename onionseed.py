#!/usr/bin/env python3

import sys
import blowfish
import hashlib
import click
from getpass import getpass
import base64
import subprocess

import bcrypt

cipher = None

@click.command()
@click.option('--n', default=1, type=int, help="The nth onionv3 will be generated with the given seedphrase. Default: 1")
@click.option('--seedphrase', default=None, help="Specifies seedphrase manually from the command-line and disables prompt.")
@click.option('--salt', default='$2b$14$8ytOrHOEmDDiPrJArDom9.', help="Choose another salt than $2b$14$8ytOrHOEmDDiPrJArDom9.")
def main(n, seedphrase, salt):
    global cipher
    if not seedphrase:
        seedphrase = getpass("Seedphrase:")
    hashed = hashlib.sha256(bcrypt.hashpw(seedphrase.encode('utf-8'), salt.encode('utf-8'))).digest()
    
    cipher = blowfish.Cipher(hashed)
    m = hashlib.sha256()

    m.update(hashed)
    init_block = m.digest()[0:8]
    block = cipher.encrypt_block(init_block)
    i = 0
    last_four_blocks = list()
    while i < n*4:
        block = cipher.encrypt_block(block)
        last_four_blocks.append(block)
        if len(last_four_blocks) > 4:
            last_four_blocks = last_four_blocks[1:5]
        i += 1

    encoded = base64.b64encode(last_four_blocks[0]+last_four_blocks[1]+last_four_blocks[2]+last_four_blocks[3])

    subprocess.call(['./onionseed', encoded.decode('utf-8')])
    
if __name__ == '__main__':
    main()