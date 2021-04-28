#!/usr/bin/env python3

import sys
import blowfish
import hashlib
import click
from getpass import getpass
import base64
import subprocess

cipher = None

@click.command()
@click.option('--n', default=1, type=int, help="The nth onionv3 will be generated with the given seedphrase. Default: 1")
@click.option('--seedphrase', default=None, help="Specifies seedphrase manually from the command-line and disables prompt.")
def main(n, seedphrase):
    global cipher
    if not seedphrase:
        seedphrase = getpass("Seedphrase (4-56 bytes):")
    cipher = blowfish.Cipher(seedphrase.encode('utf-8'))
    m = hashlib.sha256()

    m.update(seedphrase.encode('utf-8'))
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