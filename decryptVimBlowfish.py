#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import hashlib
from Crypto.Cipher import Blowfish
import struct
import sys


filename = 'file'
password = 'test'


with open(filename, 'rb') as fd:
        myBuffer = fd.read(28)
        assert myBuffer[:12] == 'VimCrypt~02!', 'This is not a Vim-blowfish-encrypted file.'
        salt = myBuffer[12:20]
        iv = myBuffer[20:28]
        contents = fd.read()


def printerr(s): sys.stderr.write(s)

def getKey(password, salt):
    # Process the key 1000 times.  (called "Key stretching")
    key = hashlib.sha256(password + salt).hexdigest()

    for i in xrange(1000):
        if i < 5:
            printerr(" key:%s\n"%key)
        key = hashlib.sha256(key + salt).hexdigest()

    printerr(" ...\n key:%s\n\n"%key)
    return key


def flipEndian(inData):
    outData = ''
    for i in xrange(0, len(inData), 4):
        outData += inData[i+3] + inData[i+2] + inData[i+1] + inData[i]
    return outData


key = getKey(password, salt)
binKey = key.decode('hex')

#Blowfish.block_size = 64
#bf = Blowfish.new(binKey, mode=Blowfish.MODE_CFB, IV=iv_be*8, segment_size=8)
#bf = Blowfish.new(binKey, mode=Blowfish.MODE_OFB, IV=iv_be)
#bf = Blowfish.new(binKey, mode=Blowfish.MODE_OFB, IV=iv_be)

bf = Blowfish.new(binKey)

# Initialize the keystream:
cipherblock = 8*iv
origin = 0
plaintextlist = []
while len(contents) > origin:
        keystream = flipEndian( bf.encrypt( flipEndian( cipherblock)))
        cipherblock = contents[origin:origin + len(cipherblock)]
        origin += len(cipherblock)
        plaintextlist.extend(chr(ord(c) ^ ord(k)) for c,k in zip(cipherblock, keystream))

sys.stdout.write(''.join(plaintextlist))
