# Copyright (C) 2011  Jeff Forcier <jeff@bitprophet.org>
#
# This file is part of ssh.
#
# 'ssh' is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# 'ssh' is distrubuted in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with 'ssh'; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Suite 500, Boston, MA  02110-1335  USA.

"""
L{DSSKey}
"""

from Crypto.PublicKey import DSA
from Crypto.Hash import SHA

from ssh.common import *
from ssh import util
from ssh.ssh_exception import SSHException
from ssh.message import Message
from ssh.ber import BER, BERException
from ssh.pkey import PKey


class DSSKey (PKey):
    """
    Representation of a DSS key which can be used to sign an verify SSH2
    data.
    """

    def __init__(self, msg=None, data=None, filename=None, password=None, vals=None, file_obj=None):
        self.p = None
        self.q = None
        self.g = None
        self.y = None
        self.x = None
        if file_obj is not None:
            self._from_private_key(file_obj, password)
            return
        if filename is not None:
            self._from_private_key_file(filename, password)
            return
        if (msg is None) and (data is not None):
            msg = Message(data)
        if vals is not None:
            self.p, self.q, self.g, self.y = vals
        else:
            if msg is None:
                raise SSHException('Key object may not be empty')
            if msg.get_string() != b'ssh-dss':
                raise SSHException('Invalid key')
            self.p = msg.get_mpint()
            self.q = msg.get_mpint()
            self.g = msg.get_mpint()
            self.y = msg.get_mpint()
        self.size = util.bit_length(self.p)

    def __bytes__(self):
        m = Message()
        m.add_string(b'ssh-dss')
        m.add_mpint(self.p)
        m.add_mpint(self.q)
        m.add_mpint(self.g)
        m.add_mpint(self.y)
        return bytes(m)

    def __str__(self):
        return bytes(self)

    def __hash__(self):
        h = hash(self.get_name())
        h = h * 37 + hash(self.p)
        h = h * 37 + hash(self.q)
        h = h * 37 + hash(self.g)
        h = h * 37 + hash(self.y)
        return hash(h)

    def get_name(self):
        return b'ssh-dss'

    def get_bits(self):
        return self.size
        
    def can_sign(self):
        return self.x is not None

    def sign_ssh_data(self, rng, data):
        digest = SHA.new(data).digest()
        dss = DSA.construct((int(self.y), int(self.g), int(self.p), int(self.q), int(self.x)))
        # generate a suitable k
        qsize = len(util.deflate_long(self.q, 0))
        while True:
            k = util.inflate_long(rng.read(qsize), 1)
            if (k > 2) and (k < self.q):
                break
        r, s = dss.sign(util.inflate_long(digest, 1), k)
        m = Message()
        m.add_string(b'ssh-dss')
        # apparently, in rare cases, r or s may be shorter than 20 bytes!
        rstr = util.deflate_long(r, 0)
        sstr = util.deflate_long(s, 0)
        if len(rstr) < 20:
            rstr = b'\x00' * (20 - len(rstr)) + rstr
        if len(sstr) < 20:
            sstr = b'\x00' * (20 - len(sstr)) + sstr
        m.add_string(rstr + sstr)
        return m

    def verify_ssh_sig(self, data, msg):
        if len(bytes(msg)) == 40:
            # spies.com bug: signature has no header
            sig = bytes(msg)
        else:
            kind = msg.get_string()
            if kind != b'ssh-dss':
                return 0
            sig = msg.get_string()

        # pull out (r, s) which are NOT encoded as mpints
        sigR = util.inflate_long(sig[:20], 1)
        sigS = util.inflate_long(sig[20:], 1)
        sigM = util.inflate_long(SHA.new(data).digest(), 1)

        dss = DSA.construct((int(self.y), int(self.g), int(self.p), int(self.q)))
        return dss.verify(sigM, (sigR, sigS))

    def _encode_key(self):
        if self.x is None:
            raise SSHException('Not enough key information')
        keylist = [ 0, self.p, self.q, self.g, self.y, self.x ]
        try:
            b = BER()
            b.encode(keylist)
        except BERException:
            raise SSHException('Unable to create ber encoding of key')
        return bytes(b)

    def write_private_key_file(self, filename, password=None):
        self._write_private_key_file('DSA', filename, self._encode_key(), password)

    def write_private_key(self, file_obj, password=None):
        self._write_private_key('DSA', file_obj, self._encode_key(), password)

    @staticmethod
    def generate(bits=1024, progress_func=None):
        """
        Generate a new private DSS key.  This factory function can be used to
        generate a new host key or authentication key.

        @param bits: number of bits the generated key should be.
        @type bits: int
        @param progress_func: an optional function to call at key points in
            key generation (used by C{pyCrypto.PublicKey}).
        @type progress_func: function
        @return: new private key
        @rtype: L{DSSKey}
        """
        dsa = DSA.generate(bits, rng.read, progress_func)
        key = DSSKey(vals=(dsa.p, dsa.q, dsa.g, dsa.y))
        key.x = dsa.x
        return key


    ###  internals...


    def _from_private_key_file(self, filename, password):
        data = self._read_private_key_file('DSA', filename, password)
        self._decode_key(data)
    
    def _from_private_key(self, file_obj, password):
        data = self._read_private_key('DSA', file_obj, password)
        self._decode_key(data)
    
    def _decode_key(self, data):
        # private key file contains:
        # DSAPrivateKey = { version = 0, p, q, g, y, x }
        try:
            keylist = BER(data).decode()
        except BERException as x:
            raise SSHException('Unable to parse key file: ' + str(x))
        if (type(keylist) is not list) or (len(keylist) < 6) or (keylist[0] != 0):
            raise SSHException('not a valid DSA private key file (bad ber encoding)')
        self.p = keylist[1]
        self.q = keylist[2]
        self.g = keylist[3]
        self.y = keylist[4]
        self.x = keylist[5]
        self.size = util.bit_length(self.p)
