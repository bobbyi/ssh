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


import sys

from Crypto.Util.py3compat import bord, bchr
from ssh import util

if sys.version > '3':
    long = int


class BERException(Exception):
    pass


class BER(object):
    """
    Robey's tiny little attempt at a BER decoder.
    """

    def __init__(self, content=''):
        self.content = content
        self.idx = 0

    def __bytes__(self):
        return self.content

    def __str__(self):
        if str == bytes: # Python 2.x
            return self.__bytes__()
        else:
            return super().__str__()

    def __repr__(self):
        return 'BER(\'' + repr(self.content) + '\')'

    def decode(self):
        return self.decode_next()
    
    def decode_next(self):
        if self.idx >= len(self.content):
            return None
        ident = bord(self.content[self.idx])
        self.idx += 1
        if (ident & 31) == 31:
            # identifier > 30
            ident = 0
            while self.idx < len(self.content):
                t = bord(self.content[self.idx])
                self.idx += 1
                ident = (ident << 7) | (t & 0x7f)
                if not (t & 0x80):
                    break
        if self.idx >= len(self.content):
            return None
        # now fetch length
        size = bord(self.content[self.idx])
        self.idx += 1
        if size & 0x80:
            # more complimicated...
            # FIXME: theoretically should handle indefinite-length (0x80)
            t = size & 0x7f
            if self.idx + t > len(self.content):
                return None
            size = util.inflate_long(self.content[self.idx : self.idx + t], True)
            self.idx += t
        if self.idx + size > len(self.content):
            # can't fit
            return None
        data = self.content[self.idx : self.idx + size]
        self.idx += size
        # now switch on id
        if ident == 0x30:
            # sequence
            return self.decode_sequence(data)
        elif ident == 2:
            # int
            return util.inflate_long(data)
        else:
            # 1: boolean (00 false, otherwise true)
            raise BERException('Unknown ber encoding type %d (robey is lazy)' % ident)

    @staticmethod
    def decode_sequence(data):
        out = []
        b = BER(data)
        while True:
            x = b.decode_next()
            if x is None:
                break
            out.append(x)
        return out

    def encode_tlv(self, ident, val):
        # no need to support ident > 31 here
        self.content += bchr(ident)
        if len(val) > 0x7f:
            lenstr = util.deflate_long(len(val))
            self.content += bchr(0x80 + len(lenstr)) + lenstr
        else:
            self.content += bchr(len(val))
        self.content += val

    def encode(self, x):
        if isinstance(x, bool):
            if x:
                self.encode_tlv(1, '\xff')
            else:
                self.encode_tlv(1, '\x00')
        elif isinstance(x, (int, long)):
            self.encode_tlv(2, util.deflate_long(x))
        elif isinstance(x, str):
            self.encode_tlv(4, x)
        elif (isinstance(x, list)) or (isinstance(x, tuple)):
            self.encode_tlv(0x30, self.encode_sequence(x))
        else:
            raise BERException('Unknown type for encoding: %s' % repr(type(x)))

    @staticmethod
    def encode_sequence(data):
        b = BER()
        for item in data:
            b.encode(item)
        return str(b)
