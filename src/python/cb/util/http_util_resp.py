#!/usr/bin/env python
#
# This material is based upon work supported by the Defense Advanced
# Research Projects Agency under Contract No. N66001-11-C-4017.
#
# Copyright 2014 - Raytheon BBN Technologies Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

import random
import string
import base64
import binascii
import hashlib
import string
import zlib
import os

import cb.cssl.aes
import cb.cssl.rsa
import cb.util.cb_constants as const
import cb.util.security_util as security_util
from M2Crypto import RSA, BIO, EVP



def create_http_resp(self,
        key, hmac, server_name, response_date, content_type, text):

    text = security_util.encrypt_text( self, text, key, False, True, False )
    payload = hmac + text

    http_ok = 'HTTP/1.1 200 OK' + const.END_LINE
    date = 'Date: ' + const.END_LINE
    server = 'Server: ' + const.END_LINE
    content_len = 'Content-Length: ' + str( len( payload ) ) + const.END_LINE
    content_encoding = 'Content-Encoding: gzip' + const.END_LINE

    resp = ( http_ok + #date + #server +
             content_len +
             content_type +
             content_encoding +
             const.END_LINE  +
             payload )

    return resp


if __name__ == '__main__':
    pass
