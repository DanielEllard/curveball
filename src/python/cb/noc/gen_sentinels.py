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

# Generate test sentinels to std_out
# input: keyfile, # of sentinels / key
# output: sentinel to std_out

# ~3m10s to create 6.4M sentinels

# todo:
# add exception handling and usage block

# keyfile is assumed to be formatted as: 'index key'

"""
Routines to help generate sentinel strings
"""

import datetime
import hashlib
import hmac
import sys

# Set to True if sentinels last a day, False if they need to change on
# the hour.  CB_PER_DAY_SENTINELS makes it easier to debug and test,
# since we don't have to update sentinel files every hour.
CB_PER_DAY_SENTINELS=False

def create_date_hmac_str(utc=None):
    """
    Create the 'time-based seed' for the sentinel generator HMAC,
    based on the given datetime.datetime UTC instance.

    If utc is None, then the current UTC is used.
    """

    if utc == None:
        utc = datetime.datetime.utcnow()

    if CB_PER_DAY_SENTINELS:
        return utc.strftime('%Y-%m-%d')
    else:
        return utc.strftime('%Y-%m-%d %H')

def create_sentinel(mykey, number, time_str=None): 
    """
    Given a key, number, and optional time_str, create the corresponding
    sentinel.

    If time_str is not supplied, then it is computed directly by calling
    create_date_hmac_str.
    """

    if time_str == None:
        time_str = create_date_hmac_str()
    msg = '%s %d' % (time_str, number)
    return hmac.new(mykey, msg, hashlib.sha256).hexdigest() # removed [:16], now returns entire hash

def gen_sentinels(key_file, num_sentinels):
    utc = datetime.datetime.utcnow()
    time_str = create_date_hmac_str(utc)
    retval = []

    # Here we have hex versions of the sentinels
    # the actual sentinels are made using binascii.unhexlify(sentinel[:16]) 
    # to get binary versions of 8B of sentinel.
    # the remainder (sentinel[16:]) is the "extra bits" or "sentinel label" 

    for line in open(key_file, 'r'):
        key = line.split()
        for i in range (0, num_sentinels):
            sentinel = create_sentinel(key[1], i, time_str)
            # it's not clear we need to return i, here --- the program
            # originally printed the index for the sentinels generated
            # for each key, and the C program still does, but
            # otherwise i isn't needed
            # (bear in mind that i goes from 0..num_sentinels for each
            # key in the key-file)
            retval.append([i, sentinel[:16], sentinel[16:]])

    return retval

if __name__ == '__main__':

    if len(sys.argv) > 2:
        key_file = sys.argv[1]
        num_sentinels = int(sys.argv[2])
    else:
        print "Usage: %s key-file num-sentinels" % sys.argv[0]
        sys.exit(1)
        
    sents = gen_sentinels(key_file, num_sentinels)

    for item in sents:
        print "%d %s %s" % (item[0], item[1], item[2])
