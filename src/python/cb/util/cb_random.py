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

def gen_rand_bytes(self, len):

    """
    len bytes = 2 * len hex digits
    """
    #r = ''.join([chr(random.randint(0, 255)) for _x in range(len)])
    r = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(len))

    return str(r)
 
if __name__ == '__main__':
    pass
