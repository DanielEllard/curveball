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

import sys
import os
location =  os.path.dirname(__file__)
sys.path.append(location + '/../python')

import atexit
import time
import pexpect
import socket
from threading import Thread
from optparse import OptionParser
from cb.util.cb_experiment import CurveballExperiment
from curveball_basics import CurveballBasics


""" TrawlWorld Experiment Interaction Script

For instructions on its use, please refer to: 
https://curveball.ir.bbn.com/projects/curveball/wiki/TrawlWorldExp

Example usage with CORE:

./helloworld.py -p $HOME/curveball/src --draddr=dr

"""

class TrawlWorld(CurveballBasics):
    def __init__(self, opts=None):
        self.opts = opts
        if opts is None:
            parser = OptionParser()
            self.add_parse_opts(parser)        
            (self.opts, _) = parser.parse_args()
        
        super(TrawlWorld, self).__init__(self.opts,
                use_firewall=False, use_client=False)
        
    def install(self, args):
        super(TrawlWorld, self).install(args)

    def start(self, args):
        """ Need to figure out how to not need the tunnel """

        super(TrawlWorld, self).start(args, 'decoy:443')

    def stop(self, args):
        """ Stop the decoy routing services """
        super(TrawlWorld, self).stop(args)

    def exit(self, args):
        """ exit the program """
        sys.exit(0)
        
    def add_parse_opts(self, parser):
        super(TrawlWorld, self).add_parse_opts(parser)

        return parser

def main():
    trawl = TrawlWorld()    
    trawl.connect()

    if not trawl.opts.batch:
        trawl.interact()
    else:
        trawl.run_batch_mode(hello.opts.batch)


if __name__ == '__main__':
    main()
