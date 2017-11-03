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
import atexit
import time
import pexpect
import socket
from threading import Thread
import subprocess
from optparse import OptionParser
sys.path.append('../python')

from curveball_basics import CurveballBasics

"""
Topology:

client -- filter -- dr -- internet_router -- virtual machine eth1
                      \-- dp

The eth1 device on the virtual machine must have its gateway at 10.0.3.2 as 
that is what internet_router is configured to send packets to

Note that the CORE simulation will commandeer the eth1 device and put it in
promiscuous mode.  The eth1 device should be a VM NAT device.

"""

class June12Demo(CurveballBasics):
    def __init__(self):
        parser = OptionParser()
        self.add_parse_opts(parser)
        (self.opts, _) = parser.parse_args()

        super(June12Demo, self).__init__(self.opts)
        self.servers.append('internet')
        self.cmds['diagnostics'] = 'run some (mostly broken) diagnostic tests'

    def add_parse_opts(self, parser):        
        super(June12Demo, self).add_parse_opts(parser)
                
        return parser        

    def test_pings(self):            
        pairs = []
        for src in self.servers:
            for dst in [x for x in self.servers if x != src]:
                pairs.append((src, dst))
        pairs.append(('client', '10.0.4.2'))
        pairs.append(('internet', '10.0.3.2'))
        
        #unallowable = [('client','dp'), ('client', 'google.com')]
        
        for (src,dst) in pairs:
            time = self.ping(src, dst)
            if time is None:
                print "%s unable to ping %s" % (src, dst)
                print "Exit the script and try restarting your CORE topology"
            else:
                print "%s -- %s: %f" % (src, dst, time)
            
                    
    def test_services(self):
        pass
    
    def diagnostics(self, args):
        """ See if we can find out what's wrong """
        self.test_pings()
        #self.test_services()
        self.test_decoy_routing()

    def start_network(self, args):
        if self.transport == 'core':
            self.stop_network(None)
            
            # Make sure we can ping 10.0.3.2 and 10.0.4.2
            # before we start core
            if not subprocess.call('ping -c 1 10.0.3.2 > /dev/null', shell=True) == 0:
                print("Error, could not ping 10.0.3.2 before opening CORE")
                sys.exit(1)
                
            if not subprocess.call('ping -c 1 10.0.4.2 > /dev/null', shell=True) == 0:
                print ("Error, could not ping 10.0.4.2 before opening CORE")
                sys.exit(1)
                                  
        super(June12Demo, self).start_network(args)
        

def main():
    demo = June12Demo()    
    demo.connect()
    
    if not demo.opts.batch:
        demo.interact()
    else:
        demo.run_batch_mode(demo.opts.batch)

if __name__ == '__main__':
    main()
