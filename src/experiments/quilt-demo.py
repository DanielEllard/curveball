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

from curveball_net import CurveballNet

"""
Topology: quilt-demo.imn:

  eth1       +-- dr0
   |         |
  client     +-- dr1
   |         |
  filter     +-- dr2
   |         |
  network----+-- qcovert
   |         |
  nat        +-- dp0
   |         |
  eth2       +-- dp1
             |
             +-- dp2
             |
             +-- cb-quilt


Note that the CORE simulation will commandeer the eth2 device and put it in
promiscuous mode.  The eth2 device should be a VM NAT device.

See: https://cureball.ir.bbn.com/projects/curveball/wiki/QuiltDemo

for instructions to set up your VM

"""

class QuiltDemo(CurveballNet):
    def __init__(self):
        parser = OptionParser()
        self.add_parse_opts(parser)
        (self.opts, _) = parser.parse_args()

        # Don't use the crypto keys for the demo (for now)
        self.opts.crypto = False
        _dr2decoy= {'dr0' : 'decoy0',
                    'dr1' : 'decoy1',
                    'dr2' : 'decoy2'}

        super(QuiltDemo, self).__init__(self.opts,
                                        drs={'dr0': 'dp0',
                                             'dr1': 'dp1',
                                             'dr2': 'dp2' },
                                        # , turns this parenthesized
                                        # term into a tuple
                                        coverts=['qcovert'],
                                        quilt='cb-quilt',
                                        dr2decoy=_dr2decoy)

        self.cmds['diagnostics'] = 'run some (mostly broken) diagnostic tests'
        self.cmds['speed_test'] = 'iperf throughput test between client and covert via curveball'

        # decoy_spec_list = ['%s:https,%s:http' % (x, x) for x in _dr2decoy.values()]
        # self.decoy_spec = ','.join(decoy_spec_list)


    def add_parse_opts(self, parser):        
        super(QuiltDemo, self).add_parse_opts(parser)



        return parser        

    def speed_test(self, args):
        """
        args (optional) = number of times to run speed test
        """

        loops = 1
        if args:
            loops = int(args)
            
        client = self.create_spare('client')
        covert = self.create_spare('qcovert')
        
        covert.run('iperf -s -p 55221')
        time.sleep(2)
        
        out = []
        
        for i in range(loops):
            if self.opts.vpn:
                client.run('iperf -c qcovert -p 55221')
            else:    
                client.run('tsocks iperf -c qcovert -p 55221')
            try:
                client.expect('connected', timeout=10)
                print "IPerf connected.. running test"
            except (pexpect.EOF, pexpect.TIMEOUT):        
                print "Client could not connect to qcovert iperf server"
                client.commandeer()
                return None
            
            try:
                data = client.expect('/sec', timeout=25)
                (speed, units) = data[0].split(' ')[-2:]
                units += '/sec'
                print "%s %s" % (speed, units)
                out.append((float(speed), units))

            except (pexpect.EOF, pexpect.TIMEOUT):
                print "Did not get a measurement"
                return None

        client.controlc()
        covert.controlc()

        return out
        
    def test_pings(self):            
        pairs = []
        for src in self.servers:
            for dst in [x for x in self.servers if x != src]:
                pairs.append((src, dst))

        #unallowable = [('client','dp'), ('client', 'google.com')]
        
        for (src,dst) in pairs:
            time = self.ping(src, dst)
            if time is None:
                print "%s unable to ping %s" % (src, dst)
                print "Exit the script and try restarting your CORE topology"
            else:
                print "%s -- %s: %f" % (src, dst, time)
            
                    
    def test_services(self):
        # Don't just return silently (does silnce indicate things are
        # good? bad?  
        print("test services not implemented yet")
        pass
    
    def diagnostics(self, args):
        """ See if we can find out what's wrong """
        self.test_pings()
        #self.test_services()
        self.test_decoy_routing()

    def start_network(self, args):
        if self.transport == 'core':
            self.stop_network(None)
            
            # # Make sure we can ping 10.0.3.2 and 10.0.4.2
            # # before we start core
            # if not subprocess.call('ping -c 1 10.0.3.2 > /dev/null', shell=True) == 0:
            #     print("Error, could not ping 10.0.3.2 before opening CORE")
            #     sys.exit(1)
                
            # if not subprocess.call('ping -c 1 10.0.4.2 > /dev/null', shell=True) == 0:
            #     print ("Error, could not ping 10.0.4.2 before opening CORE")
            #     sys.exit(1)
                                  
        super(QuiltDemo, self).start_network(args)
        

def main():
    demo = QuiltDemo()    
    demo.connect()
    
    if not demo.opts.batch:
        demo.interact()
    else:
        demo.run_batch_mode(demo.opts.batch)

if __name__ == '__main__':
    main()
