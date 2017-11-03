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
if location == '':
    location = '.'

sys.path.append(os.path.join(location, '../python'))

import atexit
import time
import pexpect
import socket
from threading import Thread
from optparse import OptionParser
from cb.util.cb_experiment import CurveballExperiment
from curveball_basics import CurveballBasics


""" HelloWorld Experiment Interaction Script

For instructions on its use, please refer to: 
https://curveball.ir.bbn.com/projects/curveball/wiki/HelloWorldExp

Example usage with DETER: ./helloworld.py -p /users/$USERNAME/curveball/src -d helloworld --draddr=10.0.2.2
Example usage with CORE: ./helloworld.py -p /home/$USERNAME/dev/curveball/src --draddr=dr

Compatible with the following DETER topology:

set ns [new Simulator]
source tb_compat.tcl

set covert [$ns node]
tb-set-node-os $covert u1204+cb+click
tb-set-hardware $covert pc3060

set decoy [$ns node]
tb-set-node-os $decoy u1204+cb+click
tb-set-hardware $decoy pc3060

set dp [$ns node]
tb-set-node-os $dp u1204+cb+click
tb-set-hardware $dp pc3060

set dr [$ns node]
tb-set-node-os $dr u1204+cb+click
tb-set-hardware $dr pc3060

set filter [$ns node]
tb-set-node-os $filter u1204+cb+click
tb-set-hardware $filter pc3060

set client [$ns node]
tb-set-node-os $client u1204+cb+click
tb-set-hardware $client pc3060

# Links
set link0 [$ns duplex-link $filter $client 100000.0kb 0.0ms DropTail]
tb-set-ip-link $client $link0 10.0.1.1
tb-set-ip-link $filter $link0 10.0.1.2

set link1 [$ns duplex-link $dr $filter 100000.0kb 0.0ms DropTail]
tb-set-ip-link $filter $link1 10.0.2.1
tb-set-ip-link $dr $link1 10.0.2.2

# Lans
set internet [$ns make-lan "$covert $decoy $dp $dr" 100000.0kb 0.0ms]
tb-set-ip-lan $dr $internet 10.0.0.1
tb-set-ip-lan $dp $internet 10.0.0.2
tb-set-ip-lan $decoy $internet 10.0.0.3
tb-set-ip-lan $covert $internet 10.0.0.4
tb-set-netmask $internet "255.255.255.0"

# Static-old configures once at exp. creation time
$ns rtproto Static-old
$ns run
"""



            
class HelloWorld(CurveballBasics):
    def __init__(self, opts=None):
        self.opts = opts
        if opts is None:
            parser = OptionParser()
            self.add_parse_opts(parser)        
            (self.opts, _) = parser.parse_args()
        
        super(HelloWorld, self).__init__(self.opts)
        
        # Add some servers to the list
        self.servers.append('decoy')
        self.servers.append('covert')
        
        # Add some commands
        self.cmds['speed_test'] = 'iperf throughput test between client and covert via curveball'


    
    def install(self, args):
        super(HelloWorld, self).install(args)

        # We've added decoy and covert, so run make on them        
        if self.transport == 'ssh': # DETER
            threads = []

            for machine in ['decoy','covert']:
                t = Thread(target=self.run, args=(machine, 'cd %s ; make' % self.prefix, True))
                t.start()
                threads.append(t)

            for thread in threads:
                thread.join()
        
    
    def start(self, args):
        # Prepare decoy and covert, then call super's start
#        self.run('decoy',
#                'sudo %s/scripts/mini-httpd --rand-filler' % self.prefix)
        self.run('decoy',
                'sudo %s/scripts/mini-httpd' % self.prefix)
        try:
            self.expect('decoy', "mini-httpd started", timeout=5)
        except (pexpect.EOF, pexpect.TIMEOUT):
            print "decoy failed to start."
            print "Expected to see 'mini-httpd started'"
            self.stop(None)
            return

#        self.run('covert',
#                'sudo %s/scripts/mini-httpd --rand-filler' % self.prefix)
        self.run('covert',
                'sudo %s/scripts/mini-httpd' % self.prefix)
        try:
            self.expect('covert', "mini-httpd started", timeout=10)
        except (pexpect.EOF, pexpect.TIMEOUT):
            print "covert failed to start."
            print "Expected to see 'mini-httpd started'"
            print ('This can happen if the filler size is large' +
                    ' and the timeout too short to initialize it')
            self.stop(None)
            return
            
        super(HelloWorld, self).start(args, 'decoy:443')

    def stop(self, args):
        """ Stop the decoy routing services """
        super(HelloWorld, self).stop(args)

        if 'decoy' in self.connections and 'covert' in self.connections:
            for machine in ['decoy', 'covert']:
                self.controlc(machine)
                self.run(machine, 'sudo killall mini-httpd')
                self.run(machine, 'sudo killall python')


        
    def exit(self, args):
        """ exit the program """
        sys.exit(0)
        

    def test_decoy_routing(self, host):
        return super(HelloWorld, self).test_decoy_routing('covert')

    def speed_test(self, args):
        """
        args (optional) = number of times to run speed test
        """

        print "First checking if decoy routing is working..."
        if not self.test(None):
            print "Sorry, decoy routing is not working, cannot perform speed test"
            return None
        
            
        loops = 1
        if args:
            loops = int(args)
            
        client = self.create_spare('client')
        covert = self.create_spare('covert')
        
        covert.run('iperf -s -p 55221')
        time.sleep(2)
        
        out = []
        
        for i in range(loops):
            if self.opts.vpn:
                client.run('iperf -c covert -p 55221')
            else:    
                client.run('tsocks iperf -c covert -p 55221')
            try:
                client.expect('connected', timeout=10)
                print "IPerf connected.. running test"
            except (pexpect.EOF, pexpect.TIMEOUT):        
                print "Client could not connect to covert iperf server"
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
        
    def add_parse_opts(self, parser):
        super(HelloWorld, self).add_parse_opts(parser)
        
        
        return parser


def main():
    hello = HelloWorld()    
    hello.connect()

    if not hello.opts.batch:
        hello.interact()
    else:
        hello.run_batch_mode(hello.opts.batch)
            

if __name__ == '__main__':
    main()
