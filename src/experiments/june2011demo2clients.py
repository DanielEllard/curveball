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
from optparse import OptionParser
sys.path.append('../python')

from cb.util.cb_experiment import CurveballExperiment


""" 
Topology:

client --\
         |
       filter -- dr -- internet_router -- virtual machine eth1
         |        \-- dp
client2 -/

The eth1 device on the virtual machine must have its gateway at 10.0.3.2 as 
that is what internet_router is configured to send packets to

Note that the CORE simulation will commandeer the eth1 device and put it in
promiscuous mode.  The eth1 device should be a VM NAT device.

"""


class June11Demo2Client(CurveballExperiment):
    def __init__(self, transport, exp_name, prefix):
        
        self.servers = ['dp', 'dr', 'client', 'client2',
                'filter', 'internet']

        cmds = {'install': 'installs packages',
                'start': 'run the dp/dr/client software, configure firewall, start danted',
                'test': 'test a connection to google.com',
                'diagnostics': 'run pings and process checks',
                'stop': 'stops the dp/dr/client software',
                'exit': 'exits this program',
                'profile': 'toggles profiler on/off, off by default',
                "commandeer": "usage: commandeer {hostname} - use ^] to exit"}
                     
        super(June11Demo2Client, self).__init__(transport, self.servers, exp_name, cmds, prefix)
        self.prefix = prefix
        atexit.register(self.stop, None)

        self.profile_str = ''

    

    def install(self, args):
                
        if self.transport == 'ssh': # DETER

            print "ERROR: DETER NOT SUPPORTED YET!"
            sys.exit(1)

            machines = ['dp','dr','client']       
            for machine in machines:
                self.run(machine, 'cd %s ; make %s ; echo "CURVEBALL $HOSTNAME DONE"' % (self.prefix, machine))
            
            #print "dr, dp, and client are building...  Please 'commandeer' each machine and wait for them to finish"
            for machine in machines:
                print "Waiting for %s to finish building/installing..." % machine
                self.expect(machine, 'CURVEBALL %s\..* DONE' % machine)

        elif self.transport == 'core':
            os.system('cd %s ; make' % self.prefix)
            
            
        
    
    def stop(self, args):
        """ Stop the decoy routing services """
        self.run('dp', 'sudo /etc/init.d/danted stop')        
        self.controlc('client')
        time.sleep(1)
        self.run('dr', 'sudo killall click')
        self.controlc('dr')
        self.run('dr', 'sudo killall python ; sudo killall click')
        time.sleep(1)
        self.controlc('dp')
        self.run('client', 'sudo killall python ; sudo killall client-agent')
        self.run('client2', 'sudo killall python ; sudo killall client-agent')
        self.run('dp', 'sudo killall python')

        self.stop_firewall()
        self.run('dr', 'sudo iptables -F')

        
    def profile(self, args):
        if self.profile_str:
            self.profile_str = ''
            print "Profiling off"
        else:
            self.profile_str = '-m cProfile'
            print "Profiling on"
            
            
    def start_firewall(self):
        self.run('filter', 'sudo iptables -F')
        self.run('filter', 'sudo iptables -A FORWARD -d 74.125.0.0/16 -j DROP')
        self.run('filter', 'sudo iptables -A FORWARD -d dp -j DROP')
        self.run('filter', 'sudo iptables -A FORWARD -d 72.0.0.0/8 -j DROP')
        self.run('filter', 'sudo iptables -A FORWARD -d 192.1.100.148 -j DROP')
        
    def stop_firewall(self):
        self.run('filter', 'sudo iptables -F')
        
    def start(self, args):
        self.start_firewall()
        
        """ Start danted on the decoy proxy """
        self.run('dp', 'sudo /etc/init.d/danted stop ; sudo /etc/init.d/danted start')
        
        
        #self.run('dp', 'cd %s/scripts ; sudo python %s cb-dp -s' % (self.prefix, self.profile_str))
        self.run('dp', 'cd %s/scripts ; sudo python %s cb-dp -t' % (self.prefix, self.profile_str))
        try:
            self.expect('dp', "DP Running", timeout=5)
        except (pexpect.EOF, pexpect.TIMEOUT):
            print "Decoy Proxy failed to start.  Expected to see 'DP Running'"
            self.stop(None)
            return
                
        self.run('dr', 'cd %s/scripts ; sudo python %s cb-dr --decoyname=internet 2> /dev/null' % (self.prefix, self.profile_str))
#        self.run('dr', 'cd %s/scripts ; sudo python %s cb-dr -c dr:443 -t 2> /dev/null' % (self.prefix, self.profile_str))
        try:
            self.expect('dr', "DR Running", timeout=5)
        except (pexpect.EOF, pexpect.TIMEOUT):
            print "Decoy Router failed to start.  Expected to see 'DR Running'"
            print "Perhaps click failed to start?  Commandeer dr to find out"
            self.stop(None)
            return
        
        time.sleep(1)
        
        
        self.run('client', 'cd %s/scripts ; python %s curveball-client -d 171.159.228.150:443 -t' % (self.prefix, self.profile_str))
        try:
            self.expect('client', 'welcome to curveball', timeout=5)
            print "Client successfully established covert tunnel"
        except (pexpect.EOF, pexpect.TIMEOUT):
            print "Client did not connect to curveball, expected a welcome message"
            print "Run diagnostics for more information"

        self.run('client2', 'cd %s/scripts ; python %s curveball-client -d 171.159.228.150:443 -t' % (self.prefix, self.profile_str))
        try:
            self.expect('client2', 'welcome to curveball', timeout=5)
            print "Client2 successfully established covert tunnel"
        except (pexpect.EOF, pexpect.TIMEOUT):
            print "Client2 did not connect to curveball, expected a welcome message"
            print "Run diagnostics for more information"
            
            
    
    def test_decoy_routing(self, host):
        """ See if we can fetch a webpage from a blocked destination through curveball """
        if host.strip() == '':
            host = 'google.com'
        
        spare = self.create_spare('client')
            
        print "Testing decoy routing, fetching webpage from %s over proxy ... " % host
        spare.run("printf 'GET / HTTP/1.0\n\n' | nc -q-1 -x localhost:5010 %s 80 | grep -i '<html>' && echo \"CURVEBALL $HOSTNAME SUCCESS\"" % host)
        try:
            spare.expect("CURVEBALL client SUCCESS", timeout=3)
            print "Test successful"
        except (pexpect.EOF, pexpect.TIMEOUT):
            print "Test failed"
            
    def ping(self, src, dst):
        self.stop_firewall()
        spare = self.create_spare(src)
        spare.run('ping %s -c 1' % dst)
        try:
            (_, buffer, _) = spare.expect('time=', timeout=4)
            time = float(buffer.split(' ')[0])
            return time
        except (pexpect.EOF, pexpect.TIMEOUT):
            return None

    def test_pings(self):            
        pairs = []
        for src in self.servers:
            for dst in [x for x in self.servers if x != src]:
                pairs.append((src, dst))
        pairs.append(('client', '10.0.4.2'))
        pairs.append(('client2', '10.0.4.2'))
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
    
    def test(self, args):
        self.start_firewall()
        self.test_decoy_routing(args)
        
        


    def status(self, args):
        """ Make sure all of the decoy routing services are up and running """
        
        
        
    def exit(self, args):
        """ exit the program """
        sys.exit(0)

        
        
        
def parse_args(argv):
    """
    Deduce the parameters from the argv
    """

    parser = OptionParser()

    #default="~/dev/curveball/src", 
    parser.add_option("-p", "--prefix", dest="prefix",
                      default="~/curveball/build", 
                      help="Location of your src directory, default: ../ (works for CORE, your DETER path will be different)")
    
    parser.add_option("-d", "--deter", dest="deter",
            help="DETER Experiment name: e.g., helloworld.  If no name is given, assume you are using CORE")

    (options, _args) = parser.parse_args(argv)

    return options


def main():
    opts = parse_args(sys.argv)
    
    exp_name = opts.deter
    transport = 'core'
    if exp_name:
        transport = 'ssh'

    demo = June11Demo2Client(transport, exp_name, opts.prefix)
    demo.connect()
    demo.interact()


if __name__ == '__main__':
    main()
