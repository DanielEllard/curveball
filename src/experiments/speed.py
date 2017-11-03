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
from helloworld import HelloWorld


""" Curveball SPEED Testing

This is the helloworld class but with some extra speed testing functions
"""


# We add some commands to the HelloWorld Experiment
            
class SpeedTest(HelloWorld):
    def __init__(self):
        parser = OptionParser()
        self.add_parse_opts(parser)        
        (self.opts, _) = parser.parse_args()
        
        super(SpeedTest, self).__init__(opts=self.opts)
        

        # Add some commands
        self.cmds['raw_speed'] = 'iperf over default network'
        self.cmds['ccp_speed'] = 'test performance of ccp'
        self.cmds['ct_speed'] = 'test performance of ct'
        self.cmds['dr2dp_speed'] = 'test performance of dr2dp'
        self.cmds['hijack_speed'] = 'test performance of tcp hijack'
        self.cmds['click_user_speed'] = 'test forwarding performance of click->user_land->raw_socket'
        self.cmds['nfq_speed'] = 'test performance of nfq'
        self.cmds['vpn_speed'] = 'test performance of vpn'
        self.cmds['tcp_glue_speed'] = 'test performance of tcp glue in twisted'
        
    def iperf(self, proxy_server=None, proxy_port=None, skip_server=False):
        """
        Run iperf -s on covert
        Run iperf -c server -p port on client
        """
        client = self.create_spare('client')
        covert = self.create_spare('covert')
        if not skip_server:
            covert.run('iperf -s')
            try:
                covert.expect('Server listening', timeout=3)
            except:
                print "IPERF could not start on server"
                return
        
        if proxy_server and proxy_port:
            client.run('iperf -c %s -p %s -t 20' % (proxy_server,proxy_port))
        else:
            client.run('iperf -c covert -t 20')

        try:
            client.expect('connecting', timeout=3)
        except:
            print "IPERF client could not connect to its destination"
            return
        
        try:
            (before, buffer, after) = client.expect("/sec", timeout=60)
            print "%s/sec" % (' '.join(before.split()[-2:]))
        except:
            print "iperf test failed, commandeering client"
            client.commandeer()
                    
        client.controlc()
        covert.controlc()
          
    def raw_speed(self, args):
        """
        Run iperf from client to server without any curveball components.
        This is our baseline measurement.
        """
        self.iperf()
   
    def ccp_speed(self, args):
        """
        Create a CCP client and a CCP server, run iperf across them
        """
        client = self.create_spare('client')
        covert = self.create_spare('covert')
        
        covert.run('cd %s/scripts ; ./c3td -s localhost:5001 -l 5555' % self.install_dir)
        time.sleep(2) # let c3td come up
        client.run('cd %s/scripts ; ./c3d -r covert:5555 -l 5010' % self.install_dir)
        self.iperf('localhost', 5010)
        client.controlc()
        covert.controlc()
    
    def ct_speed(self, args):
        client = self.create_spare('client')
        covert = self.create_spare('covert')
        covert2 = self.create_spare('covert')
        covert.run('cd %s/scripts ; ./ct_dp_test.py -l 7878 -s localhost:5001' % self.install_dir)
        try:
            covert.expect('HTTPS Running', timeout=10)
        except:
            print "HTTPS not running"
            covert.interact()
            return
        time.sleep(1)

        covert2.run('iperf -s ')
        try:
            covert2.expect('Server listening', timeout=3)
        except:
            print "IPERF could not start on server"
            return


        client.run('cd %s/openssl/openssl-1.0.0d/dmtest/ ;  LD_LIBRARY_PATH=.. ./client-agent -h covert -p 7878' % self.install_dir)
        try:
            client.expect('welcome to curveball', timeout=10)
        except:
            print 'client-agent could not connect'
            client.interact()
            return
        
        time.sleep(1)
        
        # client-agent awaits on port 4435
        self.iperf('localhost', 4435, skip_server=True)
        
        client.controlc()
        covert.controlc()
        covert2.controlc()
        
    def tcp_glue_speed(self, args):
        """ Run tcp_glue on the router, which connects the client and covert iperfs.  This
        is to get a feel for how fast/slow gluing two tcp streams is """
        dr = self.create_spare('dr')
        dr.run('cd %s/scripts ; ./tcp_glue.py -s localhost:4444 -d decoy:4444' % self.install_dir)

        
        try:
            dr.expect('Glue Ready', timeout=5)
        except:
            print 'Glue did not start'
            dr.interact()
            return
        
        decoy = self.create_spare('decoy')
        decoy.run('cd %s/scripts ; ./tcp_glue.py -s localhost:4444 -d covert:5001' % self.install_dir)

        try:
            decoy.expect('Glue Ready', timeout=5)
        except:
            print 'Glue did not start'
            decoy.interact()
            return

        
        
        self.iperf('dr', 4444)

        dr.controlc()
        decoy.controlc()
        
    def nfq_speed(self, args):
        """ Run a simple hijack test on the DR.  Whatever flow the DR sees to decoy
        (after the TCP handshake) gets hijacked and sent to covert """
        client = self.create_spare('client')
        dr = self.create_spare('dr')
        decoy = self.create_spare('decoy')
        dr.run('cd %s/scripts ; sudo ./hijack_test.py -d decoy -t covert -p 5001 -r' % self.install_dir)
        try:
            dr.expect("Hijack Test Running", timeout=10)
        except:
            print "Hijack Test Not Running, interacting with DR:"
            dr.interact()
            return
        
        decoy.run('iperf -s -p 5001')
        
        time.sleep(1)
        
        self.iperf('decoy', 5001)
        
        dr.controlc()
        decoy.controlc()
        
    def click_user_speed(self, args):
        dr = self.create_spare('dr')
        dr.run('cd %s/scripts ; sudo ./click_kernel_forward_test.py -d eth1' % self.install_dir)
        try:
            dr.expect('Running', timeout=10)
        except:
            print 'click_kernel_forward.py not running, interacting with DR:'
            dr.interact()
            return
        
        self.iperf()
        dr.controlc()
        
    def dr2dp_speed(self, args):
        """ Run click in kernel_forward mode, and give all packets to DR2DP to forward
        to the decoy proxy end """
        
        self.run('dp', 'cd %s/python/cb/dr2dp/ ; sudo PYTHONPATH=../../ ./dr2dp_dp.py --raw' % self.install_dir)
        time.sleep(1)
        self.run('dr', 'cd %s/scripts/ ; sudo ./dr.py -k -s ../click/curveball/forwarding-speed.click' % self.install_dir)

        self.iperf()
        
        self.controlc('dp')
        self.controlc('dr')
            
    def hijack_speed(self, args):
        """ Run a simple hijack test on the DR.  Whatever flow the DR sees to decoy
        (after the TCP handshake) gets hijacked and sent to covert """

        decoy = self.create_spare('decoy')

        self.run('dp', 'cd %s/scripts ; sudo ./hijack_test.py -d decoy -t covert 5001 -l 4000' % self.install_dir)
        time.sleep(1)
        self.run('dr', 'cd %s/scripts ; sudo ./click_kernel_forward_test.py -a dp -p 4000' % self.install_dir)
        
        decoy.run('iperf -s -p 5001')
        
        time.sleep(1)
        
        self.iperf('covert', 5001)

        self.controlc('dp')
        self.controlc('dr')
        decoy.controlc()

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
        time.sleep(1)
        
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



def main():
    speed = SpeedTest()    
    speed.connect()

    if not speed.opts.batch:
        speed.interact()
    else:
        speed.run_batch_mode(speed.opts.batch)
            

if __name__ == '__main__':
    main()
