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
sys.path.append('../python')

import atexit
import time
import pexpect
import socket
from optparse import OptionParser
from cb.util.cb_experiment import CurveballExperiment


""" mini-vpn Experiment Interaction Script

For instructions on its use, please refer to: 
https://curveball.ir.bbn.com/projects/curveball/wiki/HelloWorldExp


DETER topology not defined

For core,

                  .10                 .11
rj45 --------- vpn-client -------- vpn-server -------- rj45
10.0.4.2                  10.0.0.x                 10.0.3.2

so vpn-client has
    10.0.0.10 on eth0 (facing the server)
    10.0.4.10 on eth1 (facing the 10.0.4.15 gw)

so vpn-server has
    10.0.0.11 on eth0 (facing the client)
    10.0.3.11 on eth1 (facing the 10.0.4.15 gw)

"""

class MiniVPN(CurveballExperiment):
    def __init__(self, transport, exp_name, prefix):
        
        self.servers = ['vpn_client', 'vpn_server']

        cmds = {'connect': 'ssh into each machine',
                'disconnect': 'close each ssh session',
                'load': 'installs packages, sets up the firewall, and starts the proxy',
                'unload': 'stops the firewall',
                'start': 'run the vpn software',
                'stop': 'stops the vpn software',
                'test': 'runs netcat from client to server',
                'exit': 'exits this program',
                'profile': 'toggles profiler on/off, off by default',
                "commandeer": "usage: commandeer {hostname} - use ^] to exit"}

        super(MiniVPN, self).__init__(transport, self.servers, exp_name, cmds, prefix)
        self.prefix = prefix
        atexit.register(self.stop, None)

        self.profile_str = ''

    def load(self, args):
        """ Install necessary software """

        # Nothing to do right now except set up the routes

        # TODO: why isn't this set via the imn file?
        self.run('vpn_client', 'ip route add default via 10.0.4.2')
        self.run('vpn_server', 'ip route add default via 10.0.20.2')

        print "Machines prepared"
    
    def unload(self, args):
        """ Currently only removes firewall rules on filter """

        print "Unimplemented"
        
    def stop(self, args):
        """ Stop the vpn process """
        self.run('vpn_client', 'sudo killall python')
        self.run('vpn_server', 'sudo killall python')
        time.sleep(1)
        
    def profile(self, args):
        print "Not implemented"
        pass
            
    def start(self, args):
        """ Start all of the vpn services """

        print "Not implemented yet"
        pass
    
    def test(self, args):
        """ Start a netcat server on covert and connect to it from client """

        print "Not implemented yet"

    def exit(self, args):
        """ exit the program """
        sys.exit(0)


def parse_args(argv):
    """
    Deduce the parameters from the argv
    """

    parser = OptionParser()
    parser.add_option("-d", "--deter", dest="deter",
            help="DETER Experiment name: e.g., mini-vpn.  If no name is given, assume you are using CORE")

    parser.add_option("-p", "--prefix", dest="prefix",
                      default="~/dev/curveball/src", 
                      help="Location of your src directory, e.g., ~/dev/curveball/src")

    (options, _args) = parser.parse_args(argv)

    return options


def main():
    opts = parse_args(sys.argv)
    exp_name = opts.deter
    transport = 'core'
    if exp_name:
        transport = 'ssh'

    hello = MiniVPN(transport, exp_name, opts.prefix)
    hello.connect()
    hello.interact()

if __name__ == '__main__':
    main()
