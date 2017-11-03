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
import os.path
from threading import Thread
import subprocess
import glob

from optparse import OptionParser

sys.path.append('../python')

from cb.util.cb_experiment import CurveballExperiment, one_shot_ssh


class CurveballBasics(CurveballExperiment):
    def __init__(self, opts, use_firewall=True, use_client=True):
        self.servers = ['dp', 'dr', 'client', 'filter']
        self.cmds = {'install': 'copies (deter only) and installs packages',
                'start': 'run the dp/dr/client software, configure firewall, start danted',
                'test': 'test a covert tunnel via a web request',
                #'diagnostics': 'run pings and process checks',
                'stop': 'stops the dp/dr/client software',
                'exit': 'exits this program',
                'profile': 'toggles profiler on/off, off by default',
                'rsync': 'rsync files to deter and hosts on deter',
                'interact': 'when in batch mode, shows this interactive prompt',
                #'start_network': 'start core or deter and wait for them to settle',
                'stop_network': 'stop core or deter',
                "commandeer": "usage: commandeer {hostname} - use ^] to exit"}
        
        
        self.started_core = False
        self.started_deter = False

        # For trawling, we do NOT need a firewall or a client.
        self.use_firewall = use_firewall
        self.use_client = use_client

        # If we start batch core, hang on to the session id
        # so we can kill it later
        exp_name = opts.deter
        
        transport = 'core'
        if exp_name:
            transport = 'ssh'

        if transport == 'core' and opts.kernel:
            print "Should not run on CORE with DR in kernel mode, exiting"
            sys.exit(1)
                         
        super(CurveballBasics, self).__init__(transport, self.servers, exp_name, self.cmds, opts.prefix)


        # Make sure we're in the experiment directory
        assert(os.path.isfile('curveball_basics.py'))
        assert(os.path.isfile('june2012demo.imn'))

        
        if self.transport == 'ssh': # DETER
            self.install_dir = '/opt/curveball'
        else:
            self.install_dir = self.prefix
            
        atexit.register(self.stop, None)
        #atexit.register(self.stop_started_network)
        
        self.profile_str = ''
        self.kernel = opts.kernel
        self.vpn = opts.vpn
        #self.nss = opts.nss
        self.http = opts.http
        self.crypto = opts.crypto
        
        if opts.start_network:
            self.start_network(opts.start_network)
        

    def add_parse_opts(self, parser):
        """
        Deduce the parameters from argv
        """
    
        parser.add_option("-p", "--prefix", dest="prefix", default='../',
                          help="Location of your src directory, default: ../ (works for CORE, your DETER path will be different)")
        
        parser.add_option("-d", "--deter", dest="deter",
                help="DETER Experiment name: e.g., helloworld.  If no name is given, assume you are using CORE")
    
        parser.add_option("-w", "--http",
                          action="store_true",
                          default=False,
                          help="Use http")
        parser.add_option("--windows",
                          action="store_true",
                          default=False,
                          help="Running on windows")
        parser.add_option("-x", "--crypto",
                          action="store_true",
                          default=False,
                          help="Use crypto with http")
    
        parser.add_option("-k", "--kernel",
                          action="store_true",
                          help="Use the kernel router")
    
        parser.add_option("-v", "--vpn",
                          action="store_true",
                          help="Use vpn client")
        parser.add_option("--nogui", action="store_true",
                          default=False,
                          help="No CORE GUI when in -s mode")
        parser.add_option("-b", "--batch", default='', 
                          help='Run in batch mode (no gui for core). ex: -b install,start,speed_test,stop')        
        
        parser.add_option("-s", "--start_network",
                            help="Start CORE or DETER at launch.  Argument is in file for CORE or experiment name for DETER")



        return parser        
        

    def rsync(self, args):
        
        if self.transport == 'ssh': # DETER
            # First upload the files
            print "Uploading files to DETER"
            subprocess.call('cd ../scripts ; ./sync-deter.py', shell=True)          
            
            # Copy the files to /tmp/
            machines = ['dp','dr','client','covert','decoy']
            threads = []
            
            nfs_dir = self.prefix[:self.prefix.rfind('/src')]
            local_dir = self.install_dir[:self.install_dir.rfind('curveball/src')]
            topdir = self.install_dir[:self.install_dir.rfind('/src')]
            
            for machine in machines:
                self.run(machine, 'sudo mkdir -p %s ; whoami | xargs -I {} sudo chown {} %s' % (topdir, topdir)) 
                t = Thread(target=self.run, args=(machine, 'rsync -avz %s %s' % (nfs_dir, local_dir), True))
                t.start()
                threads.append((t, machine))
            print "Waiting for %d machines to finish copying to local directories" % len(threads)
            
            for (t, machine) in threads:
                print "Waiting for %s to finish copying" % machine
                t.join()

        

    def install(self, args):                
        if self.transport == 'ssh': # DETER
            self.rsync(None)
            
            machines = ['dp','dr','client']

            # Run make
            threads = []          
            
            for machine in machines:               
                t = Thread(target=self.run, args=(machine, 'cd %s ; make %s' % (self.install_dir, machine), True))
                t.start()
                #self.run(machine, 'cd %s ; make %s' % (self.install_dir, machine), True)
                threads.append((t, machine))
                
            print "Waiting for %d machines to finish installing" % len(threads)
            
            for (t, machine) in threads:            
                print "Waiting for %s" % machine
                t.join()

        elif self.transport == 'core':
            os.system('cd %s ; make all' % self.install_dir)
            
            
        
    
    def stop(self, args):
        if not self.connections:
            return
        
        """ Stop the decoy routing services """
        self.run('dp', 'sudo /etc/init.d/danted stop')
        self.controlc('client')
        time.sleep(1)
        self.controlc('dr')
        self.run('dr', 'sudo click-uninstall')
        time.sleep(5)
        self.run('dr', 'sudo killall click')
        self.run('dr', 'sudo killall python ; sudo killall click')
        time.sleep(1)
        self.controlc('dp')
        self.run('client', 'sudo killall python ; sudo killall client-agent')
        self.run('dp', 'sudo killall python')

        if not self.use_firewall:
            self.stop_firewall()

        self.run('dr', 'sudo iptables -F')

        print "Experiment done, exiting"

        
    def profile(self, args):
        if self.profile_str:
            self.profile_str = ''
            print "Profiling off"
        else:
            self.profile_str = '-m cProfile -o %s.profile' % sys.argv[0]
            print self.profile_str
            print "Profiling on"
            
            
    def start_firewall(self):
        if not self.use_firewall:
            return

        self.run('filter', 'sudo iptables -F')
        self.run('filter', 'sudo iptables -A FORWARD -d covert -j DROP')
        self.run('filter', 'sudo iptables -A FORWARD -d 74.125.0.0/16 -j DROP')
        self.run('filter', 'sudo iptables -A FORWARD -d dp -j DROP')
        self.run('filter', 'sudo iptables -A FORWARD -d 72.0.0.0/8 -j DROP')
        self.run('filter', 'sudo iptables -A FORWARD -d 192.1.100.148 -j DROP')
        
    def stop_firewall(self):
        if not self.use_firewall:
            return

        self.run('filter', 'sudo iptables -F')


    def start(self, args, decoy='171.159.227.150:443'):
        if self.use_firewall:
            self.start_firewall()
        
        """ Start danted on the decoy proxy """
        self.run('dp', 'sudo /etc/init.d/danted stop ; sudo /etc/init.d/danted start')

        try:
            i = decoy.index(':')
            decoyname = decoy[:i]
        except ValueError:
            return (decoy, None)

        #print decoyname  

        # debug replace python with pdb
        use_pdb = False


        if not self.crypto:
            if use_pdb:
                self.run('dp', 'cd %s/scripts ; sudo pdb decoyproxy.py -t' % self.install_dir)
                self.run('dp', 'b /usr/lib/python/dist-packages/twisted/python/failure.py:499')
                self.run('dp', 'r -t')
            else: 
                self.run('dp', 'cd %s/scripts ; sudo python decoyproxy.py -s' % self.install_dir)
                self.run('dp', 'cd %s/scripts ; sudo python %s decoyproxy.py -t' % (self.install_dir, self.profile_str))
        else:
            if use_pdb:
                self.run('dp', 'cd %s/scripts ; sudo pdb decoyproxy.py -t' % self.install_dir)
                self.run('dp', 'b /usr/lib/python/dist-packages/twisted/python/failure.py:499')
                self.run('dp', 'r -t')
            else: 
                self.run('dp', 'cd %s/scripts ; sudo python decoyproxy.py -s' % self.install_dir)
                self.run('dp', 'cd %s/scripts ; sudo python %s decoyproxy.py -t -x' % (self.install_dir, self.profile_str))
    
            
        try:
            self.expect('dp', "DP Running", timeout=10)
            
        except (pexpect.EOF, pexpect.TIMEOUT):
            print "Decoy Proxy failed to start.  Expected to see 'DP Running'"
            self.stop(None)
            return
                
        time.sleep(2)
        
        # The DR needs to listen on the interface coming from the adversary (filter)
        # Figure out what that interface is
        
        kernel_flag = ''
        if self.kernel:
            kernel_flag = '-k'

#        cmd = 'cd %s/scripts ; sudo python %s dr.py %s 2> /dev/null' % (self.install_dir,  self.profile_str, kernel_flag)
        cmd = 'cd %s/scripts ; sudo python %s dr.py --decoyname=%s %s 2> /dev/null' % (self.install_dir,  self.profile_str, decoyname, kernel_flag)
        self.run('dr', cmd)
        try:
            self.expect('dr', "DR Running", timeout=5)
        except (pexpect.EOF, pexpect.TIMEOUT):
            print "Decoy Router failed to start.  Expected to see 'DR Running'"
            print "Perhaps click failed to start?  Commandeer dr to find out"
            self.stop(None)
            return
        
        #        time.sleep(1)
        time.sleep(5)
                
        
        vpn_flag = ''
        nss_flag = ''
        if self.vpn:
            vpn_flag = '-v'
        #if self.nss:
        #nss_flag = '-n'
        
        if self.use_client:

            # reset the key each time the experiment starts.
            #
            cb.run('client', 'sudo %s/scripts/client-key-config -c cbtest0' %
                    self.install_dir)

            if not self.http:          
                print 'Using TLS'
                self.run('client',
                         'cd %s/scripts ; sudo python %s client.py -d %s %s %s'
                         % (self.install_dir, self.profile_str,
                         decoy, vpn_flag, nss_flag))
            else:
                print 'Using HTTP'
                decoy = 'www.google.com:80'
                decoy = 'www.nytimes.com:80'

                if not self.crypto:
                    self.run('client',
                             'cd %s/scripts ; sudo python %s client.py -w -d %s %s %s'
                             % (self.install_dir, self.profile_str,
                                decoy, vpn_flag, nss_flag))
                else:
                    self.run('client',
                             'cd %s/scripts ; sudo python %s client.py -w -x -d %s %s %s'
                             % (self.install_dir, self.profile_str,
                                decoy, vpn_flag, nss_flag))
            
            try:
                if self.vpn:
                    self.expect('client', 'VPN ESTABLISHED', timeout=10)
                else:
                    self.expect('client', 'CCP has connected', timeout=8)
                                
                print "Client successfully established covert tunnel"
            except (pexpect.EOF, pexpect.TIMEOUT):
                print "Client did not connect to curveball, expected a welcome message"


    def test_decoy_routing(self, host):
        """ See if we can fetch a webpage from a blocked destination through curveball """
        if not host or host.strip() == '':
            host = 'google.com'
        
        spare = self.create_spare('client')

        print "Testing decoy routing, fetching webpage from %s over proxy ... " % host
        spare.run('TESTSUCCESS=CURVESUCCESS')
        spare.expect("CURVESUCCESS") 
        if not self.opts.vpn:
            cmd = "printf 'GET / HTTP/1.0\n\n' | nc -q-1 -x localhost:5010 %s 80 | grep -i '<html>' && echo $TESTSUCCESS" % host
        else:
            cmd = "printf 'GET / HTTP/1.0\n\n' | nc -q-1 %s 80 | grep -i '<html>' && echo $TESTSUCCESS" % host
        #print cmd
        spare.run(cmd)
        try:
            spare.expect("CURVESUCCESS", timeout=10)
            print "Test successful"
            return True

        except (pexpect.EOF, pexpect.TIMEOUT):
            print "Test failed"
            return False
            
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

    
    def test(self, args):
        self.start_firewall()
        return self.test_decoy_routing(args)
                
        
    def exit(self, args):
        """ exit the program """
        sys.exit(0)
    
    def run_batch_mode(self, cmds):
        """ Given a comma separated list of commands, run them in order """
        cmds = cmds.split(',')
        for cmd in cmds:
            print "Running command '%s'..." % cmd
            getattr(self,cmd)(None)
            
    def update_hosts(self, imn):
        """ Find the hosts in the given imn file and make sure they're in /etc/hosts """

        # First load up the existing /etc/hosts and remove anything leftover
        # from previous runs    
        hosts = []
            
        for line in file('/etc/hosts'):
            if 'curveball_exp' in line:
                continue
            hosts.append(line)
        
        # Now parse the needed hosts
        core_hosts = []
        cur_host = None
        
        for line in file(imn):
            if line.startswith('node'):
                cur_host = line.split()[1]
            if line.startswith('}\n'):
                cur_host = None
            if 'hostname' in line and cur_host:
                cur_host = line.split()[1]
            if 'ip address' in line and cur_host:
                ip = line.split()[2].split('/')[0]
                core_hosts.append((cur_host, ip))
                cur_host = None
        
        for (host,ip) in core_hosts:
            hosts.append('%s %s #curveball_exp\n' % (ip,host))
        
        file('/tmp/hosts.core','w').writelines(hosts)
        subprocess.call('sudo cp /etc/hosts /etc/hosts.curveball.bak && sudo cp /tmp/hosts.core /etc/hosts', shell=True)
                
               
    def start_network(self, args):
        if self.transport == 'core':
            imn = sys.argv[0].replace('.py', '.imn')
            if args:
                imn = args.strip()
                imn = os.path.abspath(imn)
                
            self.stop_network(None)
            subprocess.call('sleep 3; sudo /etc/init.d/core start ; sleep 3', shell=True)

#            cmd = 'LIBDIR=/usr/lib/core wish8.5 /usr/lib/core/core.tcl --start %s' % imn
            if self.opts.nogui:
                subprocess.call('core -b %s' % imn, shell=True)

            else:
                cmd = "core -s %s" % imn
                subprocess.Popen(cmd, shell=True)
            
            # Update /etc/hosts
            self.update_hosts(imn)
            
            # Login to a core node and ping
            for i in range(20):
                try:
                    spare = self.create_spare('client')                    
                except:
                    if i == 19:
                        print "CORE failed to start, exiting"
                        sys.exit(1)
                    print "Failed to connect to core, trying again.."
                    time.sleep(1)
            print "Connected to client, now testing routing"
            
            # Ping the decoy router, once that works routing
            # should be up and we should be all set
            for i in range(120):
                try:
                    spare = self.create_spare('client')
                    spare.run('ping -c 1 dr')
                    spare.expect('packet loss', timeout=1)
                    output = spare.session.before
                    if 'Unreachable' in output:
                        # 100% packet loss, try again!
                        raise Exception('packet loss, try again')
                    if '1 received' in output:
                        print "Routing established, ping returned"
                        break
                except:
                    if i == 119:
                        print "Routing failed to propagate, exiting"
                        sys.exit(1)
                    print "Client failed to ping DR, still waiting for OSPF to propagate"
                    time.sleep(5)
            
            print "Core up and running"                
            self.started_core = True
            


        elif self.transport == 'ssh':
            ns = sys.argv[0].replace('.py', '.ns')
            if args:
                ns = args.strip()
            
            self.stop_network(None)

            # 0. copy ns file to users.isi.deterlab.net
            # 1. login to users.isi.deterlab.net
            # 2. stop existing experiment with this name
            # 3. start experiment
            
            # Copy the ns file over
            ret = subprocess.call('scp %s users.isi.deterlab.net:' % ns, shell=True)
            if ret != 0:
                print "Failed to copy NS file to deter, exiting"
                sys.exit(1)
            
            cmd = '/usr/testbed/bin/startexp -N -w -i -a 240 -E "regression test"'
            cmd += ' -e %s -p SAFER -g curveball %s' % (self.exp_name, ns)
            
            print "Starting DETER experiment %s" % self.exp_name
            (ec, out, err) = one_shot_ssh('users.isi.deterlab.net', 
                                          cmd)
            if ec != 0:            
                print "Failed to start DETER experiment:\n%s" % out
                sys.exit(1)
                            
            self.started_deter = True
            
    
    def stop_network(self, args):
        if self.transport == 'core':
            sessions = glob.glob('/tmp/pycore*')
            for session in sessions:
                id = session.split('.')[-1]
                print "Closing CORE session %s" % id
                subprocess.call('core --closebatch %s' % id, shell=True)
                    
#            subprocess.call("killall vcmd", shell=True)

            cmd = "ps ax | grep .*wish.*core\.tcl | grep -v grep | awk '{print $1}' | xargs -I {} kill -9 {} ; sleep 1"
            subprocess.call(cmd, shell=True)
            subprocess.call('sleep 1; sudo /etc/init.d/core stop ; sleep 1', shell=True)
            subprocess.call('sudo core-cleanup.sh -d ; sleep 1', shell=True)
            #subprocess.call('sleep 1; sudo /etc/init.d/core stop ; sleep 1', shell=True)

        elif self.transport == 'ssh':
            (ec, out, err) = one_shot_ssh('users.isi.deterlab.net',
                                          '/usr/testbed/bin/endexp -N -w -e SAFER,%s' % self.exp_name)

            print "Killing any existing DETER experiment, result: "
            print out
        

#    def stop_started_network(self):
#        """ Quitting experiment, stop any networks that we started """
#        if self.started_core or self.started_deter:
#            self.stop_network(None)
