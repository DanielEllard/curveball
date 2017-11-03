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
import random
import getpass
import types

from optparse import OptionParser

sys.path.append('../python')

from cb.util.cb_experiment import CurveballExperiment, one_shot_ssh

class CLIENT(object):
    """Start and stop a client"""
    @staticmethod
    def stop(client, cb):
        cb.controlc(client)
        cb.run(client, 'sudo killall python ; sudo killall client-agent')

    @staticmethod
    def start(cb, decoy, use_http, use_vpn, use_deadbeef):

        vpn_flag = '-v' if use_vpn else ''
        crypto_flag = '' if use_deadbeef else '-x'
        http_flag = '-w' if use_http else ''
        port = 80 if use_http else 443

        if not use_http:          
            print 'Using TLS'
        else:
            print 'Using HTTP'

        # reset the key each time the experiment starts.
        #
        cb.run('client', 'sudo %s/scripts/curveball-key-config -c cbtest0' %
                cb.install_dir)

        cb.run('client',
               'cd %s/scripts ; sudo python %s curveball-client %s %s -d %s:%d %s' %
               (cb.install_dir, cb.profile_str, vpn_flag, crypto_flag,
                   decoy, port, http_flag))

        try:
            if use_vpn:
                cb.expect('client', 'VPN ESTABLISHED', timeout=10)
            else:
                cb.expect('client', 'CCP has connected', timeout=8)
                
                print "Client successfully established covert tunnel"
        except (pexpect.EOF, pexpect.TIMEOUT):
            print "Client did not connect to curveball, expected a welcome message"

class WEBHOST(object):
    """Start and stop a covert host"""
    @staticmethod
    def stop(webserver, cb):
        cb.controlc(webserver)
        cb.run(webserver, 'sudo killall python ; sudo killall mini-httpd')

    @staticmethod
    def start(webserver, cb, do_filler):

        keys = "--key-path %s/auth/nodes/%s.key" % (cb.install_dir, webserver)
        certs = "--cert-path %s/auth/nodes/%s.pem" % (cb.install_dir, webserver)
        if do_filler:
            filler = '--rand-filler --filler 100000'
        else:
            filler = ''
        cb.run(webserver, 'cd %s/scripts ; sudo ./mini-httpd -q %s %s %s' %
                (cb.install_dir, keys, certs, filler))
        cb.expect(webserver, "mini-httpd started", timeout=30)

class COVERT(object):
    """Start and stop a covert host"""
    @staticmethod
    def stop(covert, cb):
        WEBHOST.stop(covert, cb)

    @staticmethod
    def start(covert, cb):
        WEBHOST.start(covert, cb, False)

class DECOY(object):
    @staticmethod
    def stop(decoy, cb):
        WEBHOST.stop(decoy, cb)

    @staticmethod
    def start(decoy, cb):
        WEBHOST.start(decoy, cb, False)

class DP(object):
    @staticmethod
    def stop(dp, cb):
        cb.controlc(dp)
        cb.run(dp, 'sudo /etc/init.d/danted stop')
        cb.run(dp, 'sudo killall python')

    @staticmethod
    def start(dp, cb, crypto, use_pdb, use_deadbeef):
        cb.run(dp, 'sudo /etc/init.d/danted stop ; sudo /etc/init.d/danted start')

        crypto_flag = '--permit-deadbeef' if use_deadbeef else ''

        if use_pdb:
            cb.run(dp, 'cd %s/scripts ; sudo pdb cb-dp %s -t' % (
                    cb.install_dir, crypto_flag))
            cb.run(dp, 'b /usr/lib/python/dist-packages/twisted/python/failure.py:499')
            cb.run(dp, 'r -t')
        else: 
            cb.run(dp, 'cd %s/scripts ; sudo python cb-dp -s' % cb.install_dir)
            cb.run(dp, 'cd %s/scripts ; sudo python %s cb-dp %s -t' % (
                    cb.install_dir, cb.profile_str, crypto_flag))
        try:
            cb.expect(dp, "DP Running", timeout=20)
            
        except (pexpect.EOF, pexpect.TIMEOUT):
            print("Decoy Proxy %s failed to start.  Expected to see 'DP Running'"
                  % dp)
            # FIXME --- Decide the right approach here
            # cb.stop(None)
            # return
            raise
        time.sleep(1)

class DR(object):
    @staticmethod
    def stop(dr, cb):
        cb.controlc(dr)
        cb.run(dr, 'sudo click-uninstall')
        time.sleep(5)
        cb.run(dr, 'sudo killall click')
        cb.run(dr, 'sudo killall python ; sudo killall click')
        time.sleep(1)
        
    @staticmethod
    def start(dr, cb, use_kernel, dpname, decoyname, use_deadbeef):
        if use_kernel:
            kernel_flag = '-k'
        else:
            kernel_flag = ''
        crypto_flag = '--permit-deadbeef' if use_deadbeef else ''

        # The DR needs to listen on the interface coming from the
        # adversary (filter) 
        # Figure out what that interface is, and what interface
        # points toward the client, by passing in the names of those
        # hosts.

        clientname_arg = '--clientname %s' % 'client' # still hardwired
        decoyname_arg = '--decoyname %s' % decoyname

        # tell this dr where its dp is
        dp_arg = '--decoyproxy %s:4001' % dpname

        cmd = ('cd %s/scripts ; sudo %s ./cb-dr %s %s %s %s %s 2> /dev/null' %
                (cb.install_dir, cb.profile_str,
                    crypto_flag, clientname_arg, decoyname_arg, dp_arg, kernel_flag))
        cb.run(dr, cmd)
        try:
            cb.expect(dr, "DR Running", timeout=5)
        except (pexpect.EOF, pexpect.TIMEOUT):
            print "Decoy Router failed to start.  Expected to see 'DR Running'"
            print "Perhaps click failed to start?  Commandeer dr to find out"
            # FIXME --- what is the right approach here?
            # cb.stop(None)
            # return
            raise
        
        #   time.sleep(1)
        time.sleep(2)
        
    @staticmethod
    def flush_iptables(dr, cb):
        cb.run(dr, 'sudo iptables -F')

class FIREWALL(object):
    @staticmethod
    def stop(firewall, cb):
        if cb.use_firewall:
            cb.run(firewall, 'sudo iptables -F')

    @staticmethod
    def start(firewall, cb, to_be_blocked):
        if not cb.use_firewall:
            return

        cb.run(firewall, 'sudo iptables -F')
        for block in to_be_blocked:
            cb.run(firewall, 'sudo iptables -A FORWARD -d %s -j DROP' % block)

        # cb.run(firewall, 'sudo iptables -A FORWARD -d 74.125.0.0/16 -j DROP')
        # cb.run(firewall, 'sudo iptables -A FORWARD -d 72.0.0.0/8 -j DROP')
        # cb.run(firewall, 'sudo iptables -A FORWARD -d 192.1.100.148 -j DROP')

class QUILT(object):
    @staticmethod
    def stop(quilt, client, cb):
        cb.run(client, 'sudo killall python')
        cb.run(quilt, 'sudo killall python')

    @staticmethod
    def start(quilt, client, decoys, cb,
              dstr=None,
              xterm=None,
              manual=False,
              use_http=True,
              use_https=True):
        # start dante on the quilt server
        cb.run(quilt, 'cd %s/scripts ; sudo python cb-dp -s' % cb.install_dir)
        cb.run(quilt,
               'cd %s/scripts ; sudo python quilt-server'
               % cb.install_dir)
        time.sleep(1)

        # if the caller doesn't provide a string listing all the
        # decoy/protocol combinations to use, then try using all
        # of the possible combinations
        #
        if not dstr:
            https_list = []
            http_list = []
            if use_https:
                https_list = ['%s:https' % x for x in decoys]
            if use_http:
                http_list =  ['%s:http' % x for x in decoys]
            dstr = ','.join(https_list + http_list)

        if manual:
            print "***** You've asked to start ctm and quilt-client by hand *****"
        else:
            if xterm:
                cb.run(client,
                       "cd %s/scripts ; sudo -u %s xterm -display %s -hold -e '../experiments/start-quilt %s %s %s' &"
                       % (cb.install_dir,
                          getpass.getuser(),
                          xterm,
                          dstr,
                          quilt,
                          client))
            else:
                cb.run(client,
                       'cd %s/scripts ; sudo ./ctm 2>&1 > /tmp/ctm-%s-$$ &'
                       % (cb.install_dir, client))
                time.sleep(2)

                # FIXME: we never use -x (self.crypto)
                cb.run(client,
                       'cd %s/scripts ; sudo ./quilt-client -d %s --quilt-host=%s 2>&1 > /tmp/quilt-client-%s-$$ &'
                       % (cb.install_dir, dstr, quilt, client))
                time.sleep(1)

class CurveballNet(CurveballExperiment):
    def __init__(self,
                 # expected opts, obtainable from add_parse_opts
                 # .deter (experiment name on DETER)
                 # .kernel (boolean -- use kernel-mode DR)
                 # .prefix (string -- pathname for executables/scripts)
                 # .vpn (booean -- use VPN)
                 # .http (boolean -- use HTTP client)
                 # .crypto (boolean -- use crypto (True) or 0xdeadbeef (False)
                 # .start_network (boolean -- start network)
                 opts,
                 # a dictionary, mapping dr to dp
                 drs={'dr': 'dp' },
                 # a list of covert hosts
                 coverts=['covert'],
                 # the quilting host
                 quilt='quilt',
                 use_firewall=True,
                 use_client=True,
                 dr2decoy={'dr' : 'decoy'}):

        """Define an experimental network --- see source code for documentation"""

        self.use_deadbeef = opts.use_deadbeef

        self.servers = ['client', 'filter']
        self.drs = drs
        self.decoys = dr2decoy.values()
        self.coverts = coverts
        self.quilt = quilt
        self.dr2decoy = dr2decoy
        # used to decide which decoy hosts and services to use ---
        # default is all services on all decoys (unless the user
        # selects a specific protocol)
        self.decoy_spec = None
        self.cmds = {
            'install': 'copies (deter only) and installs packages',
            'qstart': 'run the quilting software, dp/dr/client software, configure firewall, start danted',
            'start': 'run the dp/dr/client software, configure firewall, start danted without starting quilting',
            'test': 'test a covert tunnel via a web request',
            #'diagnostics': 'run pings and process checks',
            'stop': 'stops the dp/dr/client software',
            'exit': 'exits this program',
            'profile': 'toggles profiler on/off, off by default',
            'rsync': 'rsync files to deter and hosts on deter',
            'interact': 'when in batch mode, shows this interactive prompt',
            #'start_network': 'start core or deter and wait for them to settle',
            'stop_network': 'stop core or deter',
            'add_sentinels': 'usage: add_sentinels [num_hours]',
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
                         
        self.servers += drs.keys()
        self.servers += drs.values()
        self.servers += dr2decoy.values()
        self.servers += coverts
        self.servers += [ quilt ]

        # If we're not running with a full setup, then some of the
        # servers might be None.  Remove "None"s from the list of servers
        # we need to monitor.
        #
        self.servers = [ server for server in self.servers if server ]

        super(CurveballNet, self).__init__(transport,
                                           self.servers,
                                           exp_name,
                                           self.cmds,
                                           opts.prefix)

        # Make sure we're in the experiment directory
        assert(os.path.isfile('curveball_basics.py'))
        assert(os.path.isfile('quilt-demo.imn'))
        
        if self.transport == 'ssh': # DETER
            self.install_dir = '/opt/curveball'
        else:
            self.install_dir = self.prefix
            
        atexit.register(self.stop, None)
        #atexit.register(self.stop_started_network)
        
        self.profile_str = ''
        self.kernel = opts.kernel
        self.vpn = opts.vpn
        self.http = opts.http
        self.crypto = opts.crypto

        if opts.start_network:
            self.start_network(opts.start_network)

    # @staticmethod?
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
        parser.add_option("--use-deadbeef",
                          action="store_true",
                          default=False,
                          help="Use the debugging sentinel")
    
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
                            help="Start CORE or DETER at launch.  Argument is imn file for CORE or experiment name for DETER")

        return parser        
        
    def rsync(self, args):
        """rsync data/scripts to DETER hosts"""
        
        if self.transport == 'ssh': # DETER
            # First upload the files
            print "Uploading files to DETER"
            subprocess.call('cd ../scripts ; ./sync-deter.py', shell=True)          
            
            # Copy the files to /tmp/
            threads = []
            
            nfs_dir = self.prefix[:self.prefix.rfind('/src')]
            local_dir = self.install_dir[:self.install_dir.rfind('curveball/src')]
            topdir = self.install_dir[:self.install_dir.rfind('/src')]
            
            for machine in self.servers:
                self.run(machine, 'sudo mkdir -p %s ; whoami | xargs -I {} sudo chown {} %s' % (topdir, topdir)) 
                t = Thread(target=self.run, args=(machine, 'rsync -avz %s %s' % (nfs_dir, local_dir), True))
                t.start()
                threads.append((t, machine))

            print "Waiting for %d machines to finish copying to local directories" % len(threads)
            
            for (t, machine) in threads:
                print "Waiting for %s to finish copying" % machine
                t.join()

    def install(self, args):                
        """Install scripts on remote hosts"""

        if self.transport == 'ssh': # DETER
            self.rsync(None)
            
            # Run make
            threads = []          
            
            for machine in self.servers:
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
        
        CLIENT.stop('client', self)
        for decoy in self.decoys:
            DECOY.stop(decoy, self)
        for covert in self.coverts:
            COVERT.stop(covert, self)

        """ Stop the decoy routing services """
        time.sleep(1)
        for dr in self.drs.keys():
            print 'stop %s' % dr
            DR.stop(dr, self)

        for dp in self.drs.values():
            print 'stop %s' % dp
            DP.stop(dp, self)

        if not self.use_firewall:
            print 'stop %s' % 'filter'
            FIREWALL.stop('filter', self)

        for dr in self.drs.keys():
            print 'flush ip tables %s' % dr
            DR.flush_iptables(dr, self)

        if self.quilt:
            QUILT.stop(self.quilt, 'client', self)

        print "Experiment done, exiting"

        
    def profile(self, args):
        if self.profile_str:
            self.profile_str = ''
            print "Profiling off"
        else:
            self.profile_str = '-m cProfile -o %s.profile' % sys.argv[0]
            print self.profile_str
            print "Profiling on"
            
    def start(self, args):
        """Start without quilting"""
        self.start_helper(False, args)

    def qstart(self, args):
        """Start everyone, including quilting"""
        self.start_helper(True, args)

    def start_helper(self, quilting, args):
        """Start all the curveball pieces, in classic or quilted mode.
        Takes one optional argument: xterm=DISPLAY, to start the
        quilting software in an xterm instead of an expect pipe."""

        self.add_sentinels_worker()

        print "Starting filter, decoys, and local covert hosts...."
        try:
            if self.use_firewall:
                # copy coverts
                blocks = list(self.coverts[0:])
                blocks.extend(self.drs.values())
                FIREWALL.start('filter', self, blocks)
            for decoy in self.decoys:
                print 'Starting %s' % decoy
                DECOY.start(decoy, self)
            for covert in self.coverts:
                print 'Starting %s' % covert
                COVERT.start(covert, self)

            # debug replace python with pdb
            use_pdb = False

            """ Start danted on the decoy proxy """
            for dp in self.drs.values():
                print 'Starting %s' % dp
                DP.start(dp, self, self.crypto, use_pdb, self.use_deadbeef)
            for dr in self.drs.keys():
                print 'Starting %s' % dr
                DR.start(dr, self, self.kernel, self.drs[dr], self.dr2decoy[dr],
                        self.use_deadbeef)
        except:
            self.stop(None)
            return

        # args is a space separated list of arguments (basically, it's
        # the rest of the command line)  
        if type(args) is types.StringType:
            args = args.split(' ')

        # if the user asks for a specific protocol, restrict to that protocol
        # (Hmm, shouldn't this affect what decoys we start, as well?)
        _use_http = True
        _use_https = True

        if "http" in args:
            _use_https = False
        if "https" in args:
            _use_http = False

        if quilting:
            try:
                xtermarg = None
                _manual = False
                if "manual" in args:
                    _manual=True
                else:
                    # maybe the following should be done with a regexp

                    # look for a string starting with "xterm=" in the list
                    # of args:
                    if type(args) is types.StringType:
                        xtermarg = (args[args.index('=') + 1:]
                                    if ("xterm=" in args
                                        and args.index('xterm=') is 0)
                                    else None)
                    if type(args) is types.ListType:
                        xtermarglist = [x[x.index('=')+1:] # substr after '='
                                        for x in args
                                        if ("xterm=" in x
                                            and x.index('xterm=') is 0)]
                        if len(xtermarglist) > 0:
                            # convert to the bit after the '='
                            xtermarg = xtermarglist[0]
                        
                if self.quilt:
                    QUILT.start(self.quilt, 'client', self.decoys, self,
                            self.decoy_spec, xterm=xtermarg, manual=_manual,
                            use_http=_use_http, use_https=_use_https)
            except:
                self.stop(None)
                return
        else:
            if self.use_client:
                try:
                    random.seed(None)
                    if os.getenv('CB_DEBUG'):
                        decoy = random.choice(self.decoys)
                    CLIENT.start(self,
                                 decoy,
                                 self.http,
                                 self.vpn,
                                 self.use_deadbeef)
                except:
                    # This happens often enough to have a little
                    # patience as a result  
                    print "Couldn't tell if client started --- commandeer client to check"
                    
        


    def test_decoy_routing(self, host):
        """ See if we can fetch a webpage from a blocked destination through curveball """
        if not host or host.strip() == '':
            host = 'http://www.google.com'
        
        spare = self.create_spare('client')

        print "Testing decoy routing, fetching webpage from %s over proxy ... " % host
        #spare.run('TESTSUCCESS=CURVESUCCESS')
        #spare.expect("CURVESUCCESS")
        
        if not self.opts.vpn:
            cmd = "printf 'GET / HTTP/1.0\n\n' | nc -q-1 -x localhost:5010 %s 80 | grep -i '<html>' && echo $TESTSUCCESS" % host
        else:
            cmd = "printf 'GET / HTTP/1.0\n\n' | nc -q-1 %s 80 | grep -i '<html>' && echo $TESTSUCCESS" % host
        
        cmd = "curl -vs --socks4 localhost:5010 %s |( grep -ic 'html' && echo $TESTSUCCESS || echo failure)" % host
        spare.run(cmd)

        try:
            data = spare.expect("CURVESUCCESS", timeout=10)
            print "Test successful"
            #print data
            return True

        except (pexpect.EOF, pexpect.TIMEOUT):
            print "Test failed"
            return False
            
    def ping(self, src, dst):
        FIREWALL.stop('filter', self)

        spare = self.create_spare(src)
        spare.run('ping %s -c 1' % dst)
        try:
            (_, buffer, _) = spare.expect('time=', timeout=4)
            time = float(buffer.split(' ')[0])
            return time
        except (pexpect.EOF, pexpect.TIMEOUT):
            return None

    
    def test(self, args):
        if self.use_firewall:
            # copy coverts
            blocks = list(self.coverts[0:])
            blocks.extend(self.drs.values())
            FIREWALL.start('filter', self, blocks)
        return self.test_decoy_routing(args)
        
    def exit(self, args):
        """ exit the program """
        sys.exit(0)
    
    def run_batch_mode(self, cmds):
        """ Given a comma separated list of commands, run them in order """
        cmds = cmds.split(',')
        for cmd in cmds:
            print "Running command '%s'" % cmd
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
