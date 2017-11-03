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

# MUST BE RUN AS SUDO!

import subprocess
import time
import sys
import pexpect
import os

def exit(proc):
    subprocess.call('./helloworld.py -b stop_network', shell=True)
    print "Exiting prematurely, a step failed"
    print "Reminder: speed_test.py must be run as sudo"
    print p.before
    print p.after
    sys.exit(1)


p = subprocess.Popen('git rev-parse HEAD', shell=True, stdout=subprocess.PIPE)
(sout,serr) = p.communicate()
print "Git revision = %s" % sout

os.chdir('..')
p = pexpect.spawn('./helloworld.py -s helloworld.imn --nogui -b start,speed_test')

try:
    p.expect("Connected to client, now testing routing", timeout=30)
except:
    print "Could not connect to CORE"
    print p.before
    print p.after
    exit(p)

print "CORE running and helloworld connected"

try:
    p.expect("Core up and running", timeout=60)
except:
    print "Routing did not converge"
    exit(p)

print "CORE running, routing converged"

try:
    p.expect("Client successfully established covert tunnel", timeout=30)
except:
    print "Failed to establish curveball tunnel"
    exit(p)
    
try:
    p.expect("Test successful", timeout=30)
except:
    print "Basic http test of tunnel failed"
    exit(p)
    
print "HTTP test successful"

try:
    p.expect("/sec", timeout=60)
except:
    print "Speed test failed"
    exit(p)

speed = ' '.join(p.before.split()[-2:]) + '/sec'
    
if '0.00' in speed:
    print "0 speed!"
    print p.before
    print p.after
print "SOCKS Speed test successful: %s" % speed

print "Waiting for helloworld to close"
p.wait()

print "Now testing VPN mode"

p = pexpect.spawn('./helloworld.py -v -b stop,start,speed_test,stop_network')


try:
    p.expect("Client successfully established covert tunnel", timeout=30)
except:
    print "Failed to establish curveball tunnel"
    exit(p)
    
try:
    p.expect("Test successful", timeout=30)
except:
    print "Basic http test of tunnel failed"
    exit(p)
    
print "HTTP test successful"

try:
    p.expect("/sec", timeout=60)
except:
    print "Speed test failed"
    exit(p)
    
speed = ' '.join(p.before.split()[-2:]) + '/sec'
print "VPN Speed test successful: %s" % speed



print "All tests successful"

print "Closing down..."
try:
    p.expect("Experiment done, exiting", timeout=30)
except:
    print "Experiment did not cleanup!"
    exit(p)


