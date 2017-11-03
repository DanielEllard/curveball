#!/bin/sh
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

# For the cb-uni-small experiment
#
# The way things are set up by default in DETER, each subnet is
# generally a /24 (unless you make some effort to set netmasks
# to something else.  Therefore even though what we've really
# created is several /16 subnets, it is more convenient for
# the purpose of this script to just deal with each populated
# range in each /16 as its own /24.
#
# Some of these routes might already be absorbed by the default,
# so deleting them will generate an apparent error.
#

SCRIPTPATH=$(cd $(dirname $0) ; pwd -P)/$(basename $0)

do_remote() {
    echo "Doing dr..."
    ssh dr /usr/bin/sudo "${SCRIPTPATH}"
    echo "Doing ur"
    ssh ur /usr/bin/sudo "${SCRIPTPATH}"
    echo "Doing r2"
    ssh r2 /usr/bin/sudo "${SCRIPTPATH}"
    echo "Done"
}

do_local() {
    local SHORTNAME=$(/bin/hostname -s)
    local IP=/sbin/ip

    case $SHORTNAME in
	dr)
	    # The lan subnet with the covert, decoy, and dp:
	    # via r2.
	    #
	    $IP route del 10.0.0.0/24
	    $IP route add 10.0.0.0/24 via 10.4.1.2

	    # The client subnet: via r2.
	    # (the dr usually doesn't communicate with the filter,
	    # but we include this for completeness)
	    $IP route del 10.1.0.0/24
	    $IP route add 10.1.0.0/24 via 10.4.1.2

	    # The ur<->filter subnet: via r2.
	    # (the dr usually doesn't communicate with the filter,
	    # but we include this for completeness)
	    $IP route del 10.1.1.0/24
	    $IP route add 10.1.1.0/24 via 10.4.1.2
	    ;;

	ur)
	    # The lan subnet with the covert, decoy, and dp:
	    # via dr
	    #
	    $IP route del 10.0.0.0/24
	    $IP route add 10.0.0.0/24 via 10.3.1.2
	    ;;

	r2)
	    # The ur<->filter subnet
	    $IP route del 10.1.1.0/24
	    $IP route add 10.1.1.0/24 via 10.2.1.1

	    # The client subnet
	    $IP route del 10.1.0.0/24
	    $IP route add 10.1.0.0/24 via 10.2.1.1
	    ;;

	*)
	    ;;
    esac
}

usage() {
    cat <<EOF

    $0 [-r] [-h]

    Set routes on dr, ur, and r2 for the cb-uni-small experiment.
    The default behavior is to check whether the local hostname
    is "dr", "ur", or "r2", and set the corresponding routes.

    -h		Display the help message and exit
    -r		Invoke this program, via ssh, on dr, ur and r2

EOF
}

REMOTE=0
while getopts ":hr" opt; do
    case $opt in
	h)
	    usage
	    exit 0
	    ;;
	r)
	    REMOTE=1
	    ;;
	*)
	    usage
	    exit 1
	    ;;
    esac
done

if [ $REMOTE -ne 0 ]; then
    do_remote
else
    do_local
fi

