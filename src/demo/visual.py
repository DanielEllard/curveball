#!/usr/bin/env python
# 
# Copyright 2015 by Raytheon BBN Technologies Corp.  All Rights Reserved.

# need a module to parse packets reasonably quickly: dpkt?

import dpkt
import ipaddr
import pcapy

import struct
import sys
import threading
import time

class TrafficMonitor(threading.Thread):

    # seconds between updates
    #
    DEFAULT_UPDATE_INTERVAL = 5

    # how many lines to show of non-monitored sites
    #
    DEFAULT_MAX_SHOW = 10

    def __init__(self, update_interval=DEFAULT_UPDATE_INTERVAL, dev='eth0'):

        threading.Thread.__init__(self)

        self.seen = dict()
        self.update_interval = update_interval

        # this gets initialized to its true initial value when the
        # thread is started
        #
        self.next_update_time = 0

        self.interesting_ports = [80, 443, 8080]

        self.device = dev

        self.max_listing_len = self.DEFAULT_MAX_SHOW

        # maps prefixes to (mask, name) tuples
        #
        self.watched_prefixes = dict()

        # maps prefixes to observation counts
        #
        self.watched_counts = dict()

        self.seen_addrs = dict() 

        self.ignore_addrs = set()

    @staticmethod
    def binary2num(binary):
        return struct.unpack('!L', binary)[0]

    def run(self):

        def bin2dottedquad(binaddr):
            dot_addr = '.'.join('%d' % ord(digit) for digit in binaddr)

            return dot_addr

        def num2dottedquad(binaddr):
            return bin2dottedquad(struct.pack('!L', binaddr))

        def red_print(text):
            """
            Print the text in bold, reverse-video red
            """

            print '\x1b' + '[31;7;1m' + text + '\x1b' + '[0m'

        def dump_stats():

            # ANSI codes to clear the screen and
            # move the cursor back to the top
            #
            print '\x1b' + '[2J'
            print '\x1b' + '[;H'
            print ' Pkt Cnt         IP addr'
            print '   -----         -------'

            seen_cnt = 0

            for prefix in self.watched_prefixes:

                if prefix in self.watched_counts:
                    seen_cnt += 1

                    addr = num2dottedquad(prefix)
                    (_mask, hostname) = self.watched_prefixes[prefix]

                    red_print('%8d %15s %s' %
                            (self.watched_counts[prefix], addr, hostname))
                    del self.watched_counts[prefix]

            descending = sorted(
                    [(self.seen_addrs[addr], addr)
                        for addr in self.seen_addrs],
                    key=lambda rec: rec[0], reverse=True)

            descending = descending[:self.max_listing_len - seen_cnt]

            for (cnt, addr) in descending:
                print '%8d %15s' % (cnt, bin2dottedquad(addr))

            self.seen_addrs = dict()

        def pkt_handler(header, body):
            """
            packet handler called by pcapy's open_live or open_offline
            """

            header_time = header.getts()
            header_ts = (1.0 * header_time[0]) + (header_time[1] / 1000000.0)
            if not self.next_update_time:
                self.next_update_time = header_ts + self.update_interval

            if header_ts > self.next_update_time:
                self.next_update_time = header_ts + self.update_interval
                dump_stats()

                # TODO: do something with the data...

            eth = dpkt.ethernet.Ethernet(body)

            # toss away everything except TCP4 on a port we
            # care about
            #
            if not hasattr(eth, 'ip') or not hasattr(eth.ip, 'tcp'):
                return

            tcp_pkt = eth.ip.tcp

            if ((tcp_pkt.dport not in self.interesting_ports) and 
                    (tcp_pkt.sport not in self.interesting_ports)):
                return

            raw_addr = eth.ip.src
            raw_addr_num = self.binary2num(raw_addr)

            if raw_addr_num in self.ignore_addrs:
                return

            watched = False

            for prefix in self.watched_prefixes:
                (mask, _name) = self.watched_prefixes[prefix]

                if (raw_addr_num & mask) == prefix:
                    if prefix in self.watched_counts:
                        self.watched_counts[prefix] += 1
                    else:
                        self.watched_counts[prefix] = 1

                    watched = True
                    break

            if not watched:
                if raw_addr in self.seen_addrs:
                    self.seen_addrs[raw_addr] += 1
                else:
                    self.seen_addrs[raw_addr] = 1

        """
        Simple test-by-eyeball: load in a captured pcap and see whether
        the output looks plausible.

        TODO: this needs to be automated
        """

        # If we wanted to do a live capture, we could do that by
        # using pcapy.open_live, but open_live has some annoying quirks
        # (like blocking until the next packet arrives)
        #
        # devs = pcapy.findalldevs()
        # print devs
        # for dev in devs:
        #     print devs
        #
        # pcap = pcapy.open_live('en3', 65536, 0, 10)

        pcap = pcapy.open_live(self.device, 65536, 0, 10)
        pcap.loop(-1, pkt_handler)


if __name__ == '__main__':
    def main(args):
        """
        Runs a packet capture on 'eth0', grabs the TCP, and
        counts how many packets from each source address,
        and periodically displays the counts.  If any subnets
        are "monitored" (as described below) then they are printed
        in bold red; ordinary addresses are printed in ordinary
        text.

        There could be a dozen parameters to control how things
        are displayed, but almost everything is hardwired right now.

        We're using pcapy, so everything is driven by when packets
        arrive.  If no packets arrive, the display might never be
        updated.

        If the first argument is '-i', then the second argument
        is a comma-separated list of IP addresses to ignore.

        The rest of the argument list consists of the "monitored addresses",
        each of which is expressed as IPprefix/prefixlen/name, where IPprefix
        needs to be a full IPv4 address, prefixlen needs to be a prefix length
        (0..32) and name is the name that should be printed out in the display
        for this address.  For example,

        128.89.0.0/16/BBN.com 67.222.34.130/32/public-spectacle.com

        There's very minimal error checking on parameters; bad input
        will probably either crash or simply do the wrong thing, but
        without any useful feedback
        """

        monitor = TrafficMonitor()

        if args[0] == '-i':
            ignore_addrs = args[1].split(',')

            args = args[2:]

            for addr in ignore_addrs:
                ip_addr = ipaddr.IPv4Address(addr)
                print 'ignoring addr %s' % ip_addr

                monitor.ignore_addrs.add(int(ip_addr))

        for arg in args:
            (addr, prefixlen, name) = arg.split('/')

            ip_addr = ipaddr.IPv4Address(addr)
            mask = (1 << 32) - (1 << (32 - int(prefixlen)))

            print 'monitoring %s/%x %s' % (str(ip_addr), mask, name)
            monitor.watched_prefixes[int(ip_addr)] = (mask, name)

        monitor.start()

    main(sys.argv[1:])
