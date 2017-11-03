#!/usr/bin/env python

# Copyright (c) 2011-2012, Linus Nordberg
# See lsocks.py for details.

# usage: $0 [url ... url]
#
# Fetch some number of URLs via a SOCKS4 proxy running at 127.0.0.1:1080,
# and print some of the content to stdout.
#
# Note that because it's a SOCKS4 proxy, and we don't do resolution of the
# DNS names here, the URLs must have hosts that are dotted-quad IPv4 addresses.
# No other format is permitted.
#
# Eyeball the results to see if they are what you expect.  The system will
# give up and exit if the URLs take more than a few seconds to fetch.

import sys

from twisted.internet import endpoints
from twisted.internet import reactor
from twisted.web import client

from lsocks import SOCKSWrapper

if '__main__' == __name__:
    def main():

        def wrappercb(proxy):
            print "connected to proxy", proxy

        def clientcb(content):
            print "Content:\n%s\n" % content[:200]

        def sockswrapper(proxy, url):
            dest = client._parse(url) # scheme, host, port, path
            endpoint = endpoints.TCP4ClientEndpoint(reactor, dest[1], dest[2])
            return SOCKSWrapper(reactor, proxy[1], proxy[2], endpoint)

        proxy = (None, '127.0.0.1', 1080, True, None, None)

        for url in sys.argv[1:]:
            f = client.HTTPClientFactory(url)
            f.deferred.addCallback(clientcb)
            sw = sockswrapper(proxy, url)
            d = sw.connect(f)
            d.addCallback(wrappercb)

        reactor.callLater(3, reactor.stop)

        reactor.run()

    main()
