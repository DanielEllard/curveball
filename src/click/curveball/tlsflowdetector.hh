/*
 * This material is based upon work supported by the Defense Advanced
 * Research Projects Agency under Contract No. N66001-11-C-4017.
 *
 * Copyright 2014 - Raytheon BBN Technologies Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 */

#ifndef CURVEBALL_TLSFLOWDETECTOR_HH
#define CURVEBALL_TLSFLOWDETECTOR_HH
#include "sentineldetector.hh"
CLICK_DECLS

// Element that detects and redirects Curveball packets.
//
// It is assumed that incoming packets are TLS protocol messages.
// Packets to be redirected to the Curveball system are pushed out the
// element's outbound interface 0. All other packets are pushed out
// interface 1.

class TLSFlowDetector : public SentinelDetector { public:

    TLSFlowDetector();
    ~TLSFlowDetector();

    const char *class_name() const	{ return "TLSFlowDetector"; }

    void * cast(const char *name);

    void push(int port, Packet *p);

  private:

    // Returns true if the packet is a TCP SYN; false otherwise.
    bool syn_packet(Packet *p);

    // Handles incoming non-SYN TCP packets.
    void process_non_syn_packet(Packet *p);

    // Handles ACKs in TCP handshake.
    void process_client_ack(Packet *p, FlowEntry *entry);

    // Handles incoming TLS Hello messages.
    void process_tls_client_hello(Packet *p, FlowEntry *entry);
    void process_tls_server_hello(Packet *p, FlowEntry *entry);

    // Handles segmented sentinel packets.
    void process_sentinel_segment(Packet *p, FlowEntry *entry);

    // Determines if the given buffer contains a Curveball sentinel.
    bool sentinel_packet(const IPFlowID &flow_key, const char *buf, int len);
    bool string_sentinel(const char *buf, int len);

};


CLICK_ENDDECLS
#endif
