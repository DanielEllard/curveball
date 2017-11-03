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

#ifndef CURVEBALL_DR2DPENCODER_HH
#define CURVEBALL_DR2DPENCODER_HH
#include <click/element.hh>
#include <click/ipflowid.hh>
#include <click/timer.hh>
CLICK_DECLS


class DR2DPEncoder : public Element { public:

    DR2DPEncoder();
    ~DR2DPEncoder();

    const char *class_name() const	{ return "DR2DPEncoder"; }
    const char *port_count() const	{ return "1/1"; }
    const char *processing() const	{ return PUSH; }
    const char *flow_code()  const	{ return COMPLETE_FLOW; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);

    void push(int port, Packet *p);

    // Process any configured timers that have fired.
    void run_timer(Timer *timer);

    // Redirect the initial sentinel packets of a newly identified
    // Curveball flow. The 'pkts' parameter will be NULL on return.
    void redirect_flow(const String &tcp_syn_options,
                       const String &tcp_ack_options,
                       Packet *pkts);

    void tls_established(const IPFlowID &flow, const String &random);

    void redirect_icmp_packet(const IPFlowID &flow,
                              Packet *pkt,
                              bool to_client);

  private:

    Timer 	_ping_timer;
    uint32_t	_ping_interval;
};

CLICK_ENDDECLS
#endif
