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

#include <click/config.h>
#include "udpreceiver.hh"
#include "dr2dpprotocol.hh"
#include <click/args.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/vector.hh>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
CLICK_DECLS


UDPReceiver::UDPReceiver() : _port(0)
{
}

UDPReceiver::~UDPReceiver()
{
}

int
UDPReceiver::configure(Vector<String> &conf, ErrorHandler *errh)
{
    for (int i = 0; i < conf.size(); ++i) {
        Vector<String> parts;
        cp_spacevec(conf[i], parts);

        if (parts.size() == 0 || parts.size() > 2) {
            errh->error("conf arg requires keyword/value pair");
            continue;
        }

        if (parts[0].equals("DETECTOR", 8)) {
            Element *e = cp_element(parts[1], this, errh);
            if (e != NULL) {
                _configured_detectors.push_back(e);
            } else {
                errh->error("invalid element");
            }

        } else if (parts[0].equals("PORT", 4)) {
            if (!IntArg().parse(parts[1], _port)) {
                errh->error("invalid port");
                _port = 0;
            } 

        } else if (parts[0].equals("IPADDR", 6)) {
            _local_addr = IPAddress(parts[1]);

        } else {
            errh->error("invalid keyword");
        }
    }

    return 0;
}

int
UDPReceiver::initialize(ErrorHandler *)
{
    for (Vector<Element *>::iterator e = _configured_detectors.begin();
         e != _configured_detectors.end();
        ++e) {

        if ((*e)->cast("SentinelDetector")) {
            _sentinel_detectors.push_back((SentinelDetector *)(*e));
        }
    }

    return 0;
}

void
UDPReceiver::push(int, Packet *p)
{
    assert(p->has_network_header());
    assert(p->ip_header()->ip_p == IP_PROTO_UDP);

    // simply forward packet fragments
    if (IP_ISFRAG(p->ip_header())) {
        output(0).push(p);
        return;
    }

    assert(p->has_transport_header());

    if (ntohs(p->udp_header()->uh_dport) == _port) {
        process_notification_pkt(p);

    } else {
        output(0).push(p);
    }
}

void
UDPReceiver::process_notification_pkt(Packet *p)
{
    if (p->ip_header()->ip_src.s_addr == _local_addr.addr()) {
        click_chatter("UDPReceiver::process_notification_pkt: "
                      "received local udp notification");
        // don't forward --- routing loop???
        p->kill();
        return;
    }

    if (p->length() < sizeof(click_ip) +
                      sizeof(click_udp) +
                      sizeof(dr_flow_notification_msg)) {
        output(0).push(p);
        return;
    }

    const dr_flow_notification_msg *msg =
        reinterpret_cast<const dr_flow_notification_msg *>(p->data() +
                                                           sizeof(click_ip) +
                                                           sizeof(click_udp));

    const char *valid_sentinel = "\xba\xad\xfe\xed";
    if (strncmp((const char *)msg->dr_sentinel,
                valid_sentinel, sizeof(valid_sentinel)) != 0) {
        output(0).push(p);
        return;
    }

    IPFlowID flow_key(IPAddress(msg->src_addr), msg->src_port,
                      IPAddress(msg->dst_addr), msg->dst_port);

    int sentinel_length = ntohs(msg->flow_sentinel_length); 
    if (p->length() != sizeof(click_ip) +
                       sizeof(click_udp) +
                       sizeof(dr_flow_notification_msg) +
                       sentinel_length) {
        click_chatter("UDPReceiver::process_notification_pkt: "
                      "invalid packet length");
        // don't forward --- malformed packet
        p->kill();
        return;
    }

    const char *sentinel = reinterpret_cast<const char *>(
                               p->data() + sizeof(click_ip) +
                                           sizeof(click_udp) +
                                           sizeof(dr_flow_notification_msg));
    String flow_sentinel(sentinel, sentinel_length);

    for (Vector<SentinelDetector *>::iterator d = _sentinel_detectors.begin();
         d != _sentinel_detectors.end();
         ++d) {
        (*d)->incoming_udp_notification(flow_key, flow_sentinel);
    }

    output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(UDPReceiver)
