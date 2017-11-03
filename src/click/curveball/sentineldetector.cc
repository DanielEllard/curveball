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
#include "sentineldetector.hh"
#include "dr2dpprotocol.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <unistd.h>
CLICK_DECLS


SentinelDetector::SentinelDetector(int sentinel_length)
    : _sentinels(NULL),
      _sentinel_length(sentinel_length),
      _flow_table(),
      _timeout_in_sec(0),
      _flow_timer(this),
      _encoder(NULL),
      _port(0),
      _forward_reverse(false),
      _udp_port(0)
{
}

SentinelDetector::~SentinelDetector()
{
}

int
SentinelDetector::configure(Vector<String> &conf, ErrorHandler *errh)
{
    //TODO: What do we really want the default timeout to be?
    //      A timeout of 7 days has been added to the router config file.
    _timeout_in_sec = 60 * 60 * 24 * 7; // 7 day default (for demoing)

    return cp_va_kparse(conf, this, errh,
                        "TIMEOUT", 0, cpUnsigned, &_timeout_in_sec,
                        "PORT", 0, cpTCPPort, &_port,
                        "SENTINEL", 0, cpString, &_sentinel,
                        "ENCODER", 0, cpElement, &_encoder,
                        "SENTINEL_LENGTH", 0, cpInteger, &_sentinel_length,
                        "REVERSE", 0, cpBool, &_forward_reverse,
                        "UDP_PORT", 0, cpUDPPort, &_udp_port,
                        "LOCAL_IPADDR", 0, cpIPAddress, &_local_addr,
                        cpEnd);
}

int
SentinelDetector::initialize(ErrorHandler *)
{
    if (!_encoder ||
        !_encoder->cast("DR2DPEncoder")) {
        _encoder = NULL;
    }

    _flow_timer.initialize(this);
    _flow_timer.schedule_after_sec(_timeout_in_sec);

    return 0;
}

void
SentinelDetector::cleanup(CleanupStage)
{
    _flow_table.clear();
    _seen_flows.clear();
    _flow_timer.clear();
}

void
SentinelDetector::update_sentinel_filter(const BloomFilter * filter)
{
    _sentinels = filter;
}

void
SentinelDetector::update_dh_blacklist(
    const Vector<DHBlacklistEntry> & blacklist)
{
    _dh_blacklist = blacklist;
}

void
SentinelDetector::process_server_packet(Packet *p)
{
    if (ntohs(p->tcp_header()->th_sport) != _port) {
        output(1).push(p);
        return;
    }

    FlowEntry *entry = _flow_table.get_flow(IPFlowID(p, true));

    if (entry != NULL) {
        if (entry->state() == FLOW_STATE_ACK) {
            process_server_ack(p, entry);

        } else if (entry->state() == FLOW_STATE_REDIRECT && _forward_reverse) {
            output(0).push(p);
            return;
        }
    }

    output(1).push(p);
}

void
SentinelDetector::process_server_ack(Packet *p, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;

    if ((p->tcp_header()->th_flags & TH_ACK) &&
        (ntohl(p->tcp_header()->th_ack) == (entry->isn() + 1)) &&
        (nbytes == 0)) {

        int option_offset = 20;
        int option_length = (p->tcp_header()->th_off << 2) - option_offset;
        if (option_length > 0) {
            const uint8_t *options = p->transport_header() + option_offset;
            entry->set_tcp_ack_options(String((const char *)options,
                                              option_length));
        }

        entry->set_server_ack();

    } else {
        click_chatter("TLSFLowDetector::process_server_ack: "
                      "Invalid server ACK in TCP handshake.");
    }
}

void
SentinelDetector::generate_udp_notification(
    const Packet *p,  const char *sentinel, unsigned int sentinel_len)
{
    if (_udp_port == 0) {
        click_chatter("SentinelDetector::generate_udp_notification: "
                      "No UDP-notification port specified.");
        return;
    }

    assert(p->has_network_header());
    IPFlowID flow_key(p);

    int pkt_len = sizeof(click_ip) +
                  sizeof(click_udp) +
                  sizeof(dr_flow_notification_msg) +
                  sentinel_len;

    WritablePacket *udp_pkt = WritablePacket::make(pkt_len);
    if (!udp_pkt) {
        click_chatter("SentinelDetector::generate_udp_notification: "
                      "failed to allocate packet");
        return;
    }

    memset(udp_pkt->data(), 0, pkt_len);
    udp_pkt->set_network_header(udp_pkt->data(), sizeof(click_ip));

    // Build the IP header.
    click_ip *ip_hdr = reinterpret_cast<click_ip *>(udp_pkt->data());
    ip_hdr->ip_v   = 4;
    ip_hdr->ip_hl  = 5;
    ip_hdr->ip_len = htons(pkt_len);
    ip_hdr->ip_id  = p->ip_header()->ip_id;
    ip_hdr->ip_ttl = p->ip_header()->ip_ttl;
    ip_hdr->ip_p   = IP_PROTO_UDP;
    ip_hdr->ip_src.s_addr = _local_addr.addr();
    ip_hdr->ip_dst.s_addr = flow_key.daddr().addr();

    // Build the UDP header.
    click_udp *udp_hdr = reinterpret_cast<click_udp *>(udp_pkt->data() +
                                                       sizeof(click_ip));
    udp_hdr->uh_sport = flow_key.sport();
    udp_hdr->uh_dport = htons(_udp_port); 
    udp_hdr->uh_ulen  = htons(sizeof(click_udp) +
                              sizeof(dr_flow_notification_msg) +
                              sentinel_len);

    // Build the notification content.
    dr_flow_notification_msg *msg =
        reinterpret_cast<dr_flow_notification_msg *>(udp_pkt->data() +
                                                     sizeof(click_ip) +
                                                     sizeof(click_udp));
    strcpy((char *)msg->dr_sentinel, "\xBA\xAD\xFE\xED");
    msg->src_addr = flow_key.saddr().addr();
    msg->dst_addr = flow_key.daddr().addr();
    msg->src_port = flow_key.sport();
    msg->dst_port = flow_key.dport();
    msg->flow_sentinel_length = htons(sentinel_len);

    char *flow_sentinel = reinterpret_cast<char *>(
                            udp_pkt->data() + sizeof(click_ip) +
                                              sizeof(click_udp) +
                                              sizeof(dr_flow_notification_msg));
    strncpy(flow_sentinel, sentinel, sentinel_len);

    output(2).push(udp_pkt);
}

void
SentinelDetector::incoming_udp_notification(
    const IPFlowID &flow_key, const String &sentinel)
{
    click_chatter("SentinelDetector::incoming_udp_notification: "
                  "adding previously seen flow");
    _seen_flows.set(flow_key, sentinel);
}

bool
SentinelDetector::seen_flow(const IPFlowID &flow_key, const char *buf, int len)
{
    String *flow_sentinel = _seen_flows.get_pointer(flow_key);
    if (flow_sentinel == NULL) {
        return false;
    }

    if (len < flow_sentinel->length()) {
        return false;
    }

    String sentinel(buf, flow_sentinel->length());

    return sentinel == *flow_sentinel;
}

bool
SentinelDetector::is_blacklisted(const IPAddress & decoy_host)
{
    for (Vector<DHBlacklistEntry>::iterator entry = _dh_blacklist.begin();
         entry != _dh_blacklist.end();
         ++entry) {

        if (decoy_host.matches_prefix((*entry).addr(), (*entry).mask())) {
            click_chatter("SentinelDetector::is_blacklist: "
                          "decoy address is blacklisted: %s",
                           decoy_host.unparse().c_str());
            return true;
        }
    }

    return false;
}

void
SentinelDetector::run_timer(Timer *timer)
{
    assert(timer = &_flow_timer);

    _flow_table.remove_inactive_flows();

    click_chatter("SentinelDetector::run_timer: "
                  "removed inactive flows; rescheduling timer");
    _flow_timer.reschedule_after_sec(_timeout_in_sec);
}

enum { H_TABLE };

void
SentinelDetector::add_handlers()
{
    add_read_handler("table", read_handler, (void *)H_TABLE);
}

String
SentinelDetector::read_handler(Element *e, void *thunk)
{
    SentinelDetector *detector = (SentinelDetector *)e;

    switch ((intptr_t)thunk) {

    // return string represenation of the flow table
    case H_TABLE:
        return detector->_flow_table.table_to_str();

    default:
        return "<error>";
    }
}


CLICK_ENDDECLS
EXPORT_ELEMENT(SentinelDetector)
