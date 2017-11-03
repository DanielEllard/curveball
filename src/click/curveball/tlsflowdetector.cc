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

// prints out the sentinel for inspection-by-eyeball
// #define NEW_SENTINEL_TEST yes

#include <click/config.h>
#include "tlsflowdetector.hh"
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
CLICK_DECLS


TLSFlowDetector::TLSFlowDetector() : SentinelDetector(8)
{
    // defaults to 443 (TLS)
    _port = 443;
}

TLSFlowDetector::~TLSFlowDetector()
{
}

void *
TLSFlowDetector::cast(const char *name)
{
    if (strcmp(name, "TLSFlowDetector") == 0)
        return (TLSFlowDetector *) this;
    else if (strcmp(name, "SentinelDetector") == 0)
        return (SentinelDetector *) this;
    else
        return SentinelDetector::cast(name);
}

void
TLSFlowDetector::push(int port, Packet *p)
{
    assert(p->has_network_header());
    assert(p->ip_header()->ip_p == IP_PROTO_TCP);

    // Non-first packet fragments are simply forwarded.
    if (IP_ISFRAG(p->ip_header()) && !IP_FIRSTFRAG(p->ip_header())) {
        output(1).push(p);
        return;
    }

    assert(p->has_transport_header());

    // server-side communication
    if (port == 1) {
        process_server_packet(p);
        return;
    }

    // Non-TLS packets are simply forwarded.
    if (ntohs(p->tcp_header()->th_dport) != _port) {
        output(1).push(p);
        return;
    }

    // client-side communication
    if (syn_packet(p)) {
        _flow_table.add_flow(p);
        output(1).push(p);

    } else {
        process_non_syn_packet(p);
    }
}

bool
TLSFlowDetector::syn_packet(Packet *p)
{
    return (p->tcp_header()->th_flags & TH_SYN);
}

void
TLSFlowDetector::process_non_syn_packet(Packet *p)
{
    IPFlowID flow_key = IPFlowID(p);
    FlowEntry *entry = _flow_table.get_flow(flow_key);

    // If no entry exists, then the packet is non-Curveball.
    if (entry == NULL) {
        output(1).push(p);

    // If an entry exists in ACK state, a TCP client ACK is expected.
    } else if (entry->state() == FLOW_STATE_ACK) {
        process_client_ack(p, entry);

    // If an entry exists in SENTINEL state, a TLS Hello packet is expected.
    } else if (entry->state() == FLOW_STATE_SENTINEL) {
        process_tls_client_hello(p, entry);

    // If an entry exists in SEGMENT state, a TLS Hello segment is expected.
    } else if (entry->state() == FLOW_STATE_SEGMENT) {
        process_sentinel_segment(p, entry);

    // If an entry exists in REDIRECT state, then the packet is redirected
    // to the Curveball system.
    } else {
        assert(entry->state() == FLOW_STATE_REDIRECT);

        entry->set_active();
        output(0).push(p);
    }
}

void
TLSFlowDetector::process_client_ack(Packet *p, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;

    if ((p->tcp_header()->th_flags & TH_ACK) && (nbytes == 0)) {
        entry->set_state(FLOW_STATE_SENTINEL);

    } else {
        click_chatter("TLSFLowDetector::process_client_ack: "
                      "Invalid client ACK in TCP handshake.");
        remove_flow(IPFlowID(p));
    }

    output(1).push(p);
}

void
TLSFlowDetector::process_tls_client_hello(Packet *p, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;
    IPFlowID flow_identifier(p);

    // 0x16 in the 1st payload byte --- TLS record is of type Handshake.
    // 0x01 in the 6th payload byte --- Handshake type is Client Hello.a
    // The Curveball sentinel is contained within the random number field
    // of the TLS Hello packet, bytes 16--44 of the payload.

    const int offset_to_sentinel = 15;
    const int max_sentinel_length = 28;
    const int required_length = offset_to_sentinel + max_sentinel_length;

    // Partial TLS client hello message; handle sentinel segments.
    if (nbytes < required_length ||
        ntohl(p->tcp_header()->th_seq) != entry->isn() + 1) {
        process_sentinel_segment(p, entry);
        return;
    }

    // Not a TLS client hello message.
    if (data[0] != 0x16 || data[5] != 0x01) {
        click_chatter("TLSFlowDetector::process_tls_client_hello: "
                      "TLS client hello message expected.");
        remove_flow(flow_identifier);
        output(1).push(p);
        return;
    }

    // TLS Client Hello message contains Curveball sentinel
    // and the decoy host has not been blacklisted
    if (sentinel_packet(flow_identifier,
                        (const char *)data + offset_to_sentinel,
                        max_sentinel_length) &&
        !is_blacklisted(flow_identifier.daddr())) {

        entry->set_state(FLOW_STATE_REDIRECT);
        entry->set_active();

        if (_udp_port > 0) {
            generate_udp_notification(
                p, (const char *)data + offset_to_sentinel, _sentinel_length);
        }

        if (_encoder) {
            assert(p->next() == NULL);
            _encoder->redirect_flow(entry->tcp_syn_options(),
                                    entry->tcp_ack_options(), p);

        } else {
            click_chatter("TLSFlowDetector::process_tls_client_hello: "
                          "DR2DPEncoder not configured; can't redirect flow.");
            p->kill();
        }

    // Message does not contain Curveball sentinel.
    } else {
        remove_flow(flow_identifier);
        output(1).push(p);
    }
}

void
TLSFlowDetector::process_sentinel_segment(Packet *p, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;
    IPFlowID flow_identifier(p);

    const int offset_to_sentinel = 15;
    const int max_sentinel_length = 28;
    const int required_length = offset_to_sentinel + max_sentinel_length;

    // duplicate ack
    if (nbytes == 0) {
        output(1).push(p);
        return;
    }

    entry->set_state(FLOW_STATE_SEGMENT);
    entry->add_pkt(p);

    if (!entry->ready_for_sentinel_check(required_length)) {
        output(1).push(p);
        return;
    }

    char buf[max_sentinel_length];
    entry->construct_sentinel_buf((char *)&buf, max_sentinel_length,
                                                offset_to_sentinel + 1);

    if (!sentinel_packet(flow_identifier, (char *)&buf, max_sentinel_length)) {
        remove_flow(flow_identifier);
        output(1).push(p);
        return;
    }

    if (is_blacklisted(flow_identifier.daddr())) {
        remove_flow(flow_identifier);
        output(1).push(p);
        return;
    }

    entry->set_state(FLOW_STATE_REDIRECT);
    entry->set_active();

    if (_udp_port > 0) {
        generate_udp_notification(p, buf, _sentinel_length);
    }

    if (_encoder) {
        _encoder->redirect_flow(entry->tcp_syn_options(),
                                entry->tcp_ack_options(),
                                entry->pktbuf());

    } else {
        click_chatter("TLSFlowDetector::process_sentinel_segment: "
                      "DR2DPEncoder not configured; can't redirect flow.");
    }

    // If we make it this far, then this is the last packet segment to
    // reconstruct the sentinel field. This packet is not forwarded,
    // but redirected to the decoy proxy only.
    p->kill();
}

void
TLSFlowDetector::process_tls_server_hello(Packet *p, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;

    // 0x16 in the 1st payload byte --- TLS record is of type Handshake.
    // 0x02 in the 6th payload byte --- Handshake type is Client Hello.
    // The random number field of the TLS Hello packet are bytes
    // 16--44 of the payload.

    const int offset_to_random = 15;
    const int random_length = 28;
    const int required_length = offset_to_random + random_length;

    assert(!entry->proto_ack());

    // check for sufficient bytes
    if (nbytes < required_length) {
        return;
    }

    // check if packet is a TLS server hello message
    if (data[0] != 0x16 || data[5] != 0x02) {
        return;
    }

    entry->set_proto_ack();

    if (_encoder) {
        String random((const char *)(data + offset_to_random), random_length);
        _encoder->tls_established(IPFlowID(p, true), random);

    } else {
        click_chatter("TLSFlowDetector::process_tls_server_hello: "
                      "DR2DPEncoder not configured");
    }
}

#ifdef NEW_SENTINEL_TEST
static char*
curveball_asciify(const char* buf, const int len) 
{
    static char dest[4096];
    int i;
    int outcount = 0;
    
    /* call with NULL prefix to just dump the hex bits, with no
     * decorations
     */
    for(i = 0; i < len; i++) {
        outcount += snprintf(&dest[outcount],
                             sizeof(dest) - outcount,
                             "%02x",
                             buf[i] & 0xff);
    }
    return &dest[0];
}
#endif // NEW_SENTINEL_TEST

bool
TLSFlowDetector::sentinel_packet(
    const IPFlowID &flow_key, const char *buf, int len)
{
    if (seen_flow(flow_key, buf, len)) {
        click_chatter("TLSFlowDetector::sentinel_packet: ",
                      "ignoring already seen flow");
        return false;
    }

    // Check string sentinel first, if one is configured.
    if (_sentinel.length() > 0 && string_sentinel(buf, len)) {
            return true;
    }

    assert(len >= _sentinel_length);

#ifdef NEW_SENTINEL_TEST
    {
        char buffer[4096];
        snprintf(buffer, sizeof(buffer),
                 "TLSFlowDetector::sentinel_packet: testing sentinel [%s]",
                 curveball_asciify((char*) buf, len));
        click_chatter(buffer);
    }
#endif // NEW_SENTINEL_TEST

    if ((_sentinels == NULL) ||
        (!_sentinels->member(buf, _sentinel_length))) {
        // packet does not contain valid Curveball sentinel
        return false;
    }

    click_chatter("TLSFlowDetector::sentinel_packet: "
                  "Packet contains valid sentinel.");
    return true;
}

bool
TLSFlowDetector::string_sentinel(const char *buf, int len)
{
    if (len < _sentinel.length()) {
        return false;
    }

    if (String(buf, _sentinel.length()) != _sentinel) {
        // packet does not contain valid Curveball sentinel
        return false;
    }

    click_chatter("TLSFlowDetector::string_sentinel: "
                  "Packet contains valid sentinel.");
    return true;
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(SentinelDetector)
EXPORT_ELEMENT(TLSFlowDetector)
