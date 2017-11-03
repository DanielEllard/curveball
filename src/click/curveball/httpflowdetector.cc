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
#include "httpflowdetector.hh"
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
CLICK_DECLS

char
fromhex(char c)
{
    if (isxdigit(c)) {
        if (isdigit(c)) {
            c -= '0';
        } else {
            c = tolower(c);
            c = c - 'a' + 10;
        }

    } else {
        c = 0;
    }

    return c;
}

void
unhexlify(const char *str, char *hex_str, int hex_len)
{
    assert((hex_len > 0) && (hex_len % 2 == 0));

    for (int i = 0; i < hex_len; ++i) {
        hex_str[i] = fromhex(str[2 * i + 1]) + 16 * fromhex(str[2 * i]);
    }
}

HTTPFlowDetector::HTTPFlowDetector() : SentinelDetector(8)
{
    // defaults to 80 (HTTP)
    _port = 80;
}

HTTPFlowDetector::~HTTPFlowDetector()
{
}

void *
HTTPFlowDetector::cast(const char *name)
{
    if (strcmp(name, "HTTPFlowDetector") == 0)
        return (HTTPFlowDetector *) this;
    else if (strcmp(name, "SentinelDetector") == 0)
        return (SentinelDetector *) this;
    else
        return SentinelDetector::cast(name);
}

void
HTTPFlowDetector::push(int port, Packet *p)
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

    // Non-HTTP packets are simply forwarded.
    if (ntohs(p->tcp_header()->th_dport) != _port) {
        output(1).push(p);
        return;
    }

    if (syn_packet(p)) {
        _flow_table.add_flow(p);
        output(1).push(p);

    } else {
        process_non_syn_packet(p);
    }
}

bool
HTTPFlowDetector::syn_packet(Packet *p)
{
    return (p->tcp_header()->th_flags & TH_SYN);
}

void
HTTPFlowDetector::process_non_syn_packet(Packet *p)
{
    IPFlowID flow_key = IPFlowID(p);
    FlowEntry *entry = _flow_table.get_flow(flow_key);

    // If no entry exists, then the packet is non-Curveball.
    if (entry == NULL) {
        output(1).push(p);

    // If an entry exists in ACK state, a client ACK is expected.
    } else if (entry->state() == FLOW_STATE_ACK) {
        process_client_ack_packet(p, entry);

    // If an entry exists in SENTINEL state, an HTTP request is expected.
    } else if (entry->state() == FLOW_STATE_SENTINEL) {
        process_http_data_packet(p, entry);

    // If an entry exists in SEGMENT state, an HTTP request segment is expected.
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
HTTPFlowDetector::process_client_ack_packet(Packet *p, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;

    if ((p->tcp_header()->th_flags & TH_ACK) && (nbytes == 0)) {
        entry->set_state(FLOW_STATE_SENTINEL);

    } else {
        click_chatter("HTTPFLowDetector::process_client_ack_packet: "
                      "Invalid client ACK in TCP handshake.");
        remove_flow(IPFlowID(p));
    }

    output(1).push(p);
}

void
HTTPFlowDetector::process_http_data_packet(Packet *p, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;
    IPFlowID flow_identifier(p);

    if (ntohl(p->tcp_header()->th_seq) != entry->isn() + 1) {
        process_sentinel_segment(p, entry);
        return;
    }

    String pkt_str((const char *)data, nbytes);
    String start_of_msg_str("GET");
    String end_of_msg_str("\r\n\r\n");
    int end_of_msg;

    if (pkt_str.length() < start_of_msg_str.length()) {
        process_sentinel_segment(p, entry);
        return;
    }

    if (pkt_str.find_left(start_of_msg_str) != 0) {
        click_chatter("HTTPFlowDetector::process_http_data_packet: "
                      "packet does not begin with GET");
        remove_flow(flow_identifier);
        output(1).push(p);
        return;
    }

    if ((end_of_msg = pkt_str.find_left(end_of_msg_str)) == -1) {
        process_sentinel_segment(p, entry);
        return;
    }

    end_of_msg = end_of_msg + end_of_msg_str.length();

    String sentinel;
    process_get_message(flow_identifier,
                        pkt_str.substring(0, end_of_msg),
                        sentinel);

    if (sentinel.empty()) {
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
        generate_udp_notification(p, sentinel.data(), sentinel.length());
    }

    if (_encoder) {
        _encoder->redirect_flow(entry->tcp_syn_options(),
                                entry->tcp_ack_options(), p);

    } else {
        click_chatter("HTTPFlowDetector::process_http_data_packet: "
                      "DR2DPEncoder not configured; can't redirect flow.");
        p->kill();
    }
}

void
HTTPFlowDetector::process_sentinel_segment(Packet *p, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;
    IPFlowID flow_identifier(p);

    // duplicate ack
    if (nbytes == 0) {
        output(1).push(p);
        return;
    }

    entry->set_state(FLOW_STATE_SEGMENT);
    entry->maintain_segment_buffer();
    entry->add_pkt(p);

    String start_of_msg_str("GET");
    String end_of_msg_str("\r\n\r\n");

    if (!entry->ready_for_sentinel_check(end_of_msg_str)) {
        output(1).push(p);
        return;
    }

    if (entry->segment_buffer().find_left(start_of_msg_str) != 0) {
        click_chatter("HTTPFlowDetector::process_sentinel_segment: "
                      "data does not begin with GET");
        remove_flow(flow_identifier);
        output(1).push(p);
        return;
    }

    String sentinel;
    process_get_message(flow_identifier, entry-> segment_buffer(), sentinel);

    if (sentinel.empty()) {
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
        generate_udp_notification(p, sentinel.data(), sentinel.length());
    }

    if (_encoder) {
        _encoder->redirect_flow(entry->tcp_syn_options(),
                                entry->tcp_ack_options(),
                                entry->pktbuf());

    } else {
        click_chatter("HTTPFlowDetector::process_sentinel_segment: "
                      "DR2DPEncoder not configured; can't redirect flow.");
    }

    // If we make it this far, then this is the last packet segment to
    // reconstruct the sentinel field. This packet is not forwarded,
    // but redirected to the decoy proxy only.
    p->kill();
}

void
HTTPFlowDetector::process_get_message(
    const IPFlowID &flow_key, const String &get_msg, String &sentinel)
{
    String cookie_str("\r\nCookie: ");
    int cookie_start, cookie_end;

    cookie_start = get_msg.find_left(cookie_str);

    while (cookie_start != -1) {
        cookie_start = cookie_start + cookie_str.length();

        if ((cookie_end = get_msg.find_left("\r\n", cookie_start)) == -1) {
            click_chatter("HTTPFlowDetector::process_get_msg: "
                          "failed to find end of cookie field");
            return;
        }

        int cookie_length = cookie_end - cookie_start;

        process_cookie_field(flow_key,
                             get_msg.substring(cookie_start, cookie_length),
                             sentinel);

        if (!sentinel.empty()) {
            return;
        }

        cookie_start = get_msg.find_left(cookie_str, cookie_end);
    }
}

void
HTTPFlowDetector::process_cookie_field(
    const IPFlowID &flow_key, const String &cookie_field, String &sentinel)
{
    bool end_of_cookie_field = false;
    int cookie_start = 0, cookie_end;

    while(!end_of_cookie_field) {

        if ((cookie_end = cookie_field.find_left("; ", cookie_start)) == -1) {
            cookie_end = cookie_field.length();
            end_of_cookie_field = true;
        }

        int this_cookie_start = cookie_start;

        // add two characters to account for "; " cookie delineator
        cookie_start = cookie_end + 2;

        int value_start, value_end = cookie_end;
        if ((value_start =
                 cookie_field.find_left("=", this_cookie_start)) == -1) {
            click_chatter("HTTPFlowDetector::process_cookie: "
                          "failed to divde name/value pair");
            continue;
        }

        // advance past '=' character
        value_start += 1;
        int value_length = value_end - value_start;

        int sentinel_length = 2 * _sentinel_length;

        if (value_length < sentinel_length) {
            // value field too small to contain sentinel
            continue;
        }

        if (sentinel_packet(flow_key,
                            cookie_field.data() + value_start,
                            sentinel_length)) {
            sentinel = cookie_field.substring(value_start, sentinel_length);
            return;
        }
    }
}

bool
HTTPFlowDetector::sentinel_packet(
    const IPFlowID &flow_key, const char *buf, int len)
{
    // Check string sentinel first, if one is configured.
    if (_sentinel.length() > 0 && string_sentinel(flow_key, buf, len)) {
        return true;
    }

    if (len != (2 * _sentinel_length)) {
        return false;
    }

    char hex_str[_sentinel_length];
    unhexlify(buf, hex_str, _sentinel_length);

    if (seen_flow(flow_key, buf, len)) {
        click_chatter("HTTPFlowDetector::sentinel_packet: "
                      "ignoring already seen flow");
        return false;
    }

    if ((_sentinels == NULL) ||
        (!_sentinels->member(hex_str, _sentinel_length))) {
        // packet does not contain a valid Curveball sentinel
        return false;
    }

    click_chatter("HTTPFlowDetector::sentinel_packet: "
                  "Packet contains valid sentinel.");
    return true;
}

bool
HTTPFlowDetector::string_sentinel(
    const IPFlowID &flow_key, const char *buf, int len)
{
    if (seen_flow(flow_key, buf, len)) {
        click_chatter("HTTPFlowDetector::string_sentinel: "
                      "ignoring already seen flow");
        return false;
    }

    if (len < _sentinel.length()) {
        return false;
    }

    if (String(buf, _sentinel.length()) != _sentinel) {
        // packet does not contain valid Curveball sentinel
        return false;
    }

    click_chatter("HTTPFlowDetector::string_sentinel: "
                  "Packet contains a valid sentinel.");
    return true;
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(SentinelDetector)
EXPORT_ELEMENT(HTTPFlowDetector)
