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
#include "bittorrentdetector.hh"
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
CLICK_DECLS


BitTorrentDetector::BitTorrentDetector() : SentinelDetector(8)
{
    // defaults to 6881 (BitTorrent)
    _port = 6881;
}

BitTorrentDetector::~BitTorrentDetector()
{
}

void *
BitTorrentDetector::cast(const char *name)
{
    if (strcmp(name, "BitTorrentDetector") == 0)
        return (BitTorrentDetector *) this;
    else if (strcmp(name, "SentinelDetector") == 0)
        return (SentinelDetector *) this;
    else
        return SentinelDetector::cast(name);
}

void
BitTorrentDetector::process_non_syn_packet(Packet *p)
{
    IPFlowID flow_key = IPFlowID(p);
    FlowEntry *entry = _flow_table.get_flow(flow_key);

    // If no entry exists, then the packet is non-Curveball.
    if (entry == NULL) {
        output(1).push(p);

    // If an entry exists in ACK state, a TCP client ACK is expected.
    } else if (entry->state() == FLOW_STATE_ACK) {
        process_client_ack(p, entry);

    } else if (entry->state() == FLOW_STATE_SENTINEL) {
        process_bittorrent_data_packet(p, entry);

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
BitTorrentDetector::process_bittorrent_data_packet(Packet *p, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;
    IPFlowID flow_identifier(p);

    // The BitTorrent sentinel is contained within the first 8 bytes
    // of the first client-side data packet.

    const int offset_to_sentinel = 0;
    const int required_length = offset_to_sentinel + _sentinel_length;

    // partial data packet; handle sentinel segment
    if (nbytes < required_length ||
        ntohl(p->tcp_header()->th_seq) != entry->isn() + 1) {
        process_sentinel_segment(p, entry);
        return;
    }

    // packet contains curveball sentinel and
    // the decoy host has not been blacklisted
    if (sentinel_packet(flow_identifier,
                        (const char *)data + offset_to_sentinel,
                        _sentinel_length) &&
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
            click_chatter("BitTorrentDetector::process_bittorrent_data_packet: "
                          "DR2DPEncoder not configured; can't redirect flow.");
            p->kill();
        }

    // message does not contain curveball sentinel
    } else {
        remove_flow(flow_identifier);
        output(1).push(p);
    }
}

void
BitTorrentDetector::process_sentinel_segment(Packet *p, FlowEntry *entry)
{
    const uint8_t *data = p->transport_header() +
                          (p->tcp_header()->th_off << 2);
    int nbytes = p->end_data() - data;
    IPFlowID flow_identifier(p);

    const int offset_to_sentinel = 0;
    const int required_length = offset_to_sentinel + _sentinel_length;

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

    char buf[_sentinel_length];
    entry->construct_sentinel_buf((char *)&buf, _sentinel_length,
                                                offset_to_sentinel + 1);

    if (!sentinel_packet(flow_identifier, (char *)&buf, _sentinel_length)) {
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
        click_chatter("BitTorrent::process_sentinel_segment: "
                      "DR2DPEncoder not configured; can't redirect flow.");
    }

    // If we make it this far, then this is the last packet segment to
    // reconstruct the sentinel field. This packet is not forwarded,
    // but redirected to the decoy proxy only.
    p->kill();
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(SentinelDetector)
EXPORT_ELEMENT(BitTorrentDetector)
