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
#include "dr2dpencoder.hh"
#include "dr2dpprotocol.hh"
#include <click/confparse.hh>
#include <click/error.hh>
CLICK_DECLS


DR2DPEncoder::DR2DPEncoder()
    : _ping_timer(this),
      _ping_interval(0)
{
}

DR2DPEncoder::~DR2DPEncoder()
{
}

int
DR2DPEncoder::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return cp_va_kparse(conf, this, errh,
                        "PING", 0, cpUnsigned, &_ping_interval,
                        cpEnd);
}

int
DR2DPEncoder::initialize(ErrorHandler *)
{
    _ping_timer.initialize(this);
    if (_ping_interval > 0) {
        _ping_timer.schedule_now();
    }

    return 0;
}

void
DR2DPEncoder::cleanup(CleanupStage)
{
    _ping_timer.clear();
}

void
DR2DPEncoder::push(int, Packet *p)
{
    WritablePacket *hdr_pkt = WritablePacket::make(sizeof(dr2dp_msg));
    if (!hdr_pkt) {
        click_chatter("DR2DPEncoder::push: failed to allocate packet");
        return;
    }

    dr2dp_msg *msg = reinterpret_cast<dr2dp_msg *>(hdr_pkt->data());
    msg->protocol = DR2DP_PROTOCOL_VERSION;
    msg->session_type = 0;
    msg->message_type = DR2DP_MSG_TYPE_REQUEST;
    msg->operation_type = DR2DP_OP_TYPE_FORWARD;
    msg->response_code = 0;
    msg->xid = 0;
    msg->data_length = htonq(p->length());

    output(0).push(hdr_pkt);
    output(0).push(p);
}

void
DR2DPEncoder::redirect_flow(const String &tcp_syn_options,
                            const String &tcp_ack_options,
                            Packet *pkts)
{
    int append_len = sizeof(dr2dp_msg) +
                     sizeof(dr2dp_redirect_flow_msg) +
                     tcp_syn_options.length() +
                     tcp_ack_options.length();

    int pkt_len = 0;
    Packet *pkt = pkts;
    while (pkt != NULL) {
        pkt_len += pkt->length();
        pkt = pkt->next();
    }

    WritablePacket *p = WritablePacket::make(append_len);
    if (!p) {
        click_chatter("DR2DPEncoder::redirect_flow: "
                      "failed to allocate packet");
        return;
    }

    dr2dp_msg *msg = reinterpret_cast<dr2dp_msg *>(p->data());
    msg->protocol = DR2DP_PROTOCOL_VERSION;
    msg->session_type = 0;
    msg->message_type = DR2DP_MSG_TYPE_REQUEST;
    msg->operation_type = DR2DP_OP_TYPE_REDIRECT_FLOW;
    msg->response_code = 0;
    msg->xid = 0;
    msg->data_length = htonq((p->length() + pkt_len) - sizeof(dr2dp_msg));

    dr2dp_redirect_flow_msg *flow_msg =
        reinterpret_cast<dr2dp_redirect_flow_msg *>(p->data() +
                                                    sizeof(dr2dp_msg));
    flow_msg->flags = 0;
    flow_msg->syn_option_length = tcp_syn_options.length();
    flow_msg->ack_option_length = tcp_ack_options.length();

    memcpy((p->data() + (sizeof(dr2dp_msg) + sizeof(dr2dp_redirect_flow_msg))),
           tcp_syn_options.c_str(), tcp_syn_options.length());
    memcpy((p->data() + (sizeof(dr2dp_msg) +
                         sizeof(dr2dp_redirect_flow_msg) +
                         tcp_syn_options.length())),
           tcp_ack_options.c_str(), tcp_ack_options.length());

    output(0).push(p);

    pkt = pkts;
    while (pkt != NULL) {
        Packet *q = pkt;
        pkt = pkt->next();

        output(0).push(q);
    }
    pkts = (Packet *)NULL;
}

void
DR2DPEncoder::tls_established(const IPFlowID &flow, const String &random)
{
    assert(random.length() >= 28);

    int pkt_len = sizeof(dr2dp_msg) + sizeof(dr2dp_tls_flow_msg);

    WritablePacket *p = WritablePacket::make(pkt_len);
    if (!p) {
        click_chatter("DR2DPEncoder::tls_established: "
                      "failed to allocate packet");
        return;
    }

    dr2dp_msg *msg = reinterpret_cast<dr2dp_msg *>(p->data());
    msg->protocol = DR2DP_PROTOCOL_VERSION;
    msg->session_type = 0;
    msg->message_type = DR2DP_MSG_TYPE_REQUEST;
    msg->operation_type = DR2DP_OP_TYPE_TLS_FLOW_ESTABLISHED;
    msg->response_code = 0;
    msg->xid = 0;
    msg->data_length = htonq(pkt_len - sizeof(dr2dp_msg));

    dr2dp_tls_flow_msg *flow_msg = 
        reinterpret_cast<dr2dp_tls_flow_msg *>(p->data() + sizeof(dr2dp_msg));

    memset(flow_msg, 0, sizeof(dr2dp_tls_flow_msg));
    flow_msg->src_addr = flow.saddr().addr();
    flow_msg->dst_addr = flow.daddr().addr();
    flow_msg->src_port = flow.sport();
    flow_msg->dst_port = flow.dport();
    flow_msg->protocol = IP_PROTO_TCP;

    memcpy((p->data() + sizeof(dr2dp_msg) + 16), random.c_str(), 28);

    output(0).push(p);
}

void
DR2DPEncoder::run_timer(Timer *timer)
{
    assert(timer = &_ping_timer);
    click_chatter("DR2DPEncoder::run_timer: sending ping message");

    WritablePacket *p = WritablePacket::make(sizeof(dr2dp_msg));
    if (!p) {
        click_chatter("DR2DPEncoder::run_timer: "
                      "failed to allocate packet");
        _ping_timer.reschedule_after_sec(_ping_interval);
        return;
    }

    dr2dp_msg *msg = reinterpret_cast<dr2dp_msg *>(p->data());
    msg->protocol = DR2DP_PROTOCOL_VERSION;
    msg->session_type = 0;
    msg->message_type = DR2DP_MSG_TYPE_REQUEST;
    msg->operation_type = DR2DP_OP_TYPE_PING;
    msg->response_code = 0;
    msg->xid = 0;
    msg->data_length = 0;

    output(0).push(p);

    _ping_timer.reschedule_after_sec(_ping_interval);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(DR2DPEncoder)
