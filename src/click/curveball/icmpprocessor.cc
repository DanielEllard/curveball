/* $Id$
 *
 * This material is based upon work supported by the Defense Advanced
 * Research Projects Agency under Contract No. N66001-11-C-4017.
 * Copyright 2011 - Raytheon BBN Technologies - All Rights Reserved
 */

#include <click/config.h>
#include "icmpprocessor.hh"
#include <click/args.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/vector.hh>
#include <clicknet/ip.h>
#include <clicknet/icmp.h>
#include <clicknet/tcp.h>
CLICK_DECLS


ICMPProcessor::ICMPProcessor()
{
}

ICMPProcessor::~ICMPProcessor()
{
}

int
ICMPProcessor::configure(Vector<String> &conf, ErrorHandler *errh)
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

        } else {
            errh->error("invalid keyword");
        }
    }

    return 0;
}

int
ICMPProcessor::initialize(ErrorHandler *)
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
ICMPProcessor::push(int, Packet *p)
{
    assert(p->has_network_header());
    assert(p->ip_header()->ip_p == IP_PROTO_ICMP);

    // XXX Need a plan for fragmented ICMP packets.
    if (IP_ISFRAG(p->ip_header())) {
        output(0).push(p);
        return;
    }

    assert(p->has_transport_header());

    if (!redirect_icmp_packet(p)) {
        output(0).push(p);
    }
}

bool
ICMPProcessor::redirect_icmp_packet(Packet *p)
{
    if ((unsigned int)p->transport_length() < sizeof(click_icmp)) {
        return false;
    }

    if (p->icmp_header()->icmp_type != 3  &&
        p->icmp_header()->icmp_type != 5  &&
        p->icmp_header()->icmp_type != 11 &&
        p->icmp_header()->icmp_type != 12) {
        return false;
    }

    const unsigned char *data = p->transport_header() + sizeof(click_icmp);
    unsigned int len = p->transport_length() - sizeof(click_icmp);

    if (len < sizeof(click_ip)) {
        click_chatter("ICMPProcessor::redirect_icmp_packet: "
                      "IP header not included within packet");
        return false;
    }

    const click_ip *ip_hdr = reinterpret_cast<const click_ip *>(data);
    unsigned int ip_hdr_len = ip_hdr->ip_hl * 4;

    // non-first packet fragments do not include the necessary TCP header
    if (IP_ISFRAG(ip_hdr) && !IP_FIRSTFRAG(ip_hdr)) {
        click_chatter("ICMPProcessor::redirect_icmp_packet: "
                      "non-first IP packet fragment within ICMP packet");
        return false;
    }

    if (len < ip_hdr_len + sizeof(click_tcp)) {
        click_chatter("ICMPProcessor::redirect_icmp_packet: "
                      "TCP header not included within packet");
        return false;
    }

    const click_tcp *tcp_hdr =
                         reinterpret_cast<const click_tcp *>(data + ip_hdr_len);

    // addrs/ports required to be in network byte order
    IPFlowID flow_id(IPAddress(ip_hdr->ip_src), tcp_hdr->th_sport,
                     IPAddress(ip_hdr->ip_dst), tcp_hdr->th_dport);

    for (Vector<SentinelDetector *>::iterator d = _sentinel_detectors.begin();
         d != _sentinel_detectors.end();
         ++d) {

        if ((*d)->redirected_flow(flow_id)) {
            (*d)->redirect_icmp_packet(flow_id, p);
            return true;
        }

        if ((*d)->redirected_flow(flow_id.reverse())) {
            (*d)->redirect_icmp_packet(flow_id, p, true);
            return true;
        }
    }

    return false;
}


CLICK_ENDDECLS
EXPORT_ELEMENT(ICMPProcessor)
