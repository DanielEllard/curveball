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
#include "dr2dpdecoder.hh"
#include "dr2dpprotocol.hh"
#include <click/bitvector.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/integers.hh>
#include <click/vector.hh>
#if CLICK_LINUXMODULE
#include <click/cxxprotect.h>
CLICK_CXX_PROTECT
#include <linux/fs.h>
CLICK_CXX_UNPROTECT
#include <click/cxxunprotect.h>
#elif CLICK_USERLEVEL
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
CLICK_DECLS


DR2DPDecoder::DR2DPDecoder()
    : _pktbuf((Packet *)NULL), _header_needed(false), _bytes_remaining(0)
{
}

DR2DPDecoder::~DR2DPDecoder()
{
    release_pkt_buffer();
}

int
DR2DPDecoder::configure(Vector<String> &conf, ErrorHandler *errh)
{
    for (int i = 0; i < conf.size(); i++) {
        Vector<String> parts;
        cp_spacevec(conf[i], parts);

        if (parts.size() == 0 || parts.size() > 2) {
            errh->error("conf arg requires keyword/value pair");
            continue;
        }

        if (parts[0].equals("DETECTOR", 8)) {
            Element *e = cp_element(parts[1], this, errh);
            if (e != NULL ) {
                _configured_detectors.push_back(e);
            } else {
                errh->error("invalid element");
            }

        } else if (parts[0].equals("FILTER_FILENAME", 15)) {
            _filter_file = parts[1];

        } else if (parts[0].equals("BLACKLIST_FILENAME", 18)) {
            _dh_blacklist_file = parts[1];

        } else {
            errh->error("invalid keyword");
        }
    }

    return 0;
}

int
DR2DPDecoder::initialize(ErrorHandler *)
{
    for (Vector<Element *>::iterator e = _configured_detectors.begin();
         e != _configured_detectors.end();
         ++e) {

        if ((*e)->cast("SentinelDetector")) {
            SentinelDetector *d = (SentinelDetector *)(*e);
	    d->update_sentinel_filter(&_sentinels);
            _sentinel_detectors.push_back(d);
        }
    }

    return 0;
}

void
DR2DPDecoder::push(int, Packet *p)
{
    parse(p);
}

void
DR2DPDecoder::parse(Packet *p)
{
    bool done = false;
    while (!done) {
        // Handle partial DR2DP message.
        if (_pktbuf != NULL) {
            p = append_to_pkt_buffer(p);
            if (p == NULL) {
                return;
            }
        }

        const dr2dp_msg *msg = reinterpret_cast<const dr2dp_msg *>(p->data());

        if (p->length() < sizeof(dr2dp_msg)) {
            // Entire DR2DP message header not present;
            // DR2DP message spans multiple packet buffers.
            new_pkt_buffer(p);
            return;
        }

        if (msg->protocol != DR2DP_PROTOCOL_VERSION) {
            click_chatter("DR2DPDecoder::parse: "
                          "Invalid DR2DP protocol version %d", msg->protocol);
            p->kill();
            return;
        }

        Packet *pkt = p;
        bool release_pkt = true;
        uint64_t pkt_length = sizeof(dr2dp_msg) + ntohq(msg->data_length);

        if (pkt->length() < pkt_length) {
            // DR2DP message spans multiple packet buffers.
            new_pkt_buffer(pkt, pkt_length);
            return;

        } else if (pkt->length() > pkt_length) {
            // DR2DP message accounts for only part of the packet buffer.
            pkt = p->clone();
            pkt->take(pkt->length() - pkt_length);
            p->pull(pkt_length);

        } else { // pkt->length() == pkt_length
            done = true;
        }

        // Process a fully recieved DR2DP message.
        switch (msg->operation_type) {

        // Ping message.
        case DR2DP_OP_TYPE_PING:
            click_chatter("DR2DPDecoder::parse: ping message received");
            break;

        // Packet to be forwarded on behalf of decoy proxy.
        case DR2DP_OP_TYPE_FORWARD:
            if (msg->message_type != DR2DP_MSG_TYPE_REQUEST) {
                click_chatter("DR2DPDecoder::parse: "
                              "Invalid message type for forward operation.");
                break;
            }

            // remove DR2DP protocol message header
            pkt->pull(sizeof(dr2dp_msg));

            // push packet out the element's outbound interface
            output(0).push(pkt);
            release_pkt = false;

            break;

        // New sentinel bloom filter to upload.
        case DR2DP_OP_TYPE_SENTINEL_FILTER:
            parse_filter_msg(pkt);
            break;

        case DR2DP_OP_TYPE_REMOVE_FLOW:
            if (msg->message_type != DR2DP_MSG_TYPE_REQUEST) {
                click_chatter("DR2DPDecoder::parse: "
                              "Invalid message type for remove operation.");
                break;
            }
            parse_remove_flow_msg(pkt);
            break;

        case DR2DP_OP_TYPE_DH_BLACKLIST:
            parse_dh_blacklist_msg(pkt);
            break;

        default:
            click_chatter("DR2DPDecoder::parse: "
                          "Unsupported DR2DP operation type %d",
                          msg->operation_type);
            break;
        }

        if (release_pkt) {
            // No longer need the packet data; release memory.
            pkt->kill();
        }
    }

    return;
}

void
DR2DPDecoder::parse_filter_msg(Packet *p)
{
    if (_filter_file.length() == 0) {
        click_chatter("DR2DPDecoder::parse_filter_msg: No filter file. ");
        return;
    }

    if (_sentinel_detectors.empty()) {
        click_chatter("DR2DPDecoder::parse_filter_msg: No sentinel detector.");
        return;
    }

    const dr2dp_msg *msg_hdr = reinterpret_cast<const dr2dp_msg *>(p->data());

    uint64_t data_length = ntohq(msg_hdr->data_length);
    if (data_length < sizeof(dr2dp_filter_msg)) {
        click_chatter("DR2DPDecoder::parse_filter_msg: Message not complete.");
        return;
    }

    p->pull(sizeof(dr2dp_msg));
    const dr2dp_filter_msg *msg =
        reinterpret_cast<const dr2dp_filter_msg *>(p->data());

    Vector<uint32_t> salt_values;
    unsigned int num_salts = ntohs(msg->num_salts);

    uint32_t salt_length = data_length - sizeof(dr2dp_filter_msg);
    uint32_t *salt = (uint32_t *)(p->data() + sizeof(dr2dp_filter_msg));

    if (salt_length != num_salts * sizeof(uint32_t)) {
        click_chatter("DR2DPDecoder::parse_filter_msg: "
                      "Invalid message length.");
        return;
    }

    for (unsigned int i = 0; i < num_salts; ++i, ++salt) {
        salt_values.push_back(ntohl(*salt));
    }

    int hash_size = ntohs(msg->hash_size);
    if (hash_size < 0 || hash_size > 30) {
        click_chatter("DR2DPDecoder::parse_filter_msg: Invalid hash size %d",
                      hash_size);
        return;
    }

    if (hash_size == 0) {
        _sentinels = BloomFilter();
        click_chatter("DR2DPDecoder::parse_filter_msg: "
                      "loading empty sentinel bloom filter");
        return;
    }

    bool valid = true;
    int total_bits = BloomFilter::bit_vector_size(hash_size);
    Bitvector bit_vector(total_bits);
    uint32_t *bit_data = bit_vector.words();

#if CLICK_USERLEVEL
    int fd = open(_filter_file.c_str(), O_RDONLY);
    if (fd < 0) {
        click_chatter("DR2DDecoder::parse_filter_msg: "
                      "failed to open filter file %s", _filter_file.c_str());
        valid = false;

#elif CLICK_LINUXMODULE
    struct file* filp = (struct file *)NULL;
    mm_segment_t oldfs;

    oldfs = get_fs();
    set_fs(KERNEL_DS);

    filp = filp_open(_filter_file.c_str(), 0, O_RDONLY);
    if (IS_ERR(filp) || filp == NULL) {
        click_chatter("DR2DPDecoder::parse_filter_msg: "
                      "failed to open filter file %s", _filter_file.c_str());
        filp = (struct file *)NULL;
        valid = false;
#endif

    } else {

        int read_bytes;
        int remaining_bytes = ((total_bits < 8)? 1 : (total_bits / 8));
        uint8_t buf[256];

        while(remaining_bytes > 0) {

#if CLICK_USERLEVEL
            read_bytes = read(fd, buf, 256);
#elif CLICK_LINUXMODULE
            read_bytes = vfs_read(filp, (char *)buf, 256, &filp->f_pos);
#endif

            if (read_bytes < 0) {
                click_chatter("DR2DPDecoder::parse_filter_msg: "
                              "Error reading filter");
                valid = false;
                break;

            } else if (read_bytes == 0) {
                click_chatter("DR2DPDecoder::parse_filter_msg: "
                              "Filter too small");
                valid = false;
                break;

            } else if (read_bytes > remaining_bytes) {
                click_chatter("DR2DPDecoder::parse_filter_msg: "
                              "Filter too large");
                valid = false;
                break;
            }

            memcpy(bit_data, buf, read_bytes);

            bit_data += (read_bytes / 4);
            remaining_bytes -= read_bytes;
        }
    }

#if CLICK_USERLEVEL
    if (fd >= 0) {
        close(fd);
    }

#elif CLICK_LINUXMODULE
    if (filp != NULL) {
        filp_close(filp, (fl_owner_t)NULL);
        filp = (struct file *)NULL;
    }
    set_fs(oldfs);
#endif

    if (valid) {
	_sentinels = BloomFilter(hash_size, bit_vector, salt_values);
        click_chatter("DR2DPDecoder::parse_filter_msg: "
                      "uploaded new sentinel bloom filter");

    } else {
	_sentinels = BloomFilter();
        click_chatter("DR2DPDecoder::parse_filter_msg: "
                      "invalid sentinel bloom filter; loading empty filter");
    }
}

void
DR2DPDecoder::parse_remove_flow_msg(Packet *p)
{
    if (_sentinel_detectors.empty()) {
        click_chatter("DR2DPDecoder::parse_filter_msg: No sentinel detector.");
        return;
    }

    const dr2dp_msg *msg_hdr = reinterpret_cast<const dr2dp_msg *>(p->data());

    uint64_t data_length = ntohq(msg_hdr->data_length);
    if (data_length < sizeof(dr2dp_remove_flow_msg)) {
        click_chatter("DR2DPDecoder::parse_remove_flow_msg: "
                      "Message not complete.");
        return;
    }

    p->pull(sizeof(dr2dp_msg));
    const dr2dp_remove_flow_msg *msg =
        reinterpret_cast<const dr2dp_remove_flow_msg *>(p->data());

    // addrs/ports required to be in network byte order
    IPFlowID flow_id(IPAddress(msg->src_addr), msg->src_port,
                     IPAddress(msg->dst_addr), msg->dst_port);

    for (Vector<SentinelDetector *>::iterator d = _sentinel_detectors.begin();
         d != _sentinel_detectors.end();
         ++d) {
        (*d)->remove_flow(flow_id);
    }
}

void
DR2DPDecoder::parse_dh_blacklist_msg(Packet *)
{
    if (_dh_blacklist_file.length() == 0) {
        click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: "
                      "no blacklist file configured");
        return;
    }

    if (_sentinel_detectors.empty()) {
        click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: "
                      "no sentinel detectors configured");
        return;
    }

    Vector<DHBlacklistEntry> blacklist;

#if CLICK_USERLEVEL
    FILE *fp = fopen(_dh_blacklist_file.c_str(), "r");
    if (fp == NULL) {
        click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: "
                      "failed to open blacklist file %s",
                      _dh_blacklist_file.c_str());

    } else {
        char *line = NULL;
        size_t line_length = 0;

        while (getline(&line, &line_length, fp) != -1) {
            char *addr = NULL;
            char *mask = NULL;
            int n;

            n = sscanf(line, "%as %as", &addr, &mask);
            if (n == 1) {
                struct in_addr ipaddr;

                if (inet_aton(addr, &ipaddr) != 0) {

                    IPAddress new_addr(ipaddr);
                    DHBlacklistEntry entry(new_addr);
                    blacklist.push_back(entry);

                } else {
                    click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: "
                                  "invalid IP address: %s", addr); 
                }

                free(addr);

            } else if (n == 2) {
                struct in_addr ipaddr;
                struct in_addr ipmask;

                if ((inet_aton(addr, &ipaddr) != 0) &&
                    (inet_aton(mask, &ipmask) != 0)) {

                    IPAddress new_addr(ipaddr);
                    IPAddress new_mask(ipmask);

                    if (new_mask.mask_to_prefix_len() == -1) {
                        click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: "
                                      "invalid mask: %s", mask);
                    } else {
                        DHBlacklistEntry entry(new_addr, new_mask);
                        blacklist.push_back(entry);
                    }

                } else {
                    click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: "
                                  "invalid IP address/mask: %s %s",
                                  addr, mask);
                }

                free(addr);
                free(mask);

            } else {
                click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: "
                              "failed to parse blacklist line: %s", line);
            }

            free(line);
            line = NULL;
            line_length = 0;
        }

        fclose(fp);
    }

#elif CLICK_LINUXMODULE
    click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: "
                  "loading of DH blacklist not supported in kernel mode");

#endif

    _dh_blacklist = blacklist;

    for (Vector<SentinelDetector *>::iterator d = _sentinel_detectors.begin();
         d != _sentinel_detectors.end();
         ++d) {
        (*d)->update_dh_blacklist(_dh_blacklist);
    }

    click_chatter("DR2DPDecoder::parse_dh_blacklist_msg: "
                  "uploaded new DH blacklist");
}

void
DR2DPDecoder::new_pkt_buffer(Packet *p, uint64_t length_needed)
{
    assert(_pktbuf == NULL);
    assert(length_needed == 0 || length_needed > p->length());

    _pktbuf = p;
    _pktbuf->set_prev((Packet *)NULL);
    _pktbuf->set_next((Packet *)NULL);

    if (length_needed == 0) {
        _header_needed = true;
        _bytes_remaining = sizeof(dr2dp_msg) - p->length();

    } else {
        _bytes_remaining = length_needed - p->length();
    }
}

Packet *
DR2DPDecoder::append_to_pkt_buffer(Packet *p)
{
    assert(_pktbuf != NULL);
    assert(_bytes_remaining > 0);

    if (_header_needed) {
        if (_bytes_remaining > p->length()) {
            add_pkt(p);
            p = (Packet *)NULL;
            return p;
        }

        dr2dp_msg msg_hdr;
        memset(&msg_hdr, 0, sizeof(dr2dp_msg));

        // Build complete copy of DR2DP message header.
        Packet *pkt = _pktbuf;
        unsigned char *cur_pos = (unsigned char *)&msg_hdr;
        do {
            memcpy(cur_pos, pkt->data(), pkt->length());
            cur_pos += pkt->length();
            pkt = pkt->next();
        } while (pkt != _pktbuf && pkt != NULL);

        assert((cur_pos + _bytes_remaining) ==
               ((unsigned char *)&msg_hdr + sizeof(dr2dp_msg)));

        memcpy(cur_pos, p->data(), _bytes_remaining);

        _bytes_remaining += ntohq(msg_hdr.data_length);
        _header_needed = false;
    }

    if (_bytes_remaining >= p->length()) {
        add_pkt(p);
        p = (Packet *)NULL;

    } else {
        Packet * pkt = p->clone();
        pkt->take(pkt->length() - _bytes_remaining);
        p->pull(_bytes_remaining);

        add_pkt(pkt);
        assert(_bytes_remaining == 0);
    }

    if (_bytes_remaining == 0) {
        process_pkt_buffer();
    }

    return p;
}

void
DR2DPDecoder::add_pkt(Packet *p)
{
    assert(_pktbuf);

    if (_pktbuf->prev() == NULL) {
        assert(_pktbuf->next() == NULL);

        _pktbuf->set_next(p);
        _pktbuf->set_prev(p);
        p->set_next(_pktbuf);
        p->set_prev(_pktbuf);

    } else {
        assert(_pktbuf->prev() != NULL);
        assert(_pktbuf->next() != NULL);

        _pktbuf->prev()->set_next(p);
        p->set_prev(_pktbuf->prev());
        _pktbuf->set_prev(p);
        p->set_next(_pktbuf);
    }

    _bytes_remaining -= p->length();
}

void
DR2DPDecoder::process_pkt_buffer()
{
    assert(_header_needed == false);
    assert(_bytes_remaining == 0);
    assert(_pktbuf->next() != NULL);

    uint64_t orig_len = _pktbuf->length();
    uint64_t curr_len = _pktbuf->length();

    uint64_t data_len_to_add = 0;
    for (Packet *p = _pktbuf->next(); p != _pktbuf; p = p->next()) {
        data_len_to_add += p->length();
    }

    // Remove first packet from buffer.
    Packet * first_pkt = _pktbuf;
    _pktbuf->prev()->set_next(_pktbuf->next());
    _pktbuf->next()->set_prev(_pktbuf->prev());
    _pktbuf = _pktbuf->next();
    first_pkt->set_next((Packet *)NULL);
    first_pkt->set_prev((Packet *)NULL);

    // Create new packet to contain the total assembled DR2DP message.
    WritablePacket * pkt = first_pkt->put(data_len_to_add);
    if (pkt == NULL) {
        click_chatter("DR2DPDecoder::process_pkt_buffer: "
                      "failed to allocate packet");
        release_pkt_buffer();
        return;
    }

    // Copy message pieces from remaining packets to new packet buffer.
    Packet *p = _pktbuf;
    unsigned char * end_data = pkt->data() + curr_len;
    do {
        memcpy(end_data, p->data(), p->length());
        end_data += p->length();
        curr_len += p->length();
        p = p->next();
    } while (p != _pktbuf);
    
    if (curr_len != orig_len + data_len_to_add) {
        click_chatter("DR2DPDecoder::process_pkt_buffer: "
                      "packet lengths fail to match");
        return;
    }

    release_pkt_buffer();

    // Process complete DR2DP message.
    parse(pkt);
}

void
DR2DPDecoder::release_pkt_buffer()
{
    _header_needed = false;
    _bytes_remaining = 0;

    if (_pktbuf == NULL) {
        return;
    }

    if (_pktbuf->prev() != NULL) {
        _pktbuf->prev()->set_next((Packet *)NULL);
    }

    Packet * p = _pktbuf;
    Packet * tmp = (Packet *)NULL;

    while (p != NULL) {
        tmp = p;
        p = p->next();
        tmp->kill();
    }

    _pktbuf = (Packet *)NULL;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(DR2DPDecoder)
