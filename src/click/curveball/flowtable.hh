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

#ifndef CURVEBALL_FLOWTABLE_HH
#define CURVEBALL_FLOWTABLE_HH
#include <click/hashtable.hh>
#include <click/ipflowid.hh>
CLICK_DECLS

#define FLOW_STATE_ACK		1
#define FLOW_STATE_SENTINEL	2
#define FLOW_STATE_SEGMENT	3
#define FLOW_STATE_REDIRECT	4

// Defines a single entry within the flow table.
class FlowEntry {
  public:

    FlowEntry()
	: _state(0), _isn(0), _server_tcp_ack(false), _server_proto_ack(false),
          _active(false), _pktbuf((Packet *)NULL), _seq_ptr(0),
          _maintain_buffer(false) {}
    FlowEntry(uint32_t isn)
        : _state(FLOW_STATE_ACK), _isn(isn),
          _server_tcp_ack(false), _server_proto_ack(false),
          _active(true), _pktbuf((Packet *)NULL), _seq_ptr(isn),
          _maintain_buffer(false) {}
    ~FlowEntry() { release_pkt_buffer(); }

    void set_state(int state)	{ _state = state; }
    void set_active()		{ _active = true; }
    void set_inactive()		{ _active = false; }
    void set_server_ack()	{ _server_tcp_ack = true; }
    void set_proto_ack()	{ _server_proto_ack = true; }
    void set_tcp_syn_options(const String & options)
				{ _tcp_syn_options = options; }
    void set_tcp_ack_options(const String & options)
				{ _tcp_ack_options = options; }
    void maintain_segment_buffer() { _maintain_buffer = true; }

    int		state() const		{ return _state; }
    uint32_t 	isn() const 		{ return _isn; }
    bool 	active() const 		{ return _active; }
    bool        server_ack() const	{ return _server_tcp_ack; }
    bool	proto_ack() const	{ return _server_proto_ack; }
    Packet *	pktbuf()		{ return _pktbuf; }
    const String & tcp_syn_options() const { return _tcp_syn_options; }
    const String & tcp_ack_options() const { return _tcp_ack_options; }
    const String & segment_buffer()  const { return _segment_buffer; }

    // methods to process buffer of segmented sentinel packets
    void add_pkt(Packet *p);
    bool ready_for_sentinel_check(int len);
    bool ready_for_sentinel_check(const String &end_str);
    void construct_sentinel_buf(char *buf, int len, int offset);
    void release_pkt_buffer();

  private:

    int		_state;

    // initial sequence number contained within TCP SYN packet
    uint32_t	_isn;

    // indicates whether or not server-side acks have been observed
    bool 	_server_tcp_ack;
    bool	_server_proto_ack;

    // options contained within TCP SYN/ACK packets
    String	_tcp_syn_options;
    String	_tcp_ack_options;

    // indicates that the flow has been active
    bool	_active;

    // buffer of segmented sentinel packets
    Packet *	_pktbuf;
    uint32_t    _seq_ptr;

    bool	_maintain_buffer;
    String	_segment_buffer;
    void build_segment_buffer();
};


// Class that implements a flow table that manages Curveball flows.
class FlowTable {
  public:

    FlowTable();
    ~FlowTable();

    void add_flow(Packet *p);
    void remove_flow(const IPFlowID &flow_key);

    FlowEntry * get_flow(const IPFlowID &flow_key)
                    { return _flow_table.get_pointer(flow_key); }

    bool member_flow(const IPFlowID &flow_key)
             { return (_flow_table.find(flow_key) != _flow_table.end()); }

    void remove_inactive_flows();

    void clear() { _flow_table.clear(); }

    String table_to_str() const;

  private:

    HashTable<IPFlowID, FlowEntry> _flow_table;
};

CLICK_ENDDECLS
#endif
