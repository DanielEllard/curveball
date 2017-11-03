/* $Id$
 *
 * This material is based upon work supported by the Defense Advanced
 * Research Projects Agency under Contract No. N66001-11-C-4017.
 * Copyright 2011 - Raytheon BBN Technologies - All Rights Reserved
 */

#ifndef CURVEBALL_ICMPPROCESSOR_HH
#define CURVEBALL_ICMPPROCESSOR_HH
#include <click/element.hh>
#include "sentineldetector.hh"
CLICK_DECLS

// Element that handles incoming ICMP packets.

class ICMPProcessor : public Element {
  public:

    ICMPProcessor();
    ~ICMPProcessor();

    const char *class_name() const	{ return "ICMPProcessor"; }
    const char *port_count() const	{ return "1/1"; }
    const char *processing() const	{ return PUSH; }
    const char *flow_code()  const	{ return COMPLETE_FLOW; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);

    void push(int, Packet *);

  private:

    bool redirect_icmp_packet(Packet *p);

    // reference to sentinel detector elements
    Vector<SentinelDetector *>	_sentinel_detectors;
    Vector<Element *>		_configured_detectors;
};


CLICK_ENDDECLS
#endif
