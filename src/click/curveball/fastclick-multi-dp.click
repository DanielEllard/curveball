/*
 * This material is funded in part by a grant from the United States
 * Department of State. The opinions, findings, and conclusions stated
 * herein are those of the authors and do not necessarily reflect
 * those of the United States Department of State.
 *
 * Copyright 2016 - Raytheon BBN Technologies Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

require(package "curveball");

define($FORWARD_DEV netmap:eth4,
       $REVERSE_DEV netmap:eth5,
       $TLS_PORT 443,
       $UDP_PORT 9,
       $UDP_SRC_ADDR 10.0.0.32,
       $DP_PATH_ONE '/tmp/curveball0',
       $DP_PATH_TWO '/tmp/curveball1',
       $STAT_INTERVAL 1,
       $MAX_ZERO_INTERVAL 10)

forward_classifier :: Classifier(12/0800,         // IP in Ether
                                 12/8100 16/0800, // VLAN-tagged IP in Ether
                                 -)
reverse_classifier :: Classifier(12/0800, -)

forward_ip_classifier :: IPClassifier(dst tcp port $TLS_PORT,
                                      icmp,
                                      dst udp port $UDP_PORT,
                                      -)

reverse_ip_classifier :: IPClassifier(icmp, -)

tls_flow_detector	:: TLSFlowDetector(PORT $TLS_PORT,
                                           ENCODER dr2dp_encoder,
                                           UDP_PORT $UDP_PORT,
                                           UDP_SRC_ADDR $UDP_SRC_ADDR,
                                           REVERSE false)

forward_icmp_processor	:: ICMPProcessor(DETECTOR tls_flow_detector)
reverse_icmp_processor	:: ICMPProcessor(DETECTOR tls_flow_detector)

udp_receiver		:: UDPReceiver(PORT $UDP_PORT,
                                       IPADDR $UDP_SRC_ADDR,
                                       DETECTOR tls_flow_detector)

dr2dp_encoder :: DR2DPEncoder()
dr2dp_decoder_one :: DR2DPDecoder(DETECTOR tls_flow_detector)
dr2dp_decoder_two :: DR2DPDecoder(DETECTOR tls_flow_detector,
                                  FILTER_FILENAME /tmp/sentinel_filter,
                                  BLACKLIST_FILENAME /tmp/bad_dh_list)

decoy_proxy_one :: Socket(UNIX, $DP_PATH_ONE, CLIENT true, HEADROOM 0)
decoy_proxy_two :: Socket(UNIX, $DP_PATH_TWO, CLIENT true, HEADROOM 0)

forward_incoming :: FromNetmapDevice($FORWARD_DEV, PROMISC true)
forward_outgoing :: ToNetmapDevice($REVERSE_DEV)
forward_incoming
	-> CBPacketStats(LABEL "Incoming",
                         INTERVAL $STAT_INTERVAL,
                         MAX_ZERO_INTERVAL $MAX_ZERO_INTERVAL)
	-> forward_classifier;

reverse_incoming :: FromNetmapDevice($REVERSE_DEV, PROMISC true)
reverse_outgoing :: ToNetmapDevice($FORWARD_DEV)
reverse_incoming -> reverse_classifier;

// IPv4 traffic
forward_classifier[0]
	-> CBStripEther()
	-> MarkIPHeader()
	-> forward_ip_classifier;
forward_classifier[1]
	-> CBStripEther()
	-> MarkIPHeader()
	-> forward_ip_classifier;
reverse_classifier[0]
	-> CBStripEther()
	-> MarkIPHeader()
	-> reverse_ip_classifier;

// non-IPv4 traffic
forward_classifier[2] -> forward_outgoing;
reverse_classifier[1] -> reverse_outgoing;

// TLS
forward_ip_classifier[0]
	-> CBPacketStats(LABEL "TLS", INTERVAL $STAT_INTERVAL, TCP true)
	-> [0]tls_flow_detector;

SimpleIdle -> [1]tls_flow_detector;	// no incoming reverse traffic

tls_flow_detector[0]		// Curveball
	-> dr2dp_encoder;

dr2dp_encoder[0] -> decoy_proxy_one;
dr2dp_encoder[1] -> decoy_proxy_two;

tls_flow_detector[1]		// Non-Curveball
	-> CBUnstripEther()
	-> forward_outgoing;

tls_flow_detector[2]		// UDP Notifications
	-> forward_outgoing;

tls_flow_detector[3]		// Reverse Traffic
	-> CBUnstripEther()
	-> reverse_outgoing;

// ICMP
forward_ip_classifier[1]
	-> forward_icmp_processor
	-> CBUnstripEther()
	-> forward_outgoing;

reverse_ip_classifier[0]
	-> reverse_icmp_processor
	-> CBUnstripEther()
	-> reverse_outgoing;

// UDP
forward_ip_classifier[2]
	-> udp_receiver
	-> CBUnstripEther()
	-> forward_outgoing;

// everything else
forward_ip_classifier[3] -> CBUnstripEther() -> forward_outgoing;
reverse_ip_classifier[1] -> CBUnstripEther() -> reverse_outgoing;

// handle data/packets received from the decoy proxy
decoy_proxy_one -> dr2dp_decoder_one;
dr2dp_decoder_one[0] -> forward_outgoing;
dr2dp_decoder_one[1] -> reverse_outgoing;

decoy_proxy_two -> dr2dp_decoder_two;
dr2dp_decoder_two[0] -> forward_outgoing;
dr2dp_decoder_two[1] -> reverse_outgoing;
