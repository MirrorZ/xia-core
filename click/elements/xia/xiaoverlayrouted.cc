#include <click/config.h>
#include "xiaoverlayrouted.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libgen.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <string>
#include <vector>
#include <map>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include "xroute.pb.h"

RouteState route_state;
XIARouter xr;

#define SID_XOVERLAY "SID:1110000000000000000000000000000000001111"

CLICK_DECLS

XIAOverlayRouted::XIAOverlayRouted()
{
}

XIAOverlayRouted::~XIAOverlayRouted()
{
}

std::string sendHello() 
{
	int buflen, rc;
	string message;
	Node n_ad(route_state.myAD);
	Node n_hid(route_state.myHID);
	Node n_sid(SID_XOVERLAY);

	Xroute::XrouteMsg msg;
	Xroute::HelloMsg *hello = msg.mutable_hello();
	Xroute::Node     *node  = hello->mutable_node();
	Xroute::XID      *ad    = node->mutable_ad();
	Xroute::XID      *hid   = node->mutable_hid();
	Xroute::XID      *sid   = node->mutable_sid();

	msg.set_type(Xroute::HELLO_MSG);
	msg.set_version(Xroute::XROUTE_PROTO_VERSION);
	hello->set_flags(route_state.flags);
	ad ->set_type(n_ad.type());
	ad ->set_id(n_ad.id(), XID_SIZE);
	hid->set_type(n_hid.type());
	hid->set_id(n_hid.id(), XID_SIZE);
	sid->set_type(n_sid.type());
	sid->set_id(n_sid.id(), XID_SIZE);


//	printf("sending %s\n", msg.DebugString().c_str());
	// printf("**** sending lsa with and num_neighbors %d \n", route_state.num_neighbors);

	msg.SerializeToString(&message);
	return message;
}

void XIAOverlayRouted::push(int port, Packet *p_in)
{
	printf("In overlay\n");
	std::string msg =  sendHello();

	struct click_ip *ip;
	struct click_udp *udp;
  	WritablePacket *q = Packet::make(sizeof(*ip) + sizeof(*udp) + len(msg));
  	memset(q->data(), '\0', q->length());
	ip = (struct click_ip *) q->data();
  	udp = (struct click_udp *) (ip + 1);
  	memcpy(q + sizeof(*ip) + sizeof(*udp), msg.c_str, len(msg));

	ip->ip_v = 4;
	ip->ip_hl = 5;
	ip->ip_tos = 0x10;
	ip->ip_len = htons(q->length());
	ip->ip_id = htons(0); // what is this used for exactly?
	ip->ip_off = htons(IP_DF);
	ip->ip_ttl = 255;
	ip->ip_p = IP_PROTO_UDP;
	ip->ip_sum = 0;
	struct in_addr *saddr = malloc(sizeof(struct in_addr));
	struct in_addr *daddr = malloc(sizeof(struct in_addr));
	assert(saddr);
	assert(daddr);
	inet_aton("10.0.1.128", &saddr->saddr);
	inet_aton("10.0.1.130", &daddr->saddr);
	ip->ip_src = saddr;
	ip->ip_dst = daddr;


	udp->uh_sport = htons(8772);
	udp->uh_dport = htons(8772);
	udp->ulen = htons(len(msg));

	q->set_ip_header(ip, ip->ip_hl << 2);

	output(0).push(q);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(XIAOverlayRouted)
ELEMENT_MT_SAFE(XIAOverlayRouted)