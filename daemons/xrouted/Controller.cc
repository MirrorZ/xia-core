/*
** Copyright 2017 Carnegie Mellon University
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**    http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdio.h>
#include <sys/time.h>
#include "dagaddr.hpp"
#include "Controller.hh"

// FIXME: it would be good to eliminate all of the conversions
//  instead of having to convert everyting to or from a protobuf
//  through an additional intermediate conversion!

void Controller::purge()
{
	// initialize if this is first time in
	if (_last_purge == 0) {
		_last_purge = time(NULL);
        _last_update_config = _last_purge;
//	    _last_update_latency = _last_purge;
        return;
	}

	time_t now = time(NULL);

    // reload settings from file periodicly in case they have changed
	if (now - _last_update_config >= _settings->update_config()) {
		_last_update_config = now;
        _settings->reload();
	}

    // FIXME: do we really need all 4 of these things???

	if (now - _last_purge >= _settings->expire_time()) {
		_last_purge = now;
		map<string, time_t>::iterator iter = _timeStamp.begin();

		while (iter != _timeStamp.end())
		{
			if (now - iter->second >= _settings->expire_time() * 10) {
				_xr.delRoute(iter->first);
//				_last_update_latency = 0; // force update latency
				syslog(LOG_INFO, "purging host route for : %s", iter->first.c_str());
				_timeStamp.erase(iter++);
			} else {
				++iter;
			}
		}

		map<string, NodeStateEntry>::iterator iter1 = _ADNetworkTable.begin();

		while (iter1 != _ADNetworkTable.end())
		{
			if (now - iter1->second.timestamp >= _settings->expire_time() * 10) {
				syslog(LOG_INFO, "purging neighbor : %s", iter1->first.c_str());
//				_last_update_latency = 0; // force update latency
				_ADNetworkTable.erase(iter1++);
			} else {
				++iter1;
			}
		}

		map<string, NeighborEntry>::iterator iter2 = _neighborTable.begin();

		while (iter2 != _neighborTable.end())
		{
			if (now - iter2->second.timestamp >= _settings->expire_time()) {
//				_last_update_latency = 0; // force update latency
				syslog(LOG_INFO, "purging AD network : %s", iter2->first.c_str());
				_neighborTable.erase(iter2++);
			} else {
				++iter2;
			}
		}

		map<string, NeighborEntry>::iterator iter3 = _ADNeighborTable.begin();

		while (iter3 != _ADNeighborTable.end())
		{
			if (now - iter3->second.timestamp >= _settings->expire_time() * 10) {
//				_last_update_latency = 0; // force update latency
				syslog(LOG_INFO, "purging AD neighbor : %s", iter3->first.c_str());

				_ADNetworkTable[_myAD].neighbor_list.erase(
					std::remove(_ADNetworkTable[_myAD].neighbor_list.begin(),
								_ADNetworkTable[_myAD].neighbor_list.end(),
								iter3->second),
				_ADNetworkTable[_myAD].neighbor_list.end());
				_ADNeighborTable.erase(iter3++);
			} else {
				++iter3;
			}
		}
	}
}


int Controller::handler()
{
	int rc;
	char recv_message[BUFFER_SIZE];
	int iface;
	struct pollfd pfds[3];

	bzero(pfds, sizeof(pfds));
	pfds[0].fd = _local_sock;
	pfds[1].fd = _broadcast_sock;
	pfds[2].fd = _recv_sock;
	pfds[0].events = POLLIN;
	pfds[1].events = POLLIN;
	pfds[2].events = POLLIN;

	// get the next incoming message
	if ((rc = readMessage(recv_message, pfds, 3, &iface)) > 0) {
		processMsg(string(recv_message, rc), iface);
	}

	// send any messages that need to go out
	struct timeval now;
	gettimeofday(&now, NULL);

	if (timercmp(&now, &h_fire, >=)) {
		sendHello();
		timeradd(&now, &h_freq, &h_fire);
	}
	if (timercmp(&now, &l_fire, >=)) {
		sendInterDomainLSA();
		timeradd(&now, &l_freq, &l_fire);
	}

	purge();

	return 0;
}


int Controller::saveControllerDAG()
{
	char s[2048];

	if (XrootDir(s, sizeof(s)) == NULL) {
		// FIXME: handle error
		return -1;
	}

	strncat(s, "/etc/controller_dag", sizeof(s));

	FILE *f = fopen(s, "w");

	if (f == NULL) {
        // FIXME: handle error
		return -1;
	}

	xia_ntop(AF_XIA, &_recv_dag, s, sizeof(s));
	fprintf(f, "%s\n", s);
	fclose(f);

	return 0;
}


int Controller::makeSockets()
{
	char s[MAX_DAG_SIZE];
	Graph g;
	Node src;
	Node nHID(_myHID);
	Node nAD(_myAD);

	// broadcast socket - hello messages, can hopefully go away
	g = src * Node(broadcast_fid) * Node(intradomain_sid);
	if ((_broadcast_sock = makeSocket(g, &_broadcast_dag)) < 0) {
		return -1;
	}

	// controller socket - flooded & interdomain communication
	XcreateFID(s, sizeof(s));
	Node nFID(s);
	XmakeNewSID(s, sizeof(s));
	Node rSID(s);
	g = (src * nHID * nFID * rSID) + (src * nFID * rSID);

	if ((_recv_sock = makeSocket(g, &_recv_dag)) < 0) {
		return -1;
	}
	_controller_sid = s;
	memcpy(&_controller_dag, &_recv_dag, sizeof(sockaddr_x));

	// save the controller dag to disk so xnetj can find it
	if (saveControllerDAG() < 0) {
		// handle the error
	}

	// source socket - sending socket
	XmakeNewSID(s, sizeof(s));
	Node outSID(s);
	g = src * nAD * nHID * outSID;

	if ((_source_sock = makeSocket(g, &_source_dag)) < 0) {
		return -1;
	}

	syslog(LOG_INFO, "Broadcast: %s", g.dag_string().c_str());
	syslog(LOG_INFO, "Flood: %s", g.dag_string().c_str());
	syslog(LOG_INFO, "Source: %s", g.dag_string().c_str());

	return 0;
}

int Controller::init()
{
	srand (time(NULL));
    _settings = new Settings(_hostname);

	_flags = F_CONTROLLER; // FIXME: set any other useful flags at this time

	if (getXIDs(_myAD, _myHID) < 0) {
		exit(-1);
	}
	if (makeSockets() < 0) {
		exit(-1);
	}

	//_sid_discovery_seq = rand()%MAX_SEQNUM;  // sid discovery seq number of this router

	_calc_dijstra_ticks = -8;

	_dual_router_AD = std::string("");
	// mark if this is a dual XIA-IPv4 router
	if( XisDualStackRouter(_source_sock) == 1 ) {
		_dual_router = true;
		syslog(LOG_DEBUG, "configured as a dual-stack router");
	} else {
		_dual_router = false;
	}

	h_freq.tv_sec = 0;
	h_freq.tv_usec = 100000;
	l_freq.tv_sec = 0;
	l_freq.tv_usec = 300000;

	struct timeval now;
	gettimeofday(&now, NULL);
	timeradd(&now, &h_freq, &h_fire);
	timeradd(&now, &l_freq, &l_fire);

	return 0;
}


// FIXME: this did 2 sends in the original SDN code, still needed?
int Controller::sendHello()
{
	int rc = 0;

	Node n_ad(_myAD);
	Node n_hid(_myHID);
	//Node n_sid(_controller_sid);

	Xroute::XrouteMsg msg;
	Xroute::HelloMsg *hello = msg.mutable_hello();
	Xroute::Node     *node  = hello->mutable_node();
	Xroute::XID      *ad    = node->mutable_ad();
	Xroute::XID      *hid   = node->mutable_hid();

	msg.set_type(Xroute::HELLO_MSG);
	msg.set_version(Xroute::XROUTE_PROTO_VERSION);
	hello->set_flags(F_CONTROLLER);
	ad ->set_type(n_ad.type());
	ad ->set_id(n_ad.id(), XID_SIZE);
	hid->set_type(n_hid.type());
	hid->set_id(n_hid.id(), XID_SIZE);

	rc = sendBroadcastMessage(msg);
	// FIXME: not needed until we do SID routing
	// if (rc > 0) {
	// 	// now do it again with the SID
	// 	Xroute::XID *sid = node->mutable_sid();
	// 	sid->set_type(n_sid.type());
	// 	sid->set_id(n_sid.id(), XID_SIZE);

	// 	rc = sendBroadcastMessage(msg);
	// }

	return rc;
}

int Controller::sendInterDomainLSA()
{
	int rc = 1;

	Node a(_myAD);
	Node h(_myHID);	// FIXME: the original code uses the AD here
					// and never does anything with it. Making it HID for nwo

	Xroute::XrouteMsg msg;
	Xroute::GlobalLSAMsg *lsa  = msg.mutable_global_lsa();
	Xroute::Node         *from = lsa->mutable_from();
	Xroute::XID          *ad   = from->mutable_ad();
	Xroute::XID          *hid  = from->mutable_hid();

	msg.set_type(Xroute::GLOBAL_LSA_MSG);
	msg.set_version(Xroute::XROUTE_PROTO_VERSION);
	ad ->set_type(a.type());
	ad ->set_id(a.id(), XID_SIZE);
	hid->set_type(h.type());
	hid->set_id(h.id(), XID_SIZE);
	lsa->set_flags(_flags);

	std::map<std::string, NeighborEntry>::iterator it;
	for (it = _ADNeighborTable.begin(); it != _ADNeighborTable.end(); it++)
	{
		Node aa(it->second.AD);
		Node hh(it->second.HID);

		Xroute::NeighborEntry *n = lsa->add_neighbors();
		ad  = n->mutable_ad();
		hid = n->mutable_hid();

		ad ->set_type(aa.type());
		ad ->set_id(aa.id(), XID_SIZE);
		hid->set_type(hh.type());
		hid->set_id(hh.id(), XID_SIZE);

		n->set_port(it->second.port);
		n->set_cost(it->second.cost);
	}

	for (it = _ADNeighborTable.begin(); it != _ADNeighborTable.end(); it++)
	{
		sockaddr_x ddag;
		Graph g = Node() * Node(it->second.AD) * Node(_controller_sid);
		g.fill_sockaddr(&ddag);

		//syslog(LOG_INFO, "send inter-AD LSA[%d] to %s", _lsa_seq, it->second.AD.c_str());

		int temprc = sendMessage(&ddag, msg);
		rc = (temprc < rc)? temprc : rc;
	}

	return rc;
}

int Controller::sendRoutingTable(NodeStateEntry *nodeState, std::map<std::string, RouteEntry> routingTable)
{
	if (nodeState == NULL || nodeState->hid == _myHID) {
		// If destHID is self, process immediately
		return processRoutingTable(routingTable);

	} else if (nodeState->dag.sx_family != AF_XIA) {
		// this entry was either created as a host placeholder, or
		// is for a router we haven't received an LSA from yet
		// so we have no dag to send the table to
		return 1;

	} else {
		// If destHID is not SID, send to relevant router
		Node fad(_myAD);
		Node fhid(_myHID);
		Node tad(_myAD);
		Node thid(nodeState->hid);

		Xroute::XrouteMsg msg;
		Xroute::TableUpdateMsg *t    = msg  .mutable_table_update();
		Xroute::Node           *from = t   ->mutable_from();
		Xroute::Node           *to   = t   ->mutable_to();
		Xroute::XID            *fa   = from->mutable_ad();
		Xroute::XID            *fh   = from->mutable_hid();
		Xroute::XID            *ta   = to  ->mutable_ad();
		Xroute::XID            *th   = to  ->mutable_hid();

		msg.set_type(Xroute::TABLE_UPDATE_MSG);
		msg.set_version(Xroute::XROUTE_PROTO_VERSION);
		fa ->set_type(fad.type());
		fa ->set_id(fad.id(), XID_SIZE);
		fh ->set_type(fhid.type());
		fh ->set_id(fhid.id(), XID_SIZE);
		ta ->set_type(tad.type());
		ta ->set_id(tad.id(), XID_SIZE);
		th ->set_type(thid.type());
		th ->set_id(thid.id(), XID_SIZE);

		map<string, RouteEntry>::iterator it;
		for (it = routingTable.begin(); it != routingTable.end(); it++)
		{
			Xroute::TableEntry *e = t->add_routes();
			Node dest(it->second.dest);
			Node nexthop(it->second.nextHop);
			Xroute::XID *x = e->mutable_xid();

			x->set_type(dest.type());
			x->set_id(dest.id(), XID_SIZE);

			x = e->mutable_next_hop();
			x->set_type(nexthop.type());
			x->set_id(nexthop.id(), XID_SIZE);

			e->set_interface(it->second.port);
			e->set_flags(it->second.flags);
		}

		char ss[2048];
		xia_ntop(AF_XIA, &nodeState->dag, ss, sizeof(ss));

		return sendMessage(&nodeState->dag, msg);
	}
}


int Controller::processInterdomainLSA(const Xroute::XrouteMsg& xmsg)
{
	Xroute::GlobalLSAMsg msg = xmsg.global_lsa();
	NodeStateEntry entry;

	Xroute::XID xad  = msg.from().ad();
	Xroute::XID xhid = msg.from().hid();
	//Xroute::XID xsid = msg.node().sid();

	entry.ad  = Node(xad.type(),  xad.id().c_str(),  0).to_string();
	entry.hid = Node(xhid.type(), xhid.id().c_str(), 0).to_string();
	//string srcSID = Node(xsid.type(), xsid.id().c_str(), 0).to_string();

	// First, filter out the LSA originating from myself
	if (entry.ad == _myAD) {
		return 1;
	}

	// See if this LSA comes from AD with dualRouter
	if (msg.flags() & F_IP_GATEWAY) {
		_dual_router_AD = entry.ad;
	}

	//syslog(LOG_INFO, "inter-AD LSA from %s, %d neighbors", entry.ad.c_str(), numNeighbors);
	entry.timestamp = time(NULL);

	for (int i = 0; i < msg.neighbors_size(); i++) {
		NeighborEntry neighbor;

		Xroute::NeighborEntry n = msg.neighbors(i);

		xad  = n.ad();
		xhid = n.hid();

		neighbor.AD  = Node(xad.type(),  xad.id().c_str(),  0).to_string();
		neighbor.HID = Node(xhid.type(), xhid.id().c_str(), 0).to_string();

		neighbor.port = n.port();
		neighbor.cost = n.cost();

		//syslog(LOG_INFO, "neighbor[%d] = %s", i, neighbor.AD.c_str());

		entry.neighbor_list.push_back(neighbor);
	}

	_ADNetworkTable[entry.ad] = entry;

	// Rebroadcast this LSA
	int rc = 1;
	std::map<std::string, NeighborEntry>::iterator it;
	for (it = _ADNeighborTable.begin(); it != _ADNeighborTable.end(); it++) {
		sockaddr_x ddag;
		Graph g = Node() * Node(it->second.AD) * Node(_controller_sid);
		g.fill_sockaddr(&ddag);

		int temprc = sendMessage(&ddag, xmsg);
		rc = (temprc < rc)? temprc : rc;
	}
	return rc;
}


int Controller::processHostRegister(const Xroute::HostJoinMsg& msg)
{
	int rc;
	uint32_t flags;

	if (msg.has_flags()) {
		flags = msg.flags();
	} else {
		flags = F_HOST;
	}

	NeighborEntry neighbor;
	neighbor.AD = _myAD;
	neighbor.HID = msg.hid();
	neighbor.port = msg.interface();
	neighbor.cost = 1; // for now, same cost
	neighbor.flags = flags;

	// Add host to neighbor table so info can be sent to controller
	_neighborTable[neighbor.HID] = neighbor;

	//  update my entry in the networkTable
	NodeStateEntry entry;
	entry.hid = _myHID;
	entry.ad = _myAD;

	// fill my neighbors into my entry in the networkTable
	std::map<std::string, NeighborEntry>::iterator it;
	for (it = _neighborTable.begin(); it != _neighborTable.end(); it++) {
		entry.neighbor_list.push_back(it->second);
	}

	_networkTable[_myHID] = entry;

	// update the host entry in (click-side) HID table
	//syslog(LOG_INFO, "Routing table entry: interface=%d, host=%s\n", msg.interface(), hid.c_str());
	if ((rc = _xr.setRoute(neighbor.HID, neighbor.port, neighbor.HID, flags)) != 0) {
		syslog(LOG_ERR, "unable to set host route: %s (%d)", neighbor.HID.c_str(), rc);
	}

	// FIXME: handle timeouts
//	_hello_timeStamp[neighbor.HID] = time(NULL);

	return 1;
}


int Controller::processHello(const Xroute::HelloMsg &msg, uint32_t iface)
{
	string neighborAD, neighborHID, neighborSID;
	uint32_t flags = F_HOST;

	Xroute::XID xad  = msg.node().ad();
	Xroute::XID xhid = msg.node().hid();

	Node  ad(xad.type(),  xad.id().c_str(), 0);
	Node hid(xhid.type(), xhid.id().c_str(), 0);

	neighborAD  = ad. to_string();
	neighborHID = hid.to_string();

	if (msg.has_flags()) {
		flags = msg.flags();
	}

	// Update neighbor table
	NeighborEntry neighbor;
	neighbor.AD        = neighborAD;
	neighbor.HID       = neighborHID;
	neighbor.port      = iface;
	neighbor.flags     = flags;
	neighbor.cost      = 1; // for now, same cost
	neighbor.timestamp = time(NULL);

	// Index by HID if neighbor in same domain or by AD otherwise
	bool internal = (neighbor.AD == _myAD);
	_neighborTable[internal ? neighbor.HID : neighbor.AD] = neighbor;

	// Update network table
	NodeStateEntry entry;
	entry.hid = _myHID;
	entry.ad = _myAD;

	// Add neighbors to network table entry
	std::map<std::string, NeighborEntry>::iterator it;
	for (it = _neighborTable.begin(); it != _neighborTable.end(); it++) {
		entry.neighbor_list.push_back(it->second);
	}

	_networkTable[_myHID] = entry;
	//syslog(LOG_INFO, "Process-Hello[%s]", neighbor.HID.c_str());

	return 1;
}


int Controller::processRoutingTable(std::map<std::string, RouteEntry> routingTable)
{
	int rc;
	map<string, RouteEntry>::iterator it;
	for (it = routingTable.begin(); it != routingTable.end(); it++)
	{
		// TODO check for all published SIDs
		// TODO do this for xrouted as well
		// Ignore SIDs that we publish
		if (it->second.dest == _controller_sid) {
			continue;
		}

		if ((rc = _xr.setRoute(it->second.dest, it->second.port, it->second.nextHop, it->second.flags)) != 0)
			syslog(LOG_ERR, "error setting route %d", rc);

		_timeStamp[it->second.dest] = time(NULL);
	}

	return 1;
}


int Controller::processLSA(const Xroute::LSAMsg& msg)
{
	Xroute::XID a = msg.node().ad();
	Xroute::XID h = msg.node().hid();

	string srcAD  = Node(a.type(), a.id().c_str(), 0).to_string();
	string srcHID = Node(h.type(), h.id().c_str(), 0).to_string();

	if (msg.has_flags() && msg.flags() & F_IP_GATEWAY) {
		_dual_router_AD = srcAD;
	}

	if (srcHID == _myHID) {
		return 1;
	}

	uint32_t numNeighbors = msg.peers_size();

	// Update the network table
	NodeStateEntry entry;
	entry.ad  = srcAD;
	entry.hid = srcHID;
	bzero(&entry.dag, sizeof(sockaddr_x));
	memcpy(&entry.dag, msg.dag().c_str(), msg.dag().length());

	for (uint32_t i = 0; i < numNeighbors; i++) {
		NeighborEntry neighbor;
		Xroute::NeighborEntry n = msg.peers(i);

		a = n.ad();
		h = n.hid();
		neighbor.AD   = Node(a.type(), a.id().c_str(), 0).to_string();
		neighbor.HID  = Node(h.type(), h.id().c_str(), 0).to_string();
		neighbor.port = n.port();
		neighbor.cost = n.cost();

		if (neighbor.AD != _myAD) { // update neighbors
			neighbor.timestamp = time(NULL);
			_ADNeighborTable[neighbor.AD] = neighbor;
			_ADNeighborTable[neighbor.AD].HID = neighbor.AD; // make the algorithm work
		}

		entry.neighbor_list.push_back(neighbor);
	}
	extractNeighborADs();
	_networkTable[srcHID] = entry;
	_calc_dijstra_ticks++;

	if (_calc_dijstra_ticks >= _settings->calc_dijkstra_interval() || _calc_dijstra_ticks  < 0) {
		//syslog(LOG_DEBUG, "Calcuating shortest paths\n");

		// Calculate next hop for ADs
		std::map<std::string, RouteEntry> ADRoutingTable;
		populateRoutingTable(_myAD, _ADNetworkTable, ADRoutingTable);

		// For debugging.
		// printADNetworkTable();
		// printRoutingTable(_myAD, ADRoutingTable);

		// Calculate next hop for routers
		std::map<std::string, NodeStateEntry>::iterator it1;
		// Iterate through ADs
		for (it1 = _networkTable.begin(); it1 != _networkTable.end(); ++it1)
		{
			if ((it1->second.ad != _myAD) || (it1->second.hid == "")) {
				// Don't calculate routes for external ADs
				continue;
			} else if (it1->second.hid.find(string("SID")) != string::npos) {
				// Don't calculate routes for SIDs
				continue;
			}
			std::map<std::string, RouteEntry> routingTable;

			// Calculate routing table for HIDs instead
			populateRoutingTable(it1->second.hid, _networkTable, routingTable);

			//extractNeighborADs(routingTable);
			populateNeighboringADBorderRouterEntries(it1->second.hid, routingTable);
			populateADEntries(routingTable, ADRoutingTable);
			//printRoutingTable(it1->second.hid, routingTable);

			sendRoutingTable(&it1->second, routingTable);
		}

		// HACK HACK HACK!!!!
		// for some reason some controllers will delete their routing table entries in
		// populateRoutingTable when they shouldn't. This forces the entries back into the table
		// it's the same logic from inside the loop above
		std::map<std::string, RouteEntry> routingTable;
		populateRoutingTable(_myHID, _networkTable, routingTable);
		if (routingTable.size() == 0) {
			return 1;
		}

		populateNeighboringADBorderRouterEntries(_myHID, routingTable);
		populateADEntries(routingTable, ADRoutingTable);
		processRoutingTable(routingTable);
		// END HACK

		_calc_dijstra_ticks = _calc_dijstra_ticks >0?0:_calc_dijstra_ticks;
	}

	return 1;
}


// Extract neighboring AD from the routing table
int Controller::extractNeighborADs(void)
{
	// Update network table

// FIXME: should these both be AD?????
	NodeStateEntry entry;
	entry.ad = _myAD;
	entry.hid = _myAD;
	entry.timestamp = time(NULL);

	// Add neighbors to network table entry
	std::map<std::string, NeighborEntry>::iterator it1;
	for (it1 = _ADNeighborTable.begin(); it1 != _ADNeighborTable.end(); ++it1)
		entry.neighbor_list.push_back(it1->second);

	_ADNetworkTable[_myAD] = entry;
	return 1;
}


void Controller::populateNeighboringADBorderRouterEntries(string currHID, std::map<std::string, RouteEntry> &routingTable)
{
	vector<NeighborEntry> currNeighborTable = _networkTable[currHID].neighbor_list;

	vector<NeighborEntry>::iterator it;
	for (it = currNeighborTable.begin(); it != currNeighborTable.end(); ++it) {
		if (it->AD != _myAD) {
			// Add HID of border routers of neighboring ADs into routing table
			string neighborHID = it->HID;
			RouteEntry &entry = routingTable[neighborHID];
			entry.dest = neighborHID;
			entry.nextHop = neighborHID;
			entry.port = it->port;
			//entry.flags = 0;
		}
	}
}


void Controller::populateADEntries(std::map<std::string, RouteEntry> &routingTable, std::map<std::string, RouteEntry> ADRoutingTable)
{
	std::map<std::string, RouteEntry>::iterator it1;  // Iter for route table

	for (it1 = ADRoutingTable.begin(); it1 != ADRoutingTable.end(); it1++) {
		string destAD = it1->second.dest;
		string nextHopAD = it1->second.nextHop;

		RouteEntry &entry = routingTable[destAD];
		entry.dest = destAD;
		entry.nextHop = routingTable[nextHopAD].nextHop;
		entry.port = routingTable[nextHopAD].port;
		entry.flags = routingTable[nextHopAD].flags;
	}
}


// Run Dijkstra shortest path algorithm, and populate the next hops.
// This code is hacky to support AD and HID. This can be rewritten better.
void Controller::populateRoutingTable(std::string srcHID, std::map<std::string, NodeStateEntry> &networkTable, std::map<std::string, RouteEntry> &routingTable)
{
	std::map<std::string, NodeStateEntry>::iterator it1;  // Iter for network table
	std::vector<NeighborEntry>::iterator it2;             // Iter for neighbor list

	map<std::string, NodeStateEntry> unvisited;  // Set of unvisited nodes

	routingTable.clear();

	// Filter out anomalies
	//@ (When do these appear? Should they not be introduced in the first place? How about SIDs?)
	it1 = networkTable.begin();
	while (it1 != networkTable.end()) {

		if (it1->second.neighbor_list.size() == 0 || it1->second.ad.empty() || it1->second.hid.empty()) {
			networkTable.erase(it1++);
		} else {
			//syslog(LOG_DEBUG, "entry %s: neighbors: %d", it1->first.c_str(), it1->second.neighbor_list.size());
			++it1;
		}
	}

	unvisited = networkTable;

	// Initialize Dijkstra variables for all nodes
	for (it1=networkTable.begin(); it1 != networkTable.end(); it1++) {
		it1->second.checked = false;
		it1->second.cost = 10000000;
	}

	string currXID;

	// Visit root node (srcHID)
	unvisited.erase(srcHID);
	networkTable[srcHID].checked = true;
	networkTable[srcHID].cost = 0;

	// loop through the neighbor table of the source node
	for (it2 = networkTable[srcHID].neighbor_list.begin(); it2 < networkTable[srcHID].neighbor_list.end(); it2++) {
		currXID = (it2->AD == _myAD) ? it2->HID : it2->AD;

		if (networkTable.find(currXID) != networkTable.end()) {
			// there is an entry for this neighbor in the network table already
			// just update the cost to get there and set previous node to the one we are currently doing neighbors for
			// FIXME: variable names are confusing here
			// cost in the neighbor table is actually the link's cost which by default is 1
			//  not the distance to that node from here which goes into the final cost.
			networkTable[currXID].cost = it2->cost;
			networkTable[currXID].prevNode = srcHID;

		} else {
			// We have an endhost or a router we haven't seen an LSA from yet
			// make an entry for it in the network table and add a route to the source node to it

			// create a neighbor entry for the source node
			NeighborEntry neighbor;
			neighbor.AD = _myAD;
			neighbor.HID = srcHID;
			neighbor.port = it2->port;
			neighbor.cost = 1;

			// create a network table entry for the new node
			NodeStateEntry entry;
			entry.ad = it2->AD;
			entry.hid = it2->HID;
			entry.neighbor_list.push_back(neighbor);
			entry.cost = neighbor.cost;
			entry.prevNode = neighbor.HID;
			bzero(&entry.dag, sizeof(sockaddr_x));

			networkTable[currXID] = entry;
		}
	}

	// Loop until all nodes have been visited
	while (!unvisited.empty()) {
		int minCost = 10000000;
		string selectedHID;

		// Select unvisited node with min cost
		for (it1 = unvisited.begin(); it1 != unvisited.end(); ++it1) {
			currXID = (it1->second.ad == _myAD) ? it1->second.hid : it1->second.ad;

			if (networkTable[currXID].cost < minCost) {
				minCost = networkTable[currXID].cost;
				selectedHID = currXID;
			}
		}
		if(selectedHID.empty()) {
			// Rest of the nodes cannot be reached from the visited set
			syslog(LOG_INFO, "%s has an empty routingTable", srcHID.c_str());
			break;
		}

		// Remove selected node from unvisited set
		unvisited.erase(selectedHID);
		networkTable[selectedHID].checked = true;

		// Process all unvisited neighbors of selected node
		for (it2 = networkTable[selectedHID].neighbor_list.begin(); it2 != networkTable[selectedHID].neighbor_list.end(); it2++) {
			currXID = (it2->AD == _myAD) ? it2->HID : it2->AD;
			if (networkTable[currXID].checked != true) {
				if (networkTable[currXID].cost > networkTable[selectedHID].cost + 1) {
					//@ Why add 1 to cost instead of using link cost from neighbor_list?
					networkTable[currXID].cost = networkTable[selectedHID].cost + 1;
					networkTable[currXID].prevNode = selectedHID;
				}
			}
		}
	}

	// For each destination ID, find the next hop ID and port by going backwards along the Dijkstra graph
	string tempHID1;			// ID of destination in srcHID's routing table
	string tempHID2;			// ID of node currently being processed
	string tempNextHopHID2;		// HID of next hop to reach destID from srcHID
	int hop_count;

	for (it1 = networkTable.begin(); it1 != networkTable.end(); it1++) {

		// FIXME: this could also just check the checked flag
		if (unvisited.find(it1->first) !=  unvisited.end()) { // the unreachable set
			continue;
		}

		tempHID1 = (it1->second.ad == _myAD) ? it1->second.hid : it1->second.ad;
		if (tempHID1.find(string("SID")) != string::npos) {
			// Skip SIDs on first pass
			continue;
		}
		if (srcHID.compare(tempHID1) != 0) {
			tempHID2 = tempHID1;
			tempNextHopHID2 = it1->second.hid;
			hop_count = 0;
			while (networkTable[tempHID2].prevNode.compare(srcHID)!=0 && hop_count < _settings->max_hop_count()) {
				tempHID2 = networkTable[tempHID2].prevNode;
				tempNextHopHID2 = networkTable[tempHID2].hid;
				hop_count++;
			}
			if (hop_count < _settings->max_hop_count()) {
				routingTable[tempHID1].dest = tempHID1;
				routingTable[tempHID1].nextHop = tempNextHopHID2;
				routingTable[tempHID1].flags = 0;

				// Find port of next hop
				for (it2 = networkTable[srcHID].neighbor_list.begin(); it2 < networkTable[srcHID].neighbor_list.end(); it2++) {
					if (((it2->AD == _myAD) ? it2->HID : it2->AD) == tempHID2) {
						routingTable[tempHID1].port = it2->port;
					}
				}
			}
		}
	}

	for (it1 = networkTable.begin(); it1 != networkTable.end(); it1++) {
		tempHID1 = (it1->second.ad == _myAD) ? it1->second.hid : it1->second.ad;
		if (unvisited.find(it1->first) !=  unvisited.end()) { // the unreachable set
			continue;
		}
		if (tempHID1.find(string("SID")) == string::npos) {
			// Process SIDs on second pass
			continue;
		}
		if (srcHID.compare(tempHID1) != 0) {

			tempHID2 = tempHID1;
			tempNextHopHID2 = it1->second.hid;
			hop_count = 0;
			while (networkTable[tempHID2].prevNode.compare(srcHID)!=0 && hop_count < _settings->max_hop_count()) {
				tempHID2 = networkTable[tempHID2].prevNode;
				tempNextHopHID2 = networkTable[tempHID2].hid;
				hop_count++;
			}
			if (hop_count < _settings->max_hop_count()) {
				routingTable[tempHID1].dest = tempHID1;

				// Find port of next hop
				for (it2 = networkTable[srcHID].neighbor_list.begin(); it2 < networkTable[srcHID].neighbor_list.end(); it2++) {
					if (((it2->AD == _myAD) ? it2->HID : it2->AD) == tempHID2) {
						routingTable[tempHID1].port = it2->port;
					}
				}

				// Dest is SID, so we search existing ports for entry with same port and HID as next hop
				bool entryFound = false;
				map<string, RouteEntry>::iterator it3;
				for (it3 = routingTable.begin(); it3 != routingTable.end(); it3++) {
					if (it3->second.port == routingTable[tempHID1].port && it3->second.nextHop.find(string("HID")) != string::npos) {
						routingTable[tempHID1].nextHop = it3->second.nextHop;
						routingTable[tempHID1].flags = 0;
						entryFound = true;
						break;
					}
				}
				if (!entryFound) {
					// Delete SID entry from routingTable

					routingTable.erase(tempHID1);
				}
			}
		}
	}
	//printRoutingTable(srcHID, routingTable);
}


void Controller::printRoutingTable(std::string srcHID, std::map<std::string, RouteEntry> &routingTable)
{
	syslog(LOG_INFO, "Routing table for %s", srcHID.c_str());
	map<std::string, RouteEntry>::iterator it1;
	for ( it1=routingTable.begin() ; it1 != routingTable.end(); it1++ ) {
		syslog(LOG_INFO, "Dest=%s, NextHop=%s, Port=%d, Flags=%u", (it1->second.dest).c_str(), (it1->second.nextHop).c_str(), (it1->second.port), (it1->second.flags) );
	}
}


void Controller::printADNetworkTable()
{
	syslog(LOG_INFO, "Network table for %s:", _myAD.c_str());
	std::map<std::string, NodeStateEntry>::iterator it;
	for (it = _ADNetworkTable.begin();
			it != _ADNetworkTable.end(); it++) {
		syslog(LOG_INFO, "%s", it->first.c_str());
		for (size_t i = 0; i < it->second.neighbor_list.size(); i++) {
			syslog(LOG_INFO, "neighbor[%d]: %s", (int) i,
					it->second.neighbor_list[i].AD.c_str());
		}
	}

}


int Controller::processMsg(std::string msg_str, uint32_t iface)
{
	int rc = 0;
	Xroute::XrouteMsg msg;

	try {
		if (!msg.ParseFromString(msg_str)) {
			syslog(LOG_WARNING, "illegal packet received");
			return -1;
		} else if (msg.version() != Xroute::XROUTE_PROTO_VERSION) {
			syslog(LOG_WARNING, "invalid version # received");
			return -1;
		}

	} catch (std::exception e) {
		syslog(LOG_INFO, "invalid router message received\n");
		return 0;
	}

	switch (msg.type()) {
		case Xroute::HELLO_MSG:
			// do we still need this in the controller?
			rc = processHello(msg.hello(), iface);
			break;

		case Xroute::LSA_MSG:
			rc = processLSA(msg.lsa());
			break;

		case Xroute::GLOBAL_LSA_MSG:
			rc = processInterdomainLSA(msg);
			break;

		case Xroute::HOST_JOIN_MSG:
			rc = processHostRegister(msg.host_join());
			break;

		case Xroute::HOST_LEAVE_MSG:
			break;

		default:
			syslog(LOG_INFO, "controller received an unknown message type");
			break;
	}

	return rc;
}
