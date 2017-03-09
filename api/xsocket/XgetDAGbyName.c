/* ts=4 */
/*
** Copyright 2011 Carnegie Mellon University
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**	http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/
/*!
 @file XgetDAGbyName.c
 @brief XgetDAGbyName(), XgetNamebyDAG(), XregisterName(), Xgetpeername(),
  Xgetsockname(), xia_ntop(), xia_pton() - network address management
*/

#include "Xsocket.h"
/*! \cond */
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include "Xinit.h"
#include "Xutil.h"
#include "xns.h"
#include "dagaddr.hpp"

#define ETC_HOSTS "/etc/hosts.xia"
#define MAX_SEND_RETRIES 5

#define MAX_RV_DAG_SIZE 1024
#define MAX_XID_STR_SIZE 64
/*! \endcond */



/*!
** @brief convert a DAG from binary to text form
**
** This  function  converts the network address structure src in the
** AF_XIA address family into a character string. The resulting string
** is copied to the buffer pointed to by dst, which must be a non-null
** pointer. The caller specifies the number of bytes available in this
** buffer in the argument size.
**
** The returned text is formatted in the DAG text string format.
**
** @param af family (must be AF_XIA)
** @param src DAG to convert
** @param dst buffer to hold the converted address
** @param size length of dst
**
** @returns non-null pointer to dst on success
** @returns NULL with errno set on failure.
*/
const char *xia_ntop(int af, const sockaddr_x *src, char *dst, socklen_t size)
{
	if (af != AF_XIA) {
		errno = EAFNOSUPPORT;
		return NULL;
	}

	if (src == NULL || dst == NULL) {
		errno = EFAULT;
		return NULL;
	}

	Graph g(src);

	if (g.dag_string().size() >= size) {
		errno = ENOSPC;
		return NULL;
	}
	strncpy(dst, g.dag_string().c_str(), size);

	return dst;
}

/*!
** @brief convert a DAG from binary to text form
**
** This function converts the character string src into an
** XIA network address structure, then copies the network
** address structure to dst.
**
** @param af family (must be AF_XIA)
** @param src text representation of the DAG to convert. Can be, DAG, RE, or HTTP formatted
** @param dst destination
**
** @returns 1 on success (network address was successfully converted)
** @returns 0 if src does not contain a character string representing a valid network address
** @returns -1 with errno set to EAFNOSUPPORT If af is not AF_XIA
*/
int xia_pton(int af, const char *src, sockaddr_x *dst)
{
	if (af != AF_XIA) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	if (dst == NULL) {
		errno = EFAULT;
		return -1;
	}

	try {
		Graph g(src);
		g.fill_sockaddr(dst);
		return 1;

	} catch (std::exception e) {
		return 0;
	}
}


/*!
** @brief Send data to a host and wait for a response to be ready
**
** @param sock socket to send data on
** @param buf buffer containing data to be sent
** @param len length of the data to be sent
** @param destaddr destination DAG to send data to
** @param timeout in seconds
** @param msgtype type of nameserver message
**
** @returns 0 if data is available on socket to read before timeout
** @returns -1 on failure. NOTE: Closes sock.
*/

static int _send_and_wait(int sock, const char *buf, size_t len,
		const sockaddr *destaddr, unsigned int timeout) {

	int rc;
	int retval = -1;
	fd_set fds;
	struct timeval tv;
	int retries = MAX_SEND_RETRIES;

	for (;retries > 0; retries--) {

		// Send packet to the destination
		Graph gns((const sockaddr_x *)destaddr);
		rc = Xsendto(sock, buf, len, 0, destaddr, sizeof(sockaddr_x));
		if (rc < 0 ) {
			int err = errno;
			Graph g((sockaddr_x *)destaddr);
			LOGF("Error sending message to %s (%d)", g.dag_string().c_str(), rc);
			Xclose(sock);
			errno = err;
			return -1;
		}

		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		tv.tv_sec = timeout;
		tv.tv_usec = 0;

		// Wait for a response packet
		rc = Xselect(sock + 1, &fds, NULL, NULL, &tv);
		if (rc < 0) {
			LOG("Error waiting for response to sent packet");
			return -1;
		}
		if (rc == 0) {
			LOG("Timed out waiting for response.");
			if (retries > 1) {
				LOG("Will retry by sending packet again");
			}
			continue;
		}

		// This should never happen!
		if (!FD_ISSET (sock, &fds)) {
			LOG("No response, when a response was expected");
			return -1;
		}

		// A response is ready to be read
		retval = 0;
		break;
	}

	// 0 on success, -1 on exhausting all retries.
	return retval;
}

/*!
** @brief Lookup a DAG in the hosts.xia file
**
** @param name The name of an XIA service or host.
**
** @returns a character point to the dag on success
** @returns NULL on failure
**
*/
static char *hostsLookup(const char *name) {
	char line[512];
	char *linend;
	char *dag;
	char _dag[NS_MAX_DAG_LENGTH];

	// look for an hosts_xia file locally
	char buf[BUF_SIZE];
	FILE *hostsfp = fopen(strcat(XrootDir(buf, BUF_SIZE), ETC_HOSTS), "r");
	int answer_found = 0;
	if (hostsfp != NULL) {
		while (fgets(line, 511, hostsfp) != NULL) {
			linend = line+strlen(line)-1;
			while (*linend == '\r' || *linend == '\n' || *linend == '\0') {
				linend--;
			}
			*(linend+1) = '\0';
			if (line[0] == '#') {
				continue;
			} else if (!strncmp(line, name, strlen(name))
						&& line[strlen(name)] == ' ') {
				strncpy(_dag, line+strlen(name)+1, strlen(line)-strlen(name)-1);
				_dag[strlen(line)-strlen(name)-1] = '\0';
				answer_found = 1;
			}
		}
		fclose(hostsfp);
		if (answer_found) {
			dag = (char*)malloc(sizeof(_dag) + 1);
			strcpy(dag, _dag);
			return dag;
		}
	} else {
		//printf("XIAResolver file error\n");
	}

	//printf("Name not found in ./hosts_xia\n");
	return NULL;
}



static int _nsquery(char *name, int namelen, sockaddr_x *addr, socklen_t *addrlen, char type, char flags)
{
	int sock;
	int err;
	int rc;
	int result;
	sockaddr_x ns_dag;
	char pkt[NS_MAX_PACKET_SIZE];
	char *addrstr = NULL;

	if ((sock = Xsocket(AF_XIA, SOCK_DGRAM, 0)) < 0) {
		return -1;
	}

	//Read the nameserver DAG (the one that the name-query will be sent to)
	if ( XreadNameServerDAG(sock, &ns_dag) < 0 ) {
		LOG("Unable to find nameserver address");
		errno = NO_RECOVERY;
		return -1;
	}

	//Construct a name-query packet
	ns_pkt query_pkt;

	bzero(&query_pkt, sizeof(query_pkt));
	query_pkt.type = type;
	query_pkt.flags = flags;

	if (type == NS_TYPE_QUERY) {
		query_pkt.name = name;

	} else if (type == NS_TYPE_RQUERY) {
		Graph g(addr);
		char *addrstr = strdup(g.dag_string().c_str());

		if (addrstr == NULL) {
			LOG("Unable to allocate memory to store DAG");
			errno = NO_RECOVERY;
			return -1;
		}
		query_pkt.dag = addrstr;

	} else {
		// this better not happen!
		LOGF("invalid flag 0x%08x", flags);
		errno = NO_RECOVERY;
		return -1;
	}

	int len = make_ns_packet(&query_pkt, pkt, sizeof(pkt));

	//Send a name query to the name server
	if(_send_and_wait(sock, pkt, len, (const struct sockaddr *)&ns_dag, 1)) {
		LOG("Error sending name query");
		return -1;
	}

	//Check the response from the name server
	memset(pkt, 0, sizeof(pkt));
	if ((rc = Xrecvfrom(sock, pkt, NS_MAX_PACKET_SIZE, 0, NULL, NULL)) < 0) {
		int err = errno;
		LOGF("Error retrieving name query (%d)", rc);
		Xclose(sock);
		errno = err;
		return -1;
	}

	ns_pkt resp_pkt;
	get_ns_packet(pkt, rc, &resp_pkt);

	err = 0;

	if (resp_pkt.type == NS_TYPE_RESPONSE_ERROR) {
		// same error regardless of type
		err = HOST_NOT_FOUND;
		result = -1;

	} else if (type == NS_TYPE_QUERY && resp_pkt.type == NS_TYPE_RESPONSE_QUERY) {
		// forward lookup result
		Graph g(resp_pkt.dag);
		g.fill_sockaddr(addr);
		*addrlen = sizeof(sockaddr_x);
		result = 0;

	} else if (type == NS_TYPE_RQUERY && resp_pkt.type == NS_TYPE_RESPONSE_RQUERY) {
		// reverse lookup result
		bzero(name, namelen);
		strncpy(name, resp_pkt.name, namelen-1);
		result = 0;

	} else {
		// this shouldn't happen!
		err = NO_RECOVERY;
		result = -1;
	}

	Xclose(sock);

	if (addrstr) {
		free(addrstr);
	}

	errno = err;
	return result;
}




int _rquery(char *name, int namelen, const sockaddr_x *addr, char flags)
{
	socklen_t addrlen = sizeof(sockaddr_x);

	if (addr == NULL || name == NULL || namelen == 0) {
		errno = EINVAL;
		return -1;
	}

	return _nsquery(name, namelen, (sockaddr_x *)addr, &addrlen, NS_TYPE_RQUERY, flags);
}


int _fquery(const char *name, sockaddr_x *addr, socklen_t *addrlen, char flags)
{
	char *dag;

	if (addr == NULL || addrlen == NULL || *addrlen < sizeof(sockaddr_x) || name == NULL) {
		errno = EINVAL;
		return -1;
	}

	// see if name is registered in the local hosts.xia file
	if((dag = hostsLookup(name))) {
		Graph g(dag);
		free(dag);

		// check to see if the returned dag was valid
		// we may want a better check for this in the future
		if (g.num_nodes() > 0) {
			std::string s = g.dag_string();
			g.fill_sockaddr((sockaddr_x*)addr);
			*addrlen = sizeof(sockaddr_x);
			return 0;
		}
	}

	return _nsquery((char *)name, strlen(name), addr, addrlen, NS_TYPE_QUERY, flags);
}



/*!
** @brief reverse lookup, find a name based on the specified network address
**
** Performs a reverse name lookup to find the name associated with addr.
**
** The local hosts.xia file is checked first and if name is not found,
** a query is sent to the nameserver.
**
** @param name pointer to menory that will contain the returned name
** @param namlen the size of name
** @param addr the network address to lookup
**
** @returns 0 with name filled in with a null terminted string. If name
** is not long enough, the returned name will be truncated.
** @returns -1 on failure with errno set appropraitely
**
*/
int XgetNamebyDAG(char *name, int namelen, const sockaddr_x *addr)
{
	return _rquery(name, namelen, addr, 0);
}

int XgetHostIDbyDAG(char *name, int namelen, const sockaddr_x *addr)
{
	return _rquery(name, namelen, addr, NS_FLAGS_HOST_MAP);
}


int XgetAddrIDbyDAG(char *name, int namelen, const sockaddr_x *addr)
{
	return _rquery(name, namelen, addr, NS_FLAGS_ADDR_MAP);
}


/*!
** @brief lookup a DAG using a host or service name
**
** Lookup the DAG associated with name.
**
** The local hosts.xia file is checked first and if addr is not found,
** a query is sent to the nameserver.
**
** @note Xgetaddrinfo should be used rather than this function as it is
** very primative.
**
** @param name a test string representing the name of an XIA service or host
** @param addr a sockaddr_x to received the address
** @param addrlen pointer to the length of addr on call, contains actual
** length on return
**
** @returns 0 with addr filled in and addrlen specifying the length of addr
** @returns NULL on failure with errno set appropriately
**
*/
int XgetDAGbyName(const char *name, sockaddr_x *addr, socklen_t *addrlen)
{
	return _fquery(name, addr, addrlen, 0);
}


int XgetDAGbyHostID(const char *name, sockaddr_x *addr, socklen_t *addrlen)
{
	return _fquery(name, addr, addrlen, NS_FLAGS_HOST_MAP);
}


int XgetDAGbyAddrID(const char *name, sockaddr_x *addr, socklen_t *addrlen)
{
	return _fquery(name, addr, addrlen, NS_FLAGS_ADDR_MAP);
}


int XgetDAGbyAnycastName(const char *name, sockaddr_x *addr, socklen_t *addrlen){
	int sock;
	int rc;
	int result;
	sockaddr_x ns_dag;
	char pkt[NS_MAX_PACKET_SIZE];

	if (!name || *name == 0) {
		errno = EINVAL;
		return -1;
	}

	if (!addr || !addrlen || *addrlen < sizeof(sockaddr_x)) {
		errno = EINVAL;
		return -1;
	}

	if (!strncmp(name, "RE ", 3) || !strncmp(name, "DAG ", 4)) {

		// check to see if name is actually a dag to begin with
		Graph gcheck(name);

		// check to see if the returned dag was valid
		// we may want a better check for this in the future
		if (gcheck.num_nodes() > 0) {
			std::string s = gcheck.dag_string();
			gcheck.fill_sockaddr((sockaddr_x*)addr);
			*addrlen = sizeof(sockaddr_x);
			return 0;
		}
	}

	// not found locally, check the name server
	if ((sock = Xsocket(AF_XIA, SOCK_DGRAM, 0)) < 0)
		return -1;

	//Read the nameserver DAG (the one that the name-query will be sent to)
	if ( XreadNameServerDAG(sock, &ns_dag) < 0 ) {
		LOG("Unable to find nameserver address");
		errno = NO_RECOVERY;
		return -1;
	}

	//Construct a name-query packet
	ns_pkt query_pkt;
	query_pkt.type = NS_TYPE_ANYCAST_QUERY;
	query_pkt.flags = 0;
	query_pkt.name = name;
	query_pkt.dag = NULL;
	int len = make_ns_packet(&query_pkt, pkt, sizeof(pkt));

	//Send a name query to the name server
	if(_send_and_wait(sock, pkt, len, (const struct sockaddr *)&ns_dag, 1)) {
		LOG("Error sending anycast name query");
		return -1;
	}

	//Check the response from the name server
	memset(pkt, 0, sizeof(pkt));
	if ((rc = Xrecvfrom(sock, pkt, NS_MAX_PACKET_SIZE, 0, NULL, NULL)) < 0) {
		int err = errno;
		LOGF("Error retrieving anycast name query (%d)", rc);
		Xclose(sock);
		errno = err;
		return -1;
	}

	ns_pkt resp_pkt;
	get_ns_packet(pkt, rc, &resp_pkt);

	switch (resp_pkt.type) {
	case NS_TYPE_ANYCAST_RESPONSE_QUERY:
		result = 1;
		break;
	case NS_TYPE_ANYCAST_RESPONSE_ERROR:
		result = -1;
		break;
	default:
		LOG("Unknown nameserver response");
		result = -1;
		break;
	}
	Xclose(sock);

	if (result < 0) {
		return result;
	}

	Graph g(resp_pkt.dag);
	g.fill_sockaddr(addr);
	*addrlen = sizeof(sockaddr_x);
	return 0;
}


int XrendezvousUpdate(const char *hidstr, sockaddr_x *DAG)
{
	// Find the rendezvous service control address
	char rvControlDAG[MAX_RV_DAG_SIZE];
	if(XreadRVServerControlAddr(rvControlDAG, MAX_RV_DAG_SIZE)) {
		syslog(LOG_INFO, "No RV control address. Skipping update");
		return 1;
	}
	Graph rvg(rvControlDAG);
	sockaddr_x rv_dag;
	rvg.fill_sockaddr(&rv_dag);

	// Validate arguments
	if(!DAG) {
		syslog(LOG_ERR, "NULL DAG for rendezvous update");
		return -1;
	}
	Graph g(DAG);
	if(g.num_nodes() <= 0) {
		syslog(LOG_ERR, "Invalid DAG provided for rendezvous update");
		return -1;
	}
	std::string dag_string = g.dag_string();

	// Prepare a control message for the rendezvous service
	int controlPacketLength = MAX_XID_STR_SIZE + MAX_RV_DAG_SIZE;
	char controlPacket[controlPacketLength];
	int index = 0;
	strcpy(&controlPacket[index], hidstr);
	index += strlen(hidstr) + 1;
	strcpy(&controlPacket[index], dag_string.c_str());
	index += dag_string.size() + 1;
	controlPacketLength = index;
	// TODO: No intrinsic security for now

	// Create a socket, and send the message over it
	int sock = Xsocket(AF_XIA, SOCK_DGRAM, 0);
	if(sock < 0) {
		syslog(LOG_ERR, "Failed creating socket to talk with RV server");
		return -1;
	}
	if(Xsendto(sock, controlPacket, controlPacketLength, 0, (const struct sockaddr *)&rv_dag, sizeof(sockaddr_x)) < 0) {
		syslog(LOG_ERR, "Failed sending registration message to RV server");
		return -1;
	}
	// TODO: Receive ack from server
	return 0;
}

/*
** called by XregisterName and XregisterHost to do the actual work
*/
static int _xregister(const char *name, sockaddr_x *DAG, short flags) {
	int sock;
	int rc;
	int result;
	sockaddr_x ns_dag;
	char pkt[NS_MAX_PACKET_SIZE];

	if ((sock = Xsocket(AF_XIA, SOCK_DGRAM, 0)) < 0)
		return -1;

	//Read the nameserver DAG (the one that the name-registration will be sent to)
	if (XreadNameServerDAG(sock, &ns_dag) < 0) {
		LOG("Unable to find nameserver address");
		errno = NO_RECOVERY;
		return -1;
	}

	if (!name || *name == 0) {
		errno = EINVAL;
		return -1;
	}

	if (!DAG) {
		errno = EINVAL;
		return -1;
	}

	if (DAG->sx_family != AF_XIA) {
		errno = EINVAL;
		return -1;
	}

	Graph g(DAG);
	if (g.num_nodes() <= 0) {
		errno = EINVAL;
		return -1;
	}

	std::string dag_string = g.dag_string();

	//Construct a registration packet
	ns_pkt register_pkt;
	register_pkt.type = NS_TYPE_REGISTER;
	register_pkt.flags = flags;
	register_pkt.name = name;
	register_pkt.dag = dag_string.c_str();
	int len = make_ns_packet(&register_pkt, pkt, sizeof(pkt));

	//Send the name registration packet to the name server
	if(_send_and_wait(sock, pkt, len, (const struct sockaddr *)&ns_dag, 1)) {
		LOG("Error sending name registration");
		return -1;
	}

	//Check the response from the name server
	memset(pkt, 0, sizeof(pkt));
	if ((rc = Xrecvfrom(sock, pkt, NS_MAX_PACKET_SIZE, 0, NULL, NULL)) < 0) {
		int err = errno;
		LOGF("Error sending name registration (%d)", rc);
		Xclose(sock);
		errno = err;
		return -1;
	}

	ns_pkt resp_pkt;
	get_ns_packet(pkt, rc, &resp_pkt);

	switch (resp_pkt.type) {
	case NS_TYPE_RESPONSE_REGISTER:
		result = 0;
		break;
	case NS_TYPE_RESPONSE_ERROR:
		result = -1;
		break;
	default:
		LOGF("Unknown NS packet type (%d)", resp_pkt.type);
		result = -1;
		break;
	 }

	Xclose(sock);
	return result;
}

/*!
** @brief register a service or hostname with the name server
**
** Register a host or service name with the XIA nameserver.
**
** @note this function does not currently check to ensure
** that the client is allowed to bind to name.
**
** @param name the name of an XIA service or host
** @param DAG  the DAG to be bound to name
**
** @returns 0 on success
** @returns -1 on failure with errno set
**
*/
int XregisterName(const char *name, sockaddr_x *DAG) {
	return _xregister(name, DAG, 0);
}

/* for the wrapper's IP-port -> DAG mapping table */
int XregisterAddrID(const char *name, sockaddr_x *DAG) {
	return _xregister(name, DAG, NS_FLAGS_ADDR_MAP);
}

/* for the wrapper's Hostname-port -> DAG mapping table */
int XregisterHostID(const char *name, sockaddr_x *DAG) {
	return _xregister(name, DAG, NS_FLAGS_HOST_MAP);
}

int XregisterAnycastName(const char *name, sockaddr_x *DAG){
	int sock;
	int rc;
	int result;
	sockaddr_x ns_dag;
	char pkt[NS_MAX_PACKET_SIZE];

	if ((sock = Xsocket(AF_XIA, SOCK_DGRAM, 0)) < 0)
		return -1;

	//Read the nameserver DAG (the one that the name-registration will be sent to)
	if (XreadNameServerDAG(sock, &ns_dag) < 0) {
		LOG("Unable to find nameserver address");
		errno = NO_RECOVERY;
		return -1;
	}

	if (!name || *name == 0) {
		errno = EINVAL;
		return -1;
	}

	if (!DAG) {
		errno = EINVAL;
		return -1;
	}

	if (DAG->sx_family != AF_XIA) {
		errno = EINVAL;
		return -1;
	}

	Graph g(DAG);
	if (g.num_nodes() <= 0) {
		errno = EINVAL;
		return -1;
	}

	std::string dag_string = g.dag_string();

	//Construct a registration packet
	ns_pkt register_pkt;
	register_pkt.type = NS_TYPE_ANYCAST_REGISTER;
	register_pkt.flags = 0;
	register_pkt.name = name;
	register_pkt.dag = dag_string.c_str();
	int len = make_ns_packet(&register_pkt, pkt, sizeof(pkt));

	//Send the name registration packet to the name server
	if(_send_and_wait(sock, pkt, len, (const struct sockaddr *)&ns_dag, 1)) {
		LOG("Error sending anycast name registration");
		return -1;
	}

	//Check the response from the name server
	memset(pkt, 0, sizeof(pkt));
	if ((rc = Xrecvfrom(sock, pkt, NS_MAX_PACKET_SIZE, 0, NULL, NULL)) < 0) {
		int err = errno;
		LOGF("Error sending anycast name registration (%d)", rc);
		Xclose(sock);
		errno = err;
		return -1;
	}

	ns_pkt resp_pkt;
	get_ns_packet(pkt, rc, &resp_pkt);

	switch (resp_pkt.type) {
	case NS_TYPE_ANYCAST_RESPONSE_REGISTER:
		result = 0;
		break;
	case NS_TYPE_ANYCAST_RESPONSE_ERROR:
		result = -1;
		break;
	default:
		LOGF("Unknown NS packet type (%d)", resp_pkt.type);
		result = -1;
		break;
	 }

	Xclose(sock);
	return result;
}


/*
** only used by xhcp_client to register a host name record
** Migrate flag is used to trigger updating of related name server records
**  when the host has moved to a new AD
*/
int XregisterHost(const char *name, sockaddr_x *DAG) {
	return _xregister(name, DAG, NS_FLAGS_MIGRATE);
}

/*!
** @brief get name of connected peer socket
**
** This function returns the address of the peer connected to
** the Xsocket sockfd, in the buffer pointed to by addr.
**
** @note See the man page for the standard getpeername() call
** for more details.
**
** @param sockfd a connected Xsocket
** @param dag A sockaddr to hold the returned DAG
** @param len On input contans the size of the sockaddr
**  on output contains sizeof(sockaddr_x).
**
** @returns 0 on success
** @returns -1 on failure with errno set
** @returns errno = EFAULT if dag is NULL
** @returns errno = EOPNOTSUPP if sockfd is not of type XSSOCK_STREAM
** @returns errno = ENOTCONN if sockfd is not in a connected state
**
*/
int Xgetpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;

	if (!addr || !addrlen) {
		LOG("pointer is null!\n");
		errno = EFAULT;
		return -1;
	}

	if (*addrlen < sizeof(sockaddr_x)) {
		errno = EINVAL;
		return -1;
	}

	int stype = getSocketType(sockfd);
	if (stype != SOCK_STREAM && stype != SOCK_DGRAM) {
		LOG("Xgetpeername is only valid with stream and datagram sockets.");
		errno = EOPNOTSUPP;
		return -1;
	}

	if (getConnState(sockfd) != CONNECTED) {
		LOGF("Socket %d is not connected", sockfd);
		errno = ENOTCONN;
		return -1;
	}

	xia::XSocketMsg xsm;
	xsm.set_type(xia::XGETPEERNAME);
	unsigned seq = seqNo(sockfd);
	xsm.set_sequence(seq);

	// send the protobuf containing the user data to click
	if ((rc = click_send(sockfd, &xsm)) < 0) {
		LOGF("Error talking to Click: %s", strerror(errno));
		return -1;
	}

	// get the dag
	xsm.Clear();
	if ((rc = click_reply(sockfd, seq, &xsm)) < 0) {
		LOGF("Error retrieving status from Click: %s", strerror(errno));
		return -1;
	}

	if (xsm.type() != xia::XGETPEERNAME) {
		LOGF("error: expected %d, got %d\n", xia::XGETPEERNAME, xsm.type());
		return -1;
	}

	xia::X_GetPeername_Msg *msg = xsm.mutable_x_getpeername();

	Graph g(msg->dag().c_str());

	g.fill_sockaddr((sockaddr_x*)addr);
	*addrlen = sizeof(sockaddr_x);

	return 0;
}

/*!
** @brief get socket name
**
** Returns the current address to which the socket sockfd
** is bound, in the buffer pointed to by addr.
**
** @note See the man page for the standard getsockname() call
** for more details.
**
** @param sockfd An Xsocket
** @param dag A sockaddr_x to hold the returned DAG.
** @param len On input contans the size of the addr,
**  on output contains sizeof(sockaddr_x).
**
** @returns 0 on success
** @returns -1 on failure with errno set
** @returns errno = EFAULT if dag is NULL
** @returns errno = EOPNOTSUPP if sockfd is not an Xsocket
**
*/
int Xgetsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;

	if (!addr || !addrlen) {
		LOG("pointer is null!\n");
		errno = EFAULT;
		return -1;
	}

	if (*addrlen < sizeof(sockaddr_x)) {
		errno = EINVAL;
		return -1;
	}

	if (getSocketType(sockfd) == XSOCK_INVALID)
	{
		LOG("The socket is not a valid Xsocket");
		errno = EBADF;
		return -1;
	}

	xia::XSocketMsg xsm;
	xsm.set_type(xia::XGETSOCKNAME);
	unsigned seq = seqNo(sockfd);
	xsm.set_sequence(seq);

	// send the protobuf containing the user data to click
	if ((rc = click_send(sockfd, &xsm)) < 0) {
		LOGF("Error talking to Click: %s", strerror(errno));
		return -1;
	}

	// get the dag
	xsm.Clear();

	if ((rc = click_reply(sockfd, seq, &xsm)) < 0) {
		LOGF("Error retrieving status from Click: %s", strerror(errno));
		return -1;
	}

	if (xsm.type() != xia::XGETSOCKNAME) {
		LOGF("error: expected %d, got %d\n", xia::XGETPEERNAME, xsm.type());
		return -1;
	}

	xia::X_GetSockname_Msg *msg = xsm.mutable_x_getsockname();

	if (strcmp(msg->dag().c_str(), "RE (invalid)") == 0) {

		// socket is not initialized yet
		// FIXME: can we do a better return here?
		errno = EBADF;
		return -1;
	}

	Graph g(msg->dag().c_str());

	g.fill_sockaddr((sockaddr_x*)addr);
	*addrlen = sizeof(sockaddr_x);

	return 0;
}

int make_ns_packet(ns_pkt *np, char *pkt, int pkt_sz)
{
	char *end = pkt;

	// this had better not happen
	if (!np || !pkt || pkt_sz == 0)
		return 0;

	memset(pkt, 0, pkt_sz);
	pkt[0] = np->type;
	pkt[1] = np->flags;
	end += 2;

	switch (np->type) {
		case NS_TYPE_REGISTER:
			if (np->name == NULL || np->dag == NULL)
				return 0;
			strcpy(end, np->name);
			end += strlen(np->name) + 1;

			strcpy(end, np->dag);
			end += strlen(np->dag) + 1;
			break;
		case NS_TYPE_ANYCAST_REGISTER:
			if (np->name == NULL || np->dag == NULL)
				return 0;
			strcpy(end, np->name);
			end += strlen(np->name) + 1;

			strcpy(end, np->dag);
			end += strlen(np->dag) + 1;
			break;
		case NS_TYPE_QUERY:
			if (np->name == NULL)
				return 0;
			strcpy(end, np->name);
			end += strlen(np->name) + 1;
			break;
		case NS_TYPE_ANYCAST_QUERY:
			if (np->name == NULL)
				return 0;
			strcpy(end, np->name);
			end += strlen(np->name) + 1;
			break;
		case NS_TYPE_RESPONSE_QUERY:
			if (np->dag == NULL)
				return 0;
			strcpy(end, np->dag);
			end += strlen(np->dag) + 1;
			break;
		case NS_TYPE_ANYCAST_RESPONSE_QUERY:
			if (np->dag == NULL)
				return 0;
			strcpy(end, np->dag);
			end += strlen(np->dag) + 1;
			break;
		case NS_TYPE_RQUERY:
			if (np->dag == NULL)
				return 0;
			strcpy(end, np->dag);
			end += strlen(np->dag) + 1;
			break;

		case NS_TYPE_RESPONSE_RQUERY:
			if (np->name == NULL)
				return 0;
			strcpy(end, np->name);
			end += strlen(np->name) + 1;
			break;

		default:
			break;
	}

	return end - pkt;
}

void get_ns_packet(char *pkt, int sz, ns_pkt *np)
{
	if (sz < 2) {
		// hacky error check
		np->type = NS_TYPE_RESPONSE_ERROR;
		return;
	}

	np->type  = pkt[0];
	np->flags = pkt[1];
	np->name  = np->dag = NULL;

	switch (np->type) {
		case NS_TYPE_QUERY:
			np->name = &pkt[2];
			break;
		case NS_TYPE_ANYCAST_QUERY:
			np->name = &pkt[2];
			break;
		case NS_TYPE_RQUERY:
			np->dag = &pkt[2];
			break;
		case NS_TYPE_REGISTER:
			np->name = &pkt[2];
			np->dag = np->name + strlen(np->name) + 1;
			break;
		case NS_TYPE_ANYCAST_REGISTER:
			np->name = &pkt[2];
			np->dag = np->name + strlen(np->name) + 1;
			break;
		case NS_TYPE_RESPONSE_QUERY:
			np->dag = &pkt[2];
			break;
		case NS_TYPE_RESPONSE_RQUERY:
			np->name = &pkt[2];
			break;
		case NS_TYPE_ANYCAST_RESPONSE_QUERY:
			np->dag = &pkt[2];
			break;
		default:
			break;
	}
}
