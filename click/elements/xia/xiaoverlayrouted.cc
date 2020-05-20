#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <click/packet_anno.hh>
#include <clicknet/xia.h>
#include <click/packet.hh>
#include "click/dagaddr.hpp"
#include "xiaoverlayrouted.hh"

RouteState route_state;
XIARouter xr;

#define XID_SIZE	CLICK_XIA_XID_ID_LEN

#define SID_XOVERLAY "SID:1110000000000000000000000000000000001111"

CLICK_DECLS


#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sstream>
#include <algorithm>
#include <ctype.h>
#include <iostream>
#include <unistd.h>

#define INCLUDE_TEST_CODE 0


#define check_init() do { if (!_init) return init_err; } while (false);

ControlSocketClient::err_t
ControlSocketClient::configure(unsigned int host_ip, unsigned short port)
{

  if (_init)
    return reinit_err;

  _host = host_ip;
  _port = port;

  _fd = socket(PF_INET, SOCK_STREAM, 0);
  if (_fd < 0)
    return sys_err;

  /*
   * connect to remote ControlSocket
   */
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = _host;
  sa.sin_port = htons(port);

  char namebuf[32];
  snprintf(namebuf, 32, "%u.%u.%u.%u:%hu",
	   (_host & 0xff) >> 0,
	   (_host & 0xff00) >> 8,
	   (_host & 0xff0000) >> 16,
	   (_host & 0xff000000) >> 24,
	   port);
  _name = namebuf;

  int res = connect(_fd, (struct sockaddr *)  &sa, sizeof(sa));
  if (res < 0) {
    int save_errno = errno;
    ::close(_fd);
    errno = save_errno;
    return sys_err;
  }

  int major, minor;
  size_t slash, dot;

  /*
   * check that we get the expected banner
   */
  string buf;
  err_t err = readline(buf);
  if (err != no_err) {
    int save_errno = errno;
    ::close(_fd);
    errno = save_errno;
    return err;
  }

  slash = buf.find('/');
  dot = (slash != string::npos ? buf.find('.', slash + 1) : string::npos);
  if (slash == string::npos || dot == string::npos) {
    ::close(_fd);
    return click_err; /* bad format */
  }

  /*
   * check ControlSocket protocol version
   */
  major = atoi(buf.substr(slash + 1, dot - slash - 1).c_str());
  minor = atoi(buf.substr(dot + 1, buf.size() - dot - 1).c_str());
  if (major != PROTOCOL_MAJOR_VERSION ||
      minor < PROTOCOL_MINOR_VERSION) {
    ::close(_fd);
    return click_err; /* wrong version */
  }

  _init = true;
  return no_err;
}


ControlSocketClient::err_t
ControlSocketClient::close()
{
  check_init();
  _init = false;
  int res = ::close(_fd);
  if (res < 1)
    return sys_err;
  else
    return no_err;
}


ControlSocketClient::err_t
ControlSocketClient::readline(string &buf)
{
  assert(_fd);

#define MAX_LINE_SZ 1024 /* arbitrary... to prevent weirdness */

  /*
   * keep calling read() to get one character at a time, until we get
   * a line.  not very ``efficient'', but who cares?
   */
  char c = 0;
  buf.resize(0);
  do {
    int res = ::read(_fd, (void *) &c, 1);
    if (res < 0)
      return sys_err;
    if (res != 1)
      return sys_err;
    buf += c;
    if (buf.size() > MAX_LINE_SZ)
      return click_err;
  }
  while (c != '\n');

  return no_err;
}


int
ControlSocketClient::get_resp_code(string line)
{
  if (line.size() < 3)
    return -1;
  return atoi(line.substr(0, 3).c_str());
}


int
ControlSocketClient::get_data_len(string line)
{
  unsigned int i;
  for (i = 0; i < line.size() && !isdigit((unsigned char) line[i]); i++)
    ; // scan string
  if (i == line.size())
    return -1;
  return atoi(line.substr(i, line.size() - i).c_str());
}


ControlSocketClient::err_t
ControlSocketClient::read(string el, string handler, string &response)
{
  check_init();

  if (el.size() > 0)
    handler = el + "." + handler;
  string cmd = "READ " + handler + "\n";

  int res = ::write(_fd, cmd.c_str(), cmd.size());
  if (res < 0)
    return sys_err;
  if ((size_t) res != cmd.size())
    return sys_err;

  string cmd_resp;
  string line;
  do {
    err_t err = readline(line);
    if (err != no_err)
      return err;
    if (line.size() < 4)
      return click_err;
    cmd_resp += line;
  }
  while (line[3] == '-');

  int code = get_resp_code(line);
  if (code != CODE_OK && code != CODE_OK_WARN)
    return handle_err_code(code);

  res = readline(line);
  if (res < 0)
    return click_err;
  int num = get_data_len(line);
  if (num < 0)
    return click_err;

  response.resize(0);
  if (num == 0)
    return no_err;

  char *buf = new char[num];
  int num_read = 0;
  while (num_read < num) {
    res = ::read(_fd, buf + num_read, num - num_read);
    if (res < 0) {
      delete[] buf;
      return sys_err;
    }
    num_read += res;
  }

  response.append(buf, num);
  delete[] buf;

  return no_err;
}


ControlSocketClient::err_t
ControlSocketClient::read(string el, string handler, char *buf, int &bufsz)
{
  string resp;
  err_t err = read(el, handler, resp);
  if (err != no_err)
    return err;

  bufsz = min((size_t) bufsz, resp.size());

  memcpy(buf, resp.c_str(), bufsz);
  if (resp.size() > (size_t) bufsz)
    return too_short;
  else
    return no_err;
}


ControlSocketClient::err_t
ControlSocketClient::write(string el, string handler, const char *buf, int bufsz)
{
  check_init();

  if (el.size() > 0)
    handler = el + "." + handler;
  char cbuf[10];
  snprintf(cbuf, sizeof(cbuf), "%d", bufsz);
  string cmd = "WRITEDATA " + handler + " " + cbuf + "\n";

  int res = ::write(_fd, cmd.c_str(), cmd.size());
  if (res < 0)
    return sys_err;
  if ((size_t) res != cmd.size())
    return sys_err;

  res = ::write(_fd, buf, bufsz);
  if (res < 0)
    return sys_err;
  if (res != bufsz)
    return sys_err;

  string cmd_resp;
  string line;
  do {
    err_t err = readline(line);
    if (err != no_err)
      return err;
    if (line.size() < 4)
      return click_err;
    cmd_resp += line;
  }
  while (line[3] == '-');

  int code = get_resp_code(line);
  if (code != CODE_OK && code != CODE_OK_WARN)
    {
//      cout << "CCCC " << code << endl;
    return handle_err_code(code);
    }

  return no_err;
}


ControlSocketClient::err_t
ControlSocketClient::write(string el, string handler, string data)
{
  return write(el, handler, data.c_str(), data.size());
}


ControlSocketClient::err_t
ControlSocketClient::handle_err_code(int code)
{
  switch (code) {
  case CODE_SYNTAX_ERR: return click_err; break;
  case CODE_UNIMPLEMENTED: return click_err; break;
  case CODE_NO_ELEMENT: return no_element; break;
  case CODE_NO_HANDLER: return no_handler; break;
  case CODE_HANDLER_ERR: return handler_err; break;
  case CODE_PERMISSION: return handler_no_perm; break;
  default: return click_err; break;
  }
  return click_err;
}



vector<string>
ControlSocketClient::split(string s, size_t offset, char terminator)
{
  vector<string> v;
  size_t pos = offset;
  size_t len = s.size();
  while (pos < len) {
    size_t start = pos;
    while (pos < len && s[pos] != terminator)
      pos++;
    if (start < pos || pos < len)
      v.push_back(s.substr(start, pos - start));
    pos++;
  }
  return v;
}


ControlSocketClient::err_t
ControlSocketClient::get_config_el_names(vector<string> &els)
{
  string resp;
  err_t err = read("", "list", resp);
  if (err != no_err)
    return err;

  /* parse how many els */
  int i = resp.find('\n');
  int num = atoi(resp.substr(0, i).c_str());


  els = split(resp, i + 1, '\n');
  if (els.size() != (size_t) num)
    return handler_bad_format;

  return no_err;
}


ControlSocketClient::err_t
ControlSocketClient::get_string_vec(string el, string h, vector<string> &v)
{
  string resp;
  err_t err = read(el, h, resp);
  if (err != no_err)
    return err;

  v = split(resp, 0, '\n');
  return no_err;
}


ControlSocketClient::err_t
ControlSocketClient::get_el_handlers(string el, vector<handler_info_t> &handlers)
{
  vector<handler_info_t> v;
  vector<string> vh;

  string buf;
  err_t err = read(el, "handlers", buf);
  if (err != no_err)
    return err;

  vh = split(buf, 0, '\n');
  for (vector<string>::iterator i = vh.begin(); i != vh.end(); i++) {
    string &s = *i;
    size_t j;
    for (j = 0; j < s.size() && !isspace((unsigned char) s[j]); j++)
      ; /* find record split -- don't use s.find because could be any whitespace */
    if (j == s.size())
      return click_err;
    handler_info_t hi;
    hi.element_name = el;
    hi.handler_name = trim(s.substr(0, j));
    while (j < s.size() && isspace((unsigned char) s[j]))
      j++;
    for ( ; j < s.size(); j++) {
	if (tolower((unsigned char) s[j]) == 'r')
	    hi.can_read = true;
	else if (tolower((unsigned char) s[j]) == 'w')
	    hi.can_write = true;
	else if (isspace((unsigned char) s[j]))
	    break;
    }
    v.push_back(hi);
  }

  handlers = v;
  return no_err;
}


ControlSocketClient::err_t
ControlSocketClient::check_handler(string el, string h, bool is_write, bool &exists)
{
  check_init();

  if (el.size() > 0)
    h = el + "." + h;
  string cmd = (is_write ? "CHECKWRITE " : "CHECKREAD ") + h + "\n";

  int res = ::write(_fd, cmd.c_str(), cmd.size());
  if (res < 0)
    return sys_err;
  if ((size_t) res != cmd.size())
    return sys_err;

  string cmd_resp;
  string line;
  do {
    err_t err = readline(line);
    if (err != no_err)
      return err;
    if (line.size() < 4)
      return click_err;
    cmd_resp += line;
  }
  while (line[3] == '-');

  int code = get_resp_code(line);
  switch (code) {
  case CODE_OK:
  case CODE_OK_WARN:
    exists = true;
    return no_err;;
  case CODE_NO_ELEMENT:
  case CODE_NO_HANDLER:
  case CODE_HANDLER_ERR:
  case CODE_PERMISSION:
    exists = false;
    return no_err;
  case CODE_UNIMPLEMENTED:
    if (el.size() == 0)
      return handle_err_code(code); /* no workaround for top-level router handlers */
    else
      return check_handler_workaround(el, h, is_write, exists);
  default:
    return handle_err_code(code);
  }
}



ControlSocketClient::err_t
ControlSocketClient::check_handler_workaround(string el, string h, bool is_write, bool &exists)
{
  /*
   * If talking to an old ControlSocket, try the "handlers" handler
   * instead.
   */

  vector<handler_info_t> v;
  err_t err = get_el_handlers(el, v);
  if (err != no_err)
    return err;

  for (vector<handler_info_t>::iterator i = v.begin(); i != v.end(); i++) {
    if (i->handler_name == h) {
      if ((is_write && i->can_write) ||
	  (!is_write && i->can_read))
	exists = true;
      else
	exists = false;
      return no_err;
    }
  }

  exists = false;
  return no_err;
}


string
ControlSocketClient::trim(string s)
{
  size_t start, end;
  for (start = 0; start < s.size() && isspace((unsigned char) s[start]); start++)
    ; /* */
  for (end = s.size(); end > 0 && isspace((unsigned char) s[end - 1]); end--)
    ; /* */

  if (start >= end)
    return "";

  return s.substr(start, end - start);
}

int XIARouter::connect(std::string clickHost, unsigned short controlPort)
{
	struct hostent *h;

	if (_connected)
		return XR_ALREADY_CONNECTED;

	if ((h = gethostbyname(clickHost.c_str())) == NULL)
		return XR_BAD_HOSTNAME;

	unsigned addr = *(unsigned*)h->h_addr;

	if ((_cserr = _cs.configure(addr, controlPort)) != 0)
		return XR_NOT_CONNECTED;
	
	_connected = true;
	return XR_OK;
}

void XIARouter::close()
{
	if (_connected)
		_cserr = _cs.close();
	_connected = false;
}

int XIARouter::version(std::string &ver)
{
	if (!connected())
		return XR_NOT_CONNECTED;

	if ((_cserr = _cs.get_router_version(ver)) == 0)
		return XR_OK;
	return  XR_CLICK_ERROR;
}

int XIARouter::listRouters(std::vector<std::string> &rlist)
{
	vector<string> elements;
	size_t n;

	if (!connected())
		return XR_NOT_CONNECTED;

	if ((_cserr = _cs.get_config_el_names(elements)) != 0)
		return XR_CLICK_ERROR;

	vector<string>::iterator it;
	for (it = elements.begin(); it < elements.end(); it++) {

		// cheap way of finding host and router devices, they both have a /xrc element
		if ((n = (*it).find("/xrc")) != string::npos) {
			rlist.push_back((*it).substr(0, n));
		}
	}
	return 0;
}

int XIARouter::getNeighbors(std::string xidtype, std::vector<std::string> &neighbors)
{
	if (!connected())
		return XR_NOT_CONNECTED;
	
	std::string table = _router + "/xrc/n/proc/rt_" + xidtype;

	std::string neighborStr;
	if ((_cserr = _cs.read(table, "neighbor", neighborStr)) != 0)
		return XR_CLICK_ERROR;

	std::string::size_type beg = 0;
	for (auto end = 0; (end = neighborStr.find(',', end)) != std::string::npos; ++end)
	{
		neighbors.push_back(neighborStr.substr(beg, end - beg));
		beg = end + 1;
	}

	printf("Retuning neighbors\n");
	return 0;
}


// get the current set of route entries, return value is number of entries returned or < 0 on err
int XIARouter::getRoutes(std::string xidtype, std::vector<XIARouteEntry> &xrt)
{
	std::string result;
	vector<string> lines;
	int n = 0;

	if (!connected())
		return XR_NOT_CONNECTED;

	if (xidtype.length() == 0)
		return XR_INVALID_XID;

	if (getRouter().length() == 0)
		return  XR_ROUTER_NOT_SET;

	std::string table = _router + "/xrc/n/proc/rt_" + xidtype;

	if ((_cserr = _cs.read(table, "list", result)) != 0)
		return XR_CLICK_ERROR;

	unsigned start = 0;
	unsigned current = 0;
	unsigned len = result.length();
	string line;

	xrt.clear();
	while (current < len) {
		start = current;
		while (current < len && result[current] != '\n') {
			current++;
		}

		if (start < current || current < len) {
			line = result.substr(start, current - start);

			XIARouteEntry entry;
			unsigned start, next;
			string s;
			int port;

			start = 0;
			next = line.find(",");
			entry.xid = line.substr(start, next - start);

			start = next + 1;
			next = line.find(",", start);
			s = line.substr(start, next - start);
			port = atoi(s.c_str());
			entry.port = port;

			start = next + 1;
			next = line.find(",", start);
			entry.nextHop = line.substr(start, next - start);

			start = next + 1;
			s = line.substr(start, line.length() - start);
			entry.flags = atoi(s.c_str());

			xrt.push_back(entry);
			n++;
		}
		current++;
	}

	return n;
}

std::string XIARouter::itoa(signed i)
{
	std::string s;
	std::stringstream ss;

	ss << i;
	s = ss.str();
	return s;
}

int XIARouter::updateRoute(string cmd, const std::string &xid, int port, const std::string &next, unsigned long flags)
{
	string xidtype;
	string mutableXID(xid);
	size_t n;

	if (!connected())
		return XR_NOT_CONNECTED;

	if (mutableXID.length() == 0)
		return XR_INVALID_XID;

	if (next.length() > 0 && next.find(":") == string::npos)
		return XR_INVALID_XID;

	n = mutableXID.find(":");
	if (n == string::npos || n >= sizeof(xidtype))
		return XR_INVALID_XID;

	if (getRouter().length() == 0)
		return  XR_ROUTER_NOT_SET;

	xidtype = mutableXID.substr(0, n);

	std::string table = _router + "/xrc/n/proc/rt_" + xidtype;
	
	string default_xid("-"); 
	if (mutableXID.compare(n+1, 1, default_xid) == 0)
		mutableXID = default_xid;
		
	std::string entry;

	// remove command only takes an xid
	if (cmd == "remove") 
		entry = mutableXID;
	else
		entry = mutableXID + "," + itoa(port) + "," + next + "," + itoa(flags);

	if ((_cserr = _cs.write(table, cmd, entry)) != 0)
		return XR_CLICK_ERROR;
	
	return XR_OK;
}

int XIARouter::addRoute(const std::string &xid, int port, const std::string &next, unsigned long flags)
{
	return updateRoute("add4", xid, port, next, flags);
}

int XIARouter::setRoute(const std::string &xid, int port, const std::string &next, unsigned long flags)
{
	return updateRoute("set4", xid, port, next, flags);
}

int XIARouter::delRoute(const std::string &xid)
{
	string next = "";
	return updateRoute("remove", xid, 0, next, 0);
}

const char *XIARouter::cserror()
{
	switch(_cserr) {
		case ControlSocketClient::no_err:
			return "no error";
		case ControlSocketClient::sys_err:
			return "O/S or networking error, check errno for more information";
		case ControlSocketClient::init_err:
			return "tried to perform operation on an unconfigured ControlSocketClient";
		case ControlSocketClient::reinit_err:
			return "tried to re-configure the client before close()ing it";
		case ControlSocketClient::no_element:
			return "specified element does not exist";
		case ControlSocketClient::no_handler:
			return "specified handler does not exist";
		case ControlSocketClient::handler_no_perm:
			return "router denied access to the specified handler";
		case ControlSocketClient::handler_err:
			return "handler returned an error";
		case ControlSocketClient::handler_bad_format:
			return "bad format in calling handler";
		case ControlSocketClient::click_err:
			return "unexpected response or error from the router";
		case ControlSocketClient::too_short:
			return "user buffer was too short";
	}
	return "unknown";
}


XIAOverlayRouted::XIAOverlayRouted()
{
	
	FILE *f = fopen("etc/resolv.conf", "r");	
	if (!f) {
		printf("Failed to open resolv.conf \n");
		return;
	}
	char ad[100], hid[100], re[100];
	fscanf(f,"%s %s %s", re, ad, hid);
	fclose(f);

	strcpy(route_state.myAD, ad);
	strcpy(route_state.myHID, hid);

	route_state.num_neighbors = 0; // number of neighbor routers
	route_state.calc_dijstra_ticks = 0;

	route_state.flags = F_EDGE_ROUTER;

	route_state.dual_router_AD = "NULL";
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
	ad->set_type(n_ad.type());
	ad->set_id(n_ad.id(), XID_SIZE);
	hid->set_type(n_hid.type());
	hid->set_id(n_hid.id(), XID_SIZE);
	sid->set_type(n_sid.type());
	sid->set_id(n_sid.id(), XID_SIZE);


	printf("XIAOverlayRouted: %s\n", msg.DebugString().c_str());
	// printf("**** sending lsa with and num_neighbors %d \n", route_state.num_neighbors);

	msg.SerializeToString(&message);
	return message;
}

void XIAOverlayRouted::push(int port, Packet *p_in)
{
	std::string msg =  sendHello();

	struct click_ip *ip;
	struct click_udp *udp;
  	WritablePacket *q = Packet::make(sizeof(*ip) + sizeof(*udp) + msg.length());
  	memset(q->data(), '\0', q->length());
	ip = (struct click_ip *) q->data();
  	udp = (struct click_udp *) (ip + 1);
  	memcpy(q + sizeof(*ip) + sizeof(*udp), msg.c_str(), msg.length());

	ip->ip_v = 4;
	ip->ip_hl = 5;
	ip->ip_tos = 0x10;
	ip->ip_len = htons(q->length());
	ip->ip_id = htons(0); // what is this used for exactly?
	ip->ip_off = htons(IP_DF);
	ip->ip_ttl = 255;
	ip->ip_p = IP_PROTO_UDP;
	ip->ip_sum = 0;
	struct in_addr *saddr = (struct in_addr *)malloc(sizeof(struct in_addr));
	struct in_addr *daddr = (struct in_addr *)malloc(sizeof(struct in_addr));
	// assert(saddr);
	// assert(daddr);
	inet_aton("10.0.1.128", saddr);
	inet_aton("10.0.1.130", daddr);
	ip->ip_src = *saddr;
	ip->ip_dst = *daddr;


	udp->uh_sport = htons(8772);
	udp->uh_dport = htons(8772);
	udp->uh_ulen = htons(msg.length());

	q->set_ip_header(ip, ip->ip_hl << 2);
  q->set_dst_ip_anno(IPAddress(*daddr));
  SET_DST_PORT_ANNO(q, htons(8772));

	printf("XIAOverlayRouted: Pushing packet \n");
	output(0).push(q);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(XIAOverlayRouted)
ELEMENT_MT_SAFE(XIAOverlayRouted)
ELEMENT_LIBS(-lprotobuf -L../../api/lib -ldagaddr)
