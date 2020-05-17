#ifndef CLICK_XIAOVERLAYROUTED_HH
#define CLICK_XIAOVERLAYROUTED_HH
#include <click/element.hh>

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

#include "../../userlevel/xroute.pb.h"

using namespace std;

CLICK_DECLS

#define F_CORE_ROUTER  0x0002 // node is an internal router
#define F_EDGE_ROUTER  0x0004 // node is an edge router
#define F_CONTROLLER   0x0008 // node is a controller
#define F_IP_GATEWAY   0x0010 // router is a dual stack router
#define F_STATIC_ROUTE 0x0100 // route entry was added manually and should not expire

// Main loop iterates every 1000 usec = 1 ms = 0.001 sec
#define MAIN_LOOP_USEC 1000
#define MAIN_LOOP_MSEC 50 // .05 sec
#define RECV_ITERS 2
#define HELLO_ITERS 2
#define LSA_ITERS 8
#define CALC_DIJKSTRA_INTERVAL 4
#define MAX_HOP_COUNT 50
#define MAX_XID_SIZE 64
#define MAX_DAG_SIZE 512

#define XR_OK					0
#define XR_NOT_CONNECTED		-1
#define XR_ALREADY_CONNECTED	-2
#define XR_CLICK_ERROR			-3
#define XR_ROUTE_EXISTS			-4
#define XR_ROUTE_DOESNT_EXIST	-5
#define XR_NOT_XIA				-6
#define XR_ROUTER_NOT_SET		-7
#define XR_BAD_HOSTNAME			-8
#define XR_INVALID_XID			-9

#define TOTAL_SPECIAL_CASES 8
#define DESTINED_FOR_DISCARD -1
#define DESTINED_FOR_LOCALHOST -2
#define DESTINED_FOR_DHCP -3
#define DESTINED_FOR_BROADCAST -4
#define REDIRECT -5
#define UNREACHABLE -6
#define FALLBACK -7

/*
 * NB: obscure implementation note: this class does not handle EINTR
 * errors from any of the read/write calls.  If this is relevant to
 * your program, this class may not do the ``right thing''
 */

class ControlSocketClient
{
public:
  ControlSocketClient() : _init(false), _fd(0) { }
  ControlSocketClient(ControlSocketClient &) : _init(false), _fd(0) { }

  enum err_t {
    no_err = 0,
    sys_err,            /* O/S or networking error, check errno for more information */
    init_err,           /* tried to perform operation on an unconfigured ControlSocketClient */
    reinit_err,         /* tried to re-configure the client before close()ing it */
    no_element,         /* specified element does not exist */
    no_handler,         /* specified handler does not exist */
    handler_no_perm,    /* router denied access to the specified handler */
    handler_err,        /* handler returned an error */
    handler_bad_format, /* bad format in calling handler */
    click_err,          /* unexpected response or error from the router */
    too_short           /* user buffer was too short */
  };

  /*
   * Configure a new ControlSocketClient.
   * HOST_IP is IP address (in network byte order) of the machine that user-level click is running on
   * PORT is the IP port the ControlSocket is listening on.
   * Returns: no_err, sys_err, reinit_err, click_err
   * If returns no_err, the client is properly configured; otherwise the client is unconfigured.
   */
  err_t configure(unsigned int host_ip, unsigned short port);

  /*
   * Close a configured client.
   * Returns: no_err, sys_err, init_err
   * In any case, the client is left unconfigured.
   */
  err_t close();

  /*
   * Return a string describing the ControlSocket's host and port.
   * Requires: object is configured
   */
  const string name() { assert(_init); return _name; }


  /*
   * NB: the following functions return data about or send data to the
   * click router via the ControlSocket.  Unless otherwise noted, the
   * data returned or sent is undefined unless the function's return
   * value is no_err.
   */

  /*
   * Get a string containing the router's configuration
   * (get_router_config) or flattened configuration
   * (get_router_flat_config).
   * CONFIG is filled with the configuration; existing contents are replaced.
   * Returns: no_err, no_handler, handler_err, handler_no_perm, sys_err, init_err, click_err
   */
  err_t get_router_config(string &config)         { return read("", "config", config); }
  err_t get_router_flat_config(string &config)    { return read("", "flatconfig", config); }

  /*
   * Get a string containing the router's version
   * VERS is filled with the version; existing contents are replaced.
   * Returns: no_err, no_handler, handler_err, handler_no_perm, sys_err, init_err, click_err
   */
  err_t get_router_version(string &vers)  { err_t err = read("", "version", vers); /*vers = trim(vers);*/ return err; }

  /*
   * Get the names of the elements in the the current router configuration.
   * ELS is filled with the names, existing contents are replaced.
   * Returns: no_err, no_handler, handler_err, handler_no_perm, sys_err, init_err, click_err
   */
  err_t get_config_el_names(vector<string> &els);

  /*
   * Get the names of the element types that the router knows about.
   * CLASSES is filled with the names, existing contents are replaced.
   * Returns: no_err, no_handler, handler_err, handler_no_perm, sys_err, init_err, click_err
   */
  err_t get_router_classes(vector<string> &classes)   { return get_string_vec("", "classes", classes); }

  /*
   * Get the names of the packages that the router knows about.
   * PACKAGES is filled with the names, existing contents are replaced.
   * Returns: no_err, no_handler, handler_err, handler_no_perm, sys_err, init_err, click_err
   */
  err_t get_router_packages(vector<string> &pkgs)  { return get_string_vec("", "packages", pkgs); }

  /*
   * Get the names of the current router configuration requirements.
   * REQS is filled with the names, existing contents are replaced.
   * Returns: no_err, no_handler, handler_err, handler_no_perm, sys_err, init_err, click_err
   */
  err_t get_config_reqs(vector<string> &reqs)         { return get_string_vec("", "requirements", reqs); }

  struct handler_info_t {
    string element_name;
    string handler_name;
    bool can_read;
    bool can_write;
    handler_info_t() : can_read(false), can_write(false) { }
  };

  /*
   * Get the information about an element's handlers in the current router configuration.
   * EL is the element's name.
   * HANDLERS is filled with the handler info, existing contents are replaced.
   * Returns: no_err, no_element, handler_err, handler_no_perm, sys_err, init_err, click_err
   */
  err_t get_el_handlers(string el, vector<handler_info_t> &handlers);

  /*
   * Check whether a read/write handler exists.
   * EL is the element's name.
   * H is the handler's name.
   * IS_WRITE true to check for write handler, otherwise check read handler.
   * EXISTS is filled with true if the handler exists, otherwise false.
   * Returns: no_err, sys_err, init_err, click_err
   */
  err_t check_handler(string el, string h, bool is_write, bool &exists);
protected:
  err_t check_handler_workaround(string el, string h, bool is_write, bool &exists);

public:
  /*
   * Return the results of reading a handler.
   * EL is the element's name.
   * HANDLER is the handler name.
   * RESPONSE is filled with the handler's output, existing contents are replaced.
   * If NAME is not empty, calls``NAME.HANDLER''; otherwise calls ``HANDLER''
   * Returns: no_err, no_element, no_handler, handler_err, handler_no_perm, sys_err, init_err, click_err
   */
  err_t read(string el, string handler, string &response);

  /*
   * Return the results of reading a handler.
   * EL is the element's name.
   * HANDLER is the handler name.
   * BUF receives the data.
   * BUFSZ is the size of BUF, and recieves the actual number of characters placed into BUF.
   * If NAME is not empty, calls``NAME.HANDLER''; otherwise calls ``HANDLER''
   * Returns: no_err, no_element, no_handler, handler_err, handler_no_perm, sys_err, init_err, click_err, too_short
   * If returns too_short, the operation succeeded, but returned more than BUFSZ characters; the first BUFSZ
   * characters of the result are placed into BUF, and BUFSZ is unchanged.
   */
  err_t read(string el, string handler, char *buf, int &bufsz);

  /*
   * Write data to an element's handler.
   * EL is the element's name.
   * HANDLER is the handler name.
   * DATA contains the data.  No terminating '\0' is written.
   * If NAME is not empty, calls``NAME.HANDLER''; otherwise calls ``HANDLER''
   * Returns: no_err, no_element, no_handler, handler_err, handler_no_perm, sys_err, init_err, click_err
   */
  err_t write(string el, string handler, string data);

  /*
   * Write data to an element's handler.
   * EL is the element's name.
   * HANDLER is the handler name.
   * BUF contains the data.
   * BUFSZ is the number of characters to be written from BUF.
   * If NAME is not empty, calls``NAME.HANDLER''; otherwise calls ``HANDLER''
   * Returns: no_err, no_element, no_handler, handler_err, handler_no_perm, sys_err, init_err, click_err
   */
  err_t write(string el, string handler, const char *buf, int bufsz);

  /*
   * sugar, for reading and writing handlers.
   */
  err_t read(handler_info_t h, string &response)      { return read(h.element_name, h.handler_name, response); }
  err_t read(handler_info_t h, char *buf, int &bufsz) { return read(h.element_name, h.handler_name, buf, bufsz); }
  err_t write(handler_info_t h, string data)          { return write(h.element_name, h.handler_name, data); }
  err_t write(handler_info_t h, const char *buf, int bufsz) { return write(h.element_name, h.handler_name, buf, bufsz); }


  ~ControlSocketClient() { if (_init) ::close(_fd); }

private:
  bool _init;

  unsigned int _host;
  unsigned short _port;
  int _fd;
  int _protocol_minor_version;

  string _name;

  enum {
    CODE_OK = 200,
    CODE_OK_WARN = 220,
    CODE_SYNTAX_ERR = 500,
    CODE_UNIMPLEMENTED = 501,
    CODE_NO_ELEMENT = 510,
    CODE_NO_HANDLER = 511,
    CODE_HANDLER_ERR = 520,
    CODE_PERMISSION = 530,
    CODE_NO_ROUTER = 540,

    PROTOCOL_MAJOR_VERSION = 1,
    PROTOCOL_MINOR_VERSION = 0
  };

  /* Try to read a '\n'-terminated line (including the '\n') from the
   * socket.  */
  err_t readline(string &buf);

  int get_resp_code(string line);
  int get_data_len(string line);
  err_t handle_err_code(int code);

  err_t get_string_vec(string el, string h, vector<string> &v);
  vector<string> split(string s, size_t offset, char terminator);
  string trim(string s);
};

typedef struct {
	std::string xid;
	std::string nextHop;
	unsigned short port;
	unsigned long  flags;
} XIARouteEntry;

class XIARouter {
public:
	XIARouter(const char *_rtr = "router0") { _connected = false;
		_cserr = ControlSocketClient::no_err; _router = _rtr; };
	~XIARouter() { if (connected()) close(); };

	// connect to click
	int connect(std::string clickHost = "localhost", unsigned short controlPort = 7777);
	int connected() { return _connected; };
	void close();

	// returns the click version in <ver>
	int version(std::string &ver);

	// returns the error code from the underlying click control socket interface
	ControlSocketClient::err_t ControlSocketError() { return _cserr; };

	// return a vector of router devices click knows about (host0, router1, ....)
	int listRouters(std::vector<std::string> &rlist);

	// specify which router to operate on, must be called before adding/removing routes
	// defaults to router0
	void setRouter(std::string r) { _router = r; };
	std::string getRouter() { return _router; };

	// get the current set of route entries, return value is number of entries returned or < 0 on err
	int getRoutes(std::string xidtype, std::vector<XIARouteEntry> &xrt);

	// returns 0 success, < 0 on error
	int addRoute(const std::string &xid, int port, const std::string &next, unsigned long flags);
	int setRoute(const std::string &xid, int port, const std::string &next, unsigned long flags);
	int delRoute(const std::string &xid);
	int getNeighbors(std::string xidtype, std::vector<std::string> &neighbors);


	const char *cserror();
private:
	bool _connected;
	std::string _router;
	ControlSocketClient _cs;
	ControlSocketClient::err_t _cserr;

	int updateRoute(std::string cmd, const std::string &xid, int port, const std::string &next, unsigned long flags);
	string itoa(signed);
};

typedef struct {
	std::string dest;	// destination AD or HID
	std::string nextHop;	// nexthop HID
	int32_t port;		// interface (outgoing port)
	uint32_t flags;	// flag
} RouteEntry;

typedef struct {
	std::string AD;		// neigbor AD
	std::string HID;	// neighbor HID
	int32_t cost; 		// link cost
	int32_t port;		// interface (outgoing port)
} NeighborEntry;


typedef struct {
	std::string dest;	// destination AD or HID
	int32_t num_neighbors;	// number of neighbors of dest AD
	std::vector<std::string> neighbor_list; // neighbor AD list

	bool checked;	// used for calculating the shortest path
	int32_t cost;	// cost from myAD to destAD
	std::string prevNode; // previous node along the shortest path from myAD to destAD

} NodeStateEntry; // extracted from incoming LSA

typedef struct RouteState {
	int32_t sock; // socket for routing process

	sockaddr_x sdag;
	sockaddr_x ddag;

	char myAD[MAX_XID_SIZE]; // this router AD
	char myHID[MAX_XID_SIZE]; // this router HID
	char my4ID[MAX_XID_SIZE]; // not used

	uint32_t flags;
	std::string dual_router_AD; // AD (with dual router) -- default AD for 4ID traffic
	int32_t num_neighbors; // number of neighbor routers
	int32_t hello_lsa_ratio; // frequency ratio of hello:lsa (for timer purpose)
	int32_t calc_dijstra_ticks;

	std::map<std::string, RouteEntry> ADrouteTable; // map DestAD to route entry
	std::map<std::string, RouteEntry> HIDrouteTable; // map DestHID to route entry

	std::map<std::string, NeighborEntry> neighborTable; // map neighborAD to neighbor entry

	std::map<std::string, NodeStateEntry> networkTable; // map DestAD to NodeState entry

} RouteState;



class XIAOverlayRouted : public Element {

public:

	XIAOverlayRouted();
	~XIAOverlayRouted();

	const char *class_name() const { return "XIAOverlayRouted"; }
	const char *port_count() const { return "1/1"; }
	const char *processing() const { return PUSH; }

	void push(int, Packet *);

};

CLICK_ENDDECLS
#endif
