#include <fcntl.h>
#include <string>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "controller.h"
#include <iostream>
#include "logger.h"
#include "Xsocket.h"
#include "Xkeys.h"
#include "dagaddr.hpp"
#include "dagaddr.h"
#include "xcache_sock.h"
#include "cid.h"
#include <openssl/sha.h>

#define IGNORE_PARAM(__param) ((void)__param)

#define MAX_XID_SIZE 100

enum {
	RET_FAILED = -1,
	RET_OK,
	RET_SENDRESP,
	RET_NORESP,
	RET_REMOVEFD,
	RET_ENQUEUE,
};

DEFINE_LOG_MACROS(CTRL)

static int send_response(int fd, const char *buf, size_t len)
{
	int ret = 0;
	uint32_t msg_length = htonl(len);

	ret = send(fd, &msg_length, 4, 0);
	if(ret <= 0)
		return ret;

	ret = send(fd, buf, len, 0);
	return ret;
}

static std::string hex_str(unsigned char *data, int len)
{
	char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
			 '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	std::string s(len * 2, ' ');
	for (int i = 0; i < len; ++i) {
		s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
		s[2 * i + 1] = hexmap[data[i] & 0x0F];
	}
	return s;
}

static std::string compute_cid(const char *data, size_t len)
{
	unsigned char digest[SHA_DIGEST_LENGTH];

	SHA1((unsigned char *)data, len, digest);

	return hex_str(digest, SHA_DIGEST_LENGTH);
}

static int xcache_create_lib_socket(void)
{
	struct sockaddr_un my_addr;
	int s;
	char socket_name[512];

	s = socket(AF_UNIX, SOCK_STREAM, 0);

	my_addr.sun_family = AF_UNIX;
	if(get_xcache_sock_name(socket_name, 512) < 0) {
		return -1;
	}

	remove(socket_name);

	strcpy(my_addr.sun_path, socket_name);

	bind(s, (struct sockaddr *)&my_addr, sizeof(my_addr));

	// FIXME: ! this is a bit of a security issue as it's making the xcache
	// socket open to everyone. The alternate is to run client side apps as
	// root which is a pain. It might be better to just change things to use
	// normal sockets on localhost.
	chmod(socket_name, 0x777);

	listen(s, 100);

	return s;
}

void xcache_controller::status(void)
{
	LOG_CTRL_INFO("[Status]\n");
}

int xcache_controller::fetch_content_remote(sockaddr_x *addr, socklen_t addrlen,
					    xcache_cmd *resp, xcache_cmd *cmd,
					    int flags)
{
	int to_recv, recvd, sock;
	Graph g(addr);

	LOG_CTRL_INFO("Fetching content from remote DAG = %s\n",
		      g.dag_string().c_str());

	sock = Xsocket(AF_XIA, SOCK_STREAM, 0);
	if(sock < 0) {
		LOG_CTRL_INFO("Can't create socket\n");
		return RET_FAILED;
	}

	if (Xconnect(sock, (struct sockaddr *)addr, addrlen) < 0) {
		LOG_CTRL_INFO("Errno = %d\n", errno);
		return RET_FAILED;
	}

	LOG_CTRL_INFO("Xcache client now connected with remote\n");

	std::string data;
	char buf[1024*1024] = {0};
	struct cid_header header;
	size_t remaining;
	size_t offset;

	Node expected_cid(g.get_final_intent());
	xcache_meta *meta = new xcache_meta(expected_cid.id_string());

	meta->set_FETCHING();

	remaining = sizeof(cid_header);
	offset = 0;

	while (remaining > 0) {
		LOG_CTRL_ERROR("1 Remaining = %d\n", remaining);
		recvd = Xrecv(sock, (char *)&header + offset, remaining, 0);
		if (recvd < 0) {
			LOG_CTRL_ERROR("Sender Closed the connection - Header"
				       ".\n");
			assert(0);
			Xclose(sock);
		} else if (recvd == 0) {
			break;
		}
		remaining -= recvd;
		offset += recvd;
	}

	remaining = ntohl(header.length);


	while (remaining > 0) {
		to_recv = remaining > 1024*1024 ? 1024 * 1024 : remaining;

		LOG_CTRL_ERROR("2 Remaining = %d\n", remaining);

		recvd = Xrecv(sock, buf, to_recv, 0);
		LOG_CTRL_ERROR("recvd = %d, to_recv = %d\n", recvd, to_recv);
		if (recvd < 0) {
			LOG_CTRL_ERROR("Receiver Closed the connection - Header"
				       ".\n");
			assert(0);
			Xclose(sock);
		} else if (recvd == 0) {
			LOG_CTRL_ERROR("Xrecv returned 0.\n");
			break;
		}

		remaining -= recvd;
		std::string temp(buf, recvd);

		data += temp;
	}

	std::string computed_cid = compute_cid(data.c_str(), data.length());
	struct xcache_context *context = lookup_context(cmd->context_id());

	if (!context) {
		LOG_CTRL_ERROR("Context Lookup Failed\n");
		delete meta;
		Xclose(sock);
		return RET_FAILED;
	}

	if (!(flags & XCF_SKIPCACHE)) {
		if (__store(context, meta, (const std::string *)&data) == RET_FAILED) {
			delete meta;
			Xclose(sock);
			return RET_FAILED;
		}
	} else {
		if (verify_content(meta, (const std::string *)&data) == false) {
			delete meta;
			Xclose(sock);
			return RET_FAILED;
		}
	}

	if (resp) {
		resp->set_cmd(xcache_cmd::XCACHE_RESPONSE);
		resp->set_data(data);
	}

	LOG_CTRL_ERROR("%s: Xclosing\n", __func__);
	Xclose(sock);

	return RET_OK;
}

int xcache_controller::fetch_content_local(sockaddr_x *addr, socklen_t addrlen,
					   xcache_cmd *resp, xcache_cmd *cmd,
					   int flags)
{
	xcache_meta *meta;
	std::string data;
	Graph g(addr);
	Node expected_cid(g.get_final_intent());
	std::string cid(expected_cid.id_string());

	IGNORE_PARAM(flags);
	IGNORE_PARAM(addrlen);
	IGNORE_PARAM(cmd);

	meta = acquire_meta(cid);
	LOG_CTRL_INFO("Fetching content %s from local\n",
		      expected_cid.id_string().c_str());

	LOG_CTRL_INFO("Here %d", __LINE__);
	if(!meta) {
		LOG_CTRL_INFO("Here %d", __LINE__);
		/* We could not find the content locally */
		return RET_FAILED;
	}

	if(!meta->is_AVAILABLE()) {
		LOG_CTRL_INFO("Here %d", __LINE__);
		release_meta(meta);
		LOG_CTRL_INFO("Here %d", __LINE__);
		return RET_FAILED;
	}

	LOG_CTRL_INFO("Getting data by calling meta->get()\n");
	data = meta->get();

	if(resp) {
		resp->set_cmd(xcache_cmd::XCACHE_RESPONSE);
		resp->set_data(data);
	}

	LOG_CTRL_INFO("Releasing meta\n");

	release_meta(meta);

	LOG_CTRL_INFO("Fetching content from local DONE\n");

	return RET_OK;
}

int xcache_controller::xcache_notify(struct xcache_context *c, sockaddr_x *addr,
				     socklen_t addrlen, int event)
{
	xcache_notif notif;
	std::string buffer("");

	notif.set_cmd(event);
	notif.set_dag(addr, addrlen);
	notif.SerializeToString(&buffer);

	LOG_CTRL_INFO("Sent Notification to %d\n", c->notifSock);

	return send_response(c->notifSock, buffer.c_str(), buffer.length());
}

struct __fetch_content_args {
	xcache_controller *ctrl;
	xcache_cmd *resp;
	xcache_cmd *cmd;
	int ret;
	int flags;
};

void *xcache_controller::__fetch_content(void *__args)
{
	int ret;
	struct __fetch_content_args *args = (struct __fetch_content_args *)__args;
	sockaddr_x addr;
	size_t daglen;

	daglen = args->cmd->dag().length();
	memcpy(&addr, args->cmd->dag().c_str(), args->cmd->dag().length());

	ret = args->ctrl->fetch_content_local(&addr, daglen, args->resp,
					      args->cmd, args->flags);

	if(ret == RET_FAILED) {
		ret = args->ctrl->fetch_content_remote(&addr, daglen, args->resp,
						       args->cmd, args->flags);
		if (ret == RET_FAILED) {
			LOG_CTRL_INFO("Remote content fetch failed: %d\n", ret);
			args->resp->set_cmd(xcache_cmd::XCACHE_ERROR);
		}
	}

	args->ret = ret;

	if (!(args->flags & XCF_BLOCK)) {
		/*
		 * FIXME: In case of error must notify the error
		 */
		struct xcache_context *c = args->ctrl->lookup_context(args->cmd->context_id());

		if (c)
			args->ctrl->xcache_notify(c, &addr, daglen, XCE_CHUNKARRIVED);

		// FIXME: mixing allocation methods is troublesome and prone to weird errors
		//   when you delete instead of free something that was malloc'd
		delete args->cmd;
		free(args);
	}

	return NULL;
}

int xcache_controller::xcache_fetch_content(xcache_cmd *resp, xcache_cmd *cmd,
					    int flags)
{
	int ret = 0;

	if (flags & XCF_BLOCK) {
		struct __fetch_content_args args;

		args.ctrl = this;
		args.resp = resp;
		args.cmd = cmd;
		args.ret = ret;
		args.flags = flags;
		__fetch_content(&args);
		ret = RET_SENDRESP;
	} else {
		/* FIXME: Add to worker queue */
		struct __fetch_content_args *args =
			(struct __fetch_content_args *)
			malloc(sizeof(struct __fetch_content_args));

		pthread_t fetch_thread;
		args->ctrl = this;
		args->ret = ret;
		args->flags = flags;
		args->resp = NULL;
		args->cmd = new xcache_cmd(*cmd);
		pthread_create(&fetch_thread, NULL, __fetch_content, args);
		ret = RET_NORESP;
	}

	return ret;
}

std::string xcache_controller::addr2cid(sockaddr_x *addr)
{
	Graph g(addr);
	Node cid_node(g.get_final_intent());
	return cid_node.id_string();
}


int xcache_controller::chunk_read(xcache_cmd *resp, xcache_cmd *cmd)
{
	xcache_meta *meta = acquire_meta(addr2cid((sockaddr_x *)(cmd->dag().c_str())));
	std::string data;

	if(!meta) {
		resp->set_cmd(xcache_cmd::XCACHE_ERROR);
		resp->set_msg("Invalid address\n");
		return RET_SENDRESP;
	}

	data = meta->get(cmd->readoffset(), cmd->readlen());
	resp->set_cmd(xcache_cmd::XCACHE_RESPONSE);
	resp->set_data(data);

	release_meta(meta);
	return RET_SENDRESP;
}

int xcache_controller::fast_process_req(int fd, xcache_cmd *resp, xcache_cmd *cmd)
{
	int ret = RET_NORESP;
	xcache_cmd response;
	struct xcache_context *c;

	switch(cmd->cmd()) {
	case xcache_cmd::XCACHE_ALLOC_CONTEXT:
		LOG_CTRL_INFO("Received ALLOC_CONTEXTID\n");
		ret = alloc_context(resp, cmd);
		break;

	case xcache_cmd::XCACHE_FLAG_DATASOCKET:
		c = lookup_context(cmd->context_id());

		if (!c)
			LOG_CTRL_ERROR("Should Not Happen.\n");
		else
			c->xcacheSock = fd;

		break;

	case xcache_cmd::XCACHE_FLAG_NOTIFSOCK:
		c = lookup_context(cmd->context_id());
		if(!c) {
			LOG_CTRL_ERROR("Should Not Happen.\n");
		} else {
			c->notifSock = fd;
			ret = RET_REMOVEFD;
		}
		break;

	case xcache_cmd::XCACHE_STORE:
	case xcache_cmd::XCACHE_FETCHCHUNK:
	case xcache_cmd::XCACHE_READ:
		ret = RET_ENQUEUE;
		break;

	default:
		LOG_CTRL_ERROR("Unknown message received\n");
	}

	return ret;
}


struct xcache_context *xcache_controller::lookup_context(int context_id)
{
	std::map<uint32_t, struct xcache_context *>::iterator i = context_map.find(context_id);

	if(i != context_map.end()) {
		LOG_CTRL_INFO("Context found.\n");
		return i->second;
	} else {
		LOG_CTRL_INFO("Context %d NOT found.\n", context_id);
		return NULL;
	}
}

int xcache_controller::alloc_context(xcache_cmd *resp, xcache_cmd *cmd)
{
	struct xcache_context *c = (struct xcache_context *)malloc(sizeof(struct xcache_context));
	IGNORE_PARAM(cmd);
	++context_id;

	resp->set_cmd(xcache_cmd::XCACHE_RESPONSE);
	resp->set_context_id(context_id);

	memset(c, 0, sizeof(struct xcache_context));
	c->contextID = context_id;
	context_map[context_id] = c;
	LOG_CTRL_INFO("Allocated Context %d\n", resp->context_id());

	return RET_SENDRESP;
}

int xcache_controller::__store_policy(xcache_meta *meta)
{
	IGNORE_PARAM(meta);
	//FIXME: Add code
	return 0;
}

bool xcache_controller::verify_content(xcache_meta *meta, const std::string *data)
{
	if (meta->get_cid() != compute_cid(data->c_str(), data->length()))
		return false;

	return true;
}

int xcache_controller::__store(struct xcache_context * /*context */,
			       xcache_meta *meta, const std::string *data)
{
	lock_meta_map();
	meta->lock();

	if (verify_content(meta, data) == false) {
		/*
		 * Content Verification Failed
		 */
		LOG_CTRL_ERROR("Content Verification Failed\n");
		meta->unlock();
		unlock_meta_map();
		return RET_FAILED;
	}

	meta_map[meta->get_cid()] = meta;

	if (__store_policy(meta) < 0) {
		LOG_CTRL_ERROR("Context store failed\n");
		meta->unlock();
		unlock_meta_map();
		return RET_FAILED;
	}

	register_meta(meta);
	store_manager.store(meta, data);

	meta->set_AVAILABLE();
	meta->unlock();
	unlock_meta_map();

	return RET_SENDRESP;
}

int xcache_controller::cid2addr(std::string cid, sockaddr_x *sax)
{
	int rc = 0;
	std::string myCid("CID:");

	struct addrinfo *ai, hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_XIA;
	hints.ai_flags = XAI_FALLBACK;

	myCid += cid;
	if (Xgetaddrinfo(NULL, myCid.c_str(), &hints, &ai) >= 0) {
		if (ai->ai_addr) {
			memcpy(sax, ai->ai_addr, sizeof(sockaddr_x));
		} else {
			rc = -1;
		}

		Xfreeaddrinfo(ai);
	} else {
		rc = -1;
	}

	return rc;
}

int xcache_controller::store(xcache_cmd *resp, xcache_cmd *cmd)
{
	struct xcache_context *context;
	xcache_meta *meta;
	std::string cid = compute_cid(cmd->data().c_str(), cmd->data().length());

	meta = acquire_meta(cid);

	if (meta != NULL) {
		/*
		 * Meta already exists
		 */
		resp->set_status(xcache_cmd::XCACHE_ERR_EXISTS);
		release_meta(meta);
	} else {
		/*
		 * New object - Allocate a meta
		 */
		meta = new xcache_meta(cid);

		context = lookup_context(cmd->context_id());
		if(!context) {
			return RET_FAILED;
		}

		if(__store(context, meta, &cmd->data()) == RET_FAILED) {
			return RET_FAILED;
		}
	}

	resp->set_cmd(xcache_cmd::XCACHE_RESPONSE);

	sockaddr_x addr;

	if (cid2addr(cid, &addr) == 0) {
		resp->set_dag((char *)&addr, sizeof(sockaddr_x));
		Graph g(&addr);
		printf("--------------------\n");
		g.print_graph();
	} else {
		// FIXME: do some sort of error handling here
	}

	LOG_CTRL_INFO("Store Finished\n");

	return RET_SENDRESP;
}


void xcache_controller::send_content_remote(int sock, sockaddr_x *mypath)
{
	Graph g(mypath);
	Node cid(g.get_final_intent());
	xcache_cmd resp;

	LOG_CTRL_INFO("CID = %s\n", cid.id_string().c_str());

	if (fetch_content_local(mypath, sizeof(sockaddr_x), &resp, NULL, 0) != RET_OK) {
		LOG_CTRL_ERROR("This should not happen.\n");
		assert(0);
	}

	struct cid_header header;
	size_t remaining;
	size_t offset;
	int sent;

	header.length = htonl(resp.data().length());
	remaining = sizeof(header);
	offset = 0;

	LOG_CTRL_INFO("Header Send Start\n");

	while (remaining > 0) {
		sent = Xsend(sock, (char *)&header + offset, remaining, 0);
		if (sent < 0) {
			LOG_CTRL_ERROR("Receiver Closed the connection - Header"
				       ".\n");
			assert(0);
			Xclose(sock);
		}
		remaining -= sent;
		offset += sent;
		LOG_CTRL_INFO("Header Send Remaining %d\n", remaining);

	}

	remaining = resp.data().length();
	offset = 0;

	LOG_CTRL_INFO("Content Send Start\n");

	while (remaining > 0) {
		sent = Xsend(sock, (char *)resp.data().c_str() + offset,
			     remaining, 0);
		LOG_CTRL_INFO("Sent = %d\n", sent);
		if (sent < 0) {
			LOG_CTRL_ERROR("Receiver Closed the connection - Data"
				       ".\n");
			assert(0);
			Xclose(sock);
		}
		remaining -= sent;
		offset += sent;
		LOG_CTRL_INFO("Content Send Remaining %d\n", remaining);
	}
	LOG_CTRL_INFO("Send Done\n");

}

int xcache_controller::create_sender(void)
{
	char sid_string[strlen("SID:") + XIA_SHA_DIGEST_STR_LEN];
	int xcache_sock;
	struct addrinfo *ai;

	if ((xcache_sock = Xsocket(AF_XIA, SOCK_STREAM, 0)) < 0)
		return -1;

	if (XmakeNewSID(sid_string, sizeof(sid_string))) {
		LOG_CTRL_ERROR("XmakeNewSID failed\n");
		return -1;
	}

	if (XsetXcacheSID(xcache_sock, sid_string, strlen(sid_string)) < 0)
		return -1;

	LOG_CTRL_DEBUG("XcacheSID is %s\n", sid_string);

	if (Xgetaddrinfo(NULL, sid_string, NULL, &ai) != 0)
		return -1;

	sockaddr_x *dag = (sockaddr_x *)ai->ai_addr;

	if (Xbind(xcache_sock, (struct sockaddr*)dag, sizeof(dag)) < 0) {
		Xclose(xcache_sock);
		Xfreeaddrinfo(ai);
		return -1;
	}

	Xlisten(xcache_sock, 5);

	Graph g(dag);
	LOG_CTRL_INFO("Listening on dag: %s\n", g.dag_string().c_str());

	Xfreeaddrinfo(ai);
	return xcache_sock;
}

int xcache_controller::register_meta(xcache_meta *meta)
{
	int rv;
	std::string empty_str("");
	std::string temp_cid("CID:");

	temp_cid += meta->get_cid();

	LOG_CTRL_DEBUG("Setting Route for %s.\n", temp_cid.c_str());
	rv = xr.setRoute(temp_cid, DESTINED_FOR_LOCALHOST, empty_str, 0);
	LOG_CTRL_DEBUG("Route Setting Returned %d\n", rv);

	return rv;
}

void xcache_controller::enqueue_request_safe(xcache_req *req)
{
	pthread_mutex_lock(&request_queue_lock);
	request_queue.push(req);
	pthread_mutex_unlock(&request_queue_lock);

	while(sem_post(&req_sem) != 0);
}

xcache_req *xcache_controller::dequeue_request_safe(void)
{
	xcache_req *ret;

	while(sem_wait(&req_sem) != 0);

	pthread_mutex_lock(&request_queue_lock);
	ret = request_queue.front();
	request_queue.pop();
	pthread_mutex_unlock(&request_queue_lock);

	return ret;
}

void xcache_controller::process_req(xcache_req *req)
{
	xcache_cmd resp, *cmd;
	int ret;
	std::string buffer;

	ret = RET_NORESP;

	switch(req->type) {
	case xcache_cmd::XCACHE_STORE:
		ret = store(&resp, (xcache_cmd *)req->data);
		if(ret == RET_SENDRESP) {
			resp.SerializeToString(&buffer);
			send_response(req->to_sock, buffer.c_str(), buffer.length());
		}
		break;
	case xcache_cmd::XCACHE_FETCHCHUNK:
		cmd = (xcache_cmd *)req->data;
		ret = xcache_fetch_content(&resp, cmd, cmd->flags());
		LOG_CTRL_INFO("xcache_fetch_content returned %d\n", ret);
		if(ret == RET_SENDRESP) {
			resp.SerializeToString(&buffer);
			send_response(req->to_sock, buffer.c_str(), buffer.length());
		}
		break;
	case xcache_cmd::XCACHE_READ:
		cmd = (xcache_cmd *)req->data;
		ret = chunk_read(&resp, cmd);
		if(ret == RET_SENDRESP) {
			resp.SerializeToString(&buffer);
			send_response(req->to_sock, buffer.c_str(), buffer.length());
		}
		break;
	case xcache_cmd::XCACHE_SENDCHUNK:
		send_content_remote(req->to_sock, (sockaddr_x *)req->data);
		break;
	}


	if (req->type == xcache_cmd::XCACHE_SENDCHUNK) {
		if (req->data) {
			free(req->data);
		}
	} else {
		if (req->data) {
			delete (xcache_cmd*)req->data;
		}
	}
	delete req;

	if(req->flags & XCFI_REMOVEFD) {
		LOG_CTRL_INFO("Closing Socket\n");
		Xclose(req->to_sock);
	}
}

/**
 * Worker thread
 * This thea
 */
void *xcache_controller::worker_thread(void *arg)
{
	xcache_controller *ctrl = (xcache_controller *)arg;

	LOG_CTRL_INFO("Worker started working.\n");

	while(1) {
		xcache_req *req;

		req = ctrl->dequeue_request_safe();
		if(req) {
			ctrl->process_req(req);
		}
	}

	return NULL;
}

void xcache_controller::run(void)
{
	fd_set fds, allfds;
	int max, libsocket, rc, sendersocket;
	struct cache_args args;

	std::vector<int> active_conns;
	std::vector<int>::iterator iter;

	/* Application interface */
	libsocket = xcache_create_lib_socket();

	/* Arguments for the cache thread */
	args.cache = &cache;
	args.cache_in_port = getXcacheInPort();
	args.cache_out_port = getXcacheOutPort();
	args.ctrl = this;

	/*
	 * Caching is performed by an independent thread
	 * Please see cache.cc for details
	 */
	cache.spawn_thread(&args);

	if((rc = xr.connect()) != 0) {
		LOG_CTRL_ERROR("Unable to connect to click %d \n", rc);
		return;
	}

	xr.setRouter(hostname);
	sendersocket = create_sender();

	FD_ZERO(&fds);
	FD_SET(libsocket, &allfds);
	FD_SET(sendersocket, &allfds);

	/* Launch all the worker threads */
	for(int i = 0; i < n_threads; i++) {
		pthread_create(&threads[i], NULL, worker_thread, (void *)this);
	}

	LOG_CTRL_INFO("Entering The Loop\n");

repeat:
	memcpy(&fds, &allfds, sizeof(fd_set));

	max = libsocket;

	/* FIXME: do something better */
	for(iter = active_conns.begin(); iter != active_conns.end(); ++iter) {
		max = MAX(max, *iter);
	}

	Xselect(max + 1, &fds, NULL, NULL, NULL);
//	LOG_CTRL_INFO("Broken\n");

	if(FD_ISSET(libsocket, &fds)) {
		int new_connection = accept(libsocket, NULL, 0);

		if (new_connection > 0) {

			active_conns.push_back(new_connection);
			FD_SET(new_connection, &allfds);
			LOG_CTRL_INFO("HEREH\n");
		}
	}

	if(FD_ISSET(sendersocket, &fds)) {
		int accept_sock;
		sockaddr_x mypath;
		socklen_t mypath_len = sizeof(mypath);

		LOG_CTRL_INFO("Accepting!\n");
		if((accept_sock = XacceptAs(sendersocket, (struct sockaddr *)&mypath,
									&mypath_len, NULL, NULL)) < 0) {
			LOG_CTRL_ERROR("XacceptAs failed\n");
		} else {
			xcache_req *req = new xcache_req();

			LOG_CTRL_INFO("XacceptAs Succeeded\n");
			/* Create a request to add to worker queue */

			/* Send chunk Request */
			req->type = xcache_cmd::XCACHE_SENDCHUNK;
			req->from_sock = sendersocket;
			req->to_sock = accept_sock;
			req->data = malloc(mypath_len);
			memcpy(req->data, &mypath, mypath_len);
			req->datalen = mypath_len;
			/* Indicates that after sending, remove the fd */
			req->flags = XCFI_REMOVEFD;

			enqueue_request_safe(req);
			LOG_CTRL_INFO("Request Enqueued\n");
		}
	}

	for(iter = active_conns.begin(); iter != active_conns.end(); ) {
		if(!FD_ISSET(*iter, &fds)) {
			++iter;
			continue;
		}

		char buf[XIA_MAXBUF];
		std::string buffer("");
		xcache_cmd resp, cmd;
		int ret;
		uint32_t msg_length, remaining;

		ret = recv(*iter, &msg_length, sizeof(msg_length), 0);
		if(ret <= 0)
			goto disconnected;

		remaining = ntohl(msg_length);

		while(remaining > 0) {
			ret = recv(*iter, buf, MIN(sizeof(buf), remaining), 0);
			LOG_CTRL_INFO("Recv returned %d, remaining = %d\n", ret, remaining);
			if(ret <= 0)
				break;

			buffer.append(buf, ret);
			remaining -= ret;
		}

		if(msg_length == 0 && ret <= 0) {
			goto disconnected;
		} else {
			bool parse_success = cmd.ParseFromString(buffer);

			LOG_CTRL_INFO("Controller received %lu bytes\n", buffer.length());
			if(!parse_success) {
				LOG_CTRL_ERROR("[ERROR] Protobuf could not parse\n");
				goto next;
			}
		}

		/*
		 * Try to see if we can process request in the fast path
		 */
		ret = fast_process_req(*iter, &resp, &cmd);

		if(ret == RET_SENDRESP) {
			/*
			 * Send response back to the client
			 */
			resp.SerializeToString(&buffer);
			if(send_response(*iter, buffer.c_str(), buffer.length()) < 0) {
				LOG_CTRL_ERROR("FIXME: handle return value of write\n");
			} else {
				LOG_CTRL_INFO("Data sent to client\n");
			}
		} else if(ret == RET_REMOVEFD) {
			/* Remove this fd from the pool */
			goto removefd;
		} else if(ret == RET_ENQUEUE) {
			/*
			 * Fast path processing not possible:
			 * Enqueue the request into worker queue
			 */
			xcache_req *req = new xcache_req();

			req->type = cmd.cmd();
			req->from_sock = *iter;
			req->to_sock = *iter;
			req->data = new xcache_cmd(cmd);
			req->datalen = sizeof(xcache_cmd);

			enqueue_request_safe(req);
		}

next:
		++iter;
		continue;

disconnected:
		LOG_CTRL_DEBUG("Client %d disconnected.\n", *iter);
		close(*iter);
removefd:
		FD_CLR(*iter, &allfds);
		active_conns.erase(iter);
	}

	goto repeat;
}

xcache_meta *xcache_controller::acquire_meta(std::string cid)
{
	lock_meta_map();

	std::map<std::string, xcache_meta *>::iterator i = meta_map.find(cid);
	if(i == meta_map.end()) {
		/* We could not find the content locally */
		unlock_meta_map();
		return NULL;
	}

	xcache_meta *meta = i->second;
	meta->lock();

	return meta;

}

void xcache_controller::release_meta(xcache_meta *meta)
{
	unlock_meta_map();
	if(meta)
		meta->unlock();
}

inline int xcache_controller::lock_meta_map(void)
{
	return pthread_mutex_lock(&meta_map_lock);
}

inline int xcache_controller::unlock_meta_map(void)
{
	return pthread_mutex_unlock(&meta_map_lock);
}

void xcache_controller::add_meta(xcache_meta *meta)
{
	lock_meta_map();
	meta_map[meta->get_cid()] = meta;
	unlock_meta_map();
}

void xcache_controller::set_conf(struct xcache_conf *conf)
{
	hostname = std::string(conf->hostname);

	n_threads = conf->threads;
	threads = (pthread_t *)malloc(sizeof(pthread_t) * conf->threads);
}