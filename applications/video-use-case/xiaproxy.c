#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <pthread.h>
#include <unistd.h>
#include <algorithm>

#include "utils.h"
#include "csapp.h"

#include "xiaproxy.h"
#include "Xsocket.h"
#include "xcache.h"
#include "cdn.pb.h"
#include "minIni.h"
#include "dagaddr.hpp"

#define APPNAME "xiaproxy"

static int port = 0;                    // port this server runs on
static int reuseaddr = 1;               // need to reuse the address for binding
static int list_s;                      // listening socket of this proxy
static XcacheHandle xcache;             // xcache instance

static int locator_interval = 5;
static int scorer_interval  = 5;
static int alive            = 1;

static int num_clients      = 1;

static char hostname[64];
static char *ident = NULL;

static struct addrinfo *broker_addr;

// these variables all need to be protected by a mutex when accessed!
//static std::string cdn_ad;
//static std::string cdn_hid;
//static std::string cdn_host;
//static CDNStatistics cdn_stats;
//uint32_t last_bandwidth = 0;
//pthread_mutex_t cdn_lock       = PTHREAD_MUTEX_INITIALIZER;
ClientState client_state;


// for proxy http header back to the browser
static const char *http_chunk_header_status_ok        = "HTTP/1.0 200 OK\r\n";
static const char *http_chunk_header_end_marker       = "\r\n";
static const char *http_chunk_header_same_origin      = "Access-Control-Allow-Origin: *\r\n";
static const char *http_chunk_header_date_fmt         = "Date: %a, %d %b %Y %H:%M:%S %Z\r\n";
static const char *http_chunk_header_server           = "Server: XIA Video Proxy\r\n";

static const char *http_header_allow_headers          = "Access-Control-Allow-Headers: range\r\n";
static const char *http_header_allow_methods          = "Access-Control-Allow-Methods: GET, POST, PUT\r\n";

static const char *bandwidth_str                      = "bandwidth";
static const char *client_str                         = "client";

static const char *connection_str                     = "Connection: close\r\n";

// http DASH header for videos
static const char *http_chunk_header_mp4_content_type = "Content-Type: application\r\n";
static const char *http_chunk_header_mpd_content_type = "Content-Type: application\r\n";



void *cdn_locator(void *)
{
	int sock;
	int rc;
	char buf[2048];

	while (alive) {
		for (int i = 0; i < num_clients; i++) {

			std::string hname = client_state[i].hostname;
			syslog(LOG_DEBUG, "fetching best cdn for %s", hname.c_str());

			if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
				syslog(LOG_ERR, "can't create broker sock: %s", strerror(errno));
				exit(EXIT_FAILURE);

			}

			connect(sock, broker_addr->ai_addr, sizeof(struct sockaddr));

			CDN::CDNMsg msg;
			msg.Clear();
			msg.set_type(CDN::CDN_REQUEST_MSG);
			msg.set_version(CDN::CDN_PROTO_VERSION);
			msg.set_client(hname);

			// fIXME: move the xfer scores to this?
			CDN::Request *req_msg = msg.mutable_request();

			if (pthread_mutex_lock(&client_state[i].cdn_lock)) {
				syslog(LOG_ERR, "cdn_mutex lock error: %s", strerror(errno));
				exit(EXIT_FAILURE);
			}
			req_msg->set_last_cdn(client_state[i].cdn_host);
			req_msg->set_bandwidth(client_state[i].last_bandwidth);
			pthread_mutex_unlock(&client_state[i].cdn_lock);

			string message;
			msg.SerializeToString(&message);
			unsigned len = message.length();
			unsigned msg_len = htonl(len);

			if ((rc = send(sock, &msg_len, 4, 0)) > 0) {
				if ((rc = send(sock, message.c_str(), len, 0)) > 0) {
					if ((rc = recv(sock, &msg_len, 4, 0) > 0)) {
						len = ntohl(msg_len);
						rc = recv(sock, buf, sizeof(buf), 0);
					}
				}
			}

			close(sock);

			if (rc > 0) {
				msg.Clear();
				std::string result(buf, rc);
				msg.ParseFromString(result);

				CDN::Reply *reply_msg = msg.mutable_reply();
				reply_msg = msg.mutable_reply();

				// lock mutex
				if (pthread_mutex_lock(&client_state[i].cdn_lock)) {
					syslog(LOG_ERR, "cdn_mutex lock error: %s", strerror(errno));
					exit(EXIT_FAILURE);
				}

				client_state[i].cdn_ad = reply_msg->ad();
				client_state[i].cdn_hid = reply_msg->hid();
				client_state[i].cdn_host = reply_msg->cluster();
				pthread_mutex_unlock(&client_state[i].cdn_lock);

				syslog(LOG_NOTICE, "New CDN: %s (RE %s %s)", client_state[i].cdn_host.c_str(), client_state[i].cdn_ad.c_str(), client_state[i].cdn_hid.c_str());
			} else {
				syslog(LOG_ERR, "CDN update failed: %s", strerror(errno));
			}
		}

		sleep(locator_interval);
	}

	return NULL;
}



void *cdn_scores(void *)
{
	while (alive) {
		for (int i = 0; i < num_clients; i++) {
			syslog(LOG_DEBUG, "updating tput scores for %s", client_state[i].hostname.c_str());

			if (client_state[i].cdn_stats.size() == 0) {
				syslog(LOG_NOTICE, "no new tput records, skipping...");

			} else {
				int sock;
				int rc;

				if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
					syslog(LOG_ERR, "can't create broker sock: %s", strerror(errno));
					exit(EXIT_FAILURE);
				}

				connect(sock, broker_addr->ai_addr, sizeof(struct sockaddr));

				CDN::CDNMsg msg;
				msg.Clear();
				msg.set_type(CDN::STATS_SCORE_MSG);
				msg.set_version(CDN::CDN_PROTO_VERSION);
				msg.set_client(client_state[i].hostname);

				CDN::Scores *scores_msg = msg.mutable_scores();

				if (pthread_mutex_lock(&client_state[i].cdn_lock)) {
					syslog(LOG_ERR, "cdn_mutex lock error: %s", strerror(errno));
					exit(EXIT_FAILURE);
				}

				for (CDNStatistics::iterator it = client_state[i].cdn_stats.begin(); it != client_state[i].cdn_stats.end(); it++) {
					CDNStats stats = it->second.stats;

					CDN::Cluster *c = scores_msg->add_clusters();
					c->set_name(it->first);

					for (CDNStats::iterator it2 = stats.begin(); it2 != stats.end(); it2++) {
						CDN::Stats *s = c->add_stats();
						s->set_cached(it2->cached);
						s->set_bandwidth(it2->bandwidth);
						s->set_size(it2->size);
						s->set_elapsed(it2->elapsed);
						s->set_tput(it2->tput);
					}
					stats.clear();
				}
				client_state[i].cdn_stats.clear();

				pthread_mutex_unlock(&client_state[i].cdn_lock);

				string message;
				msg.SerializeToString(&message);
				unsigned len = message.length();
				unsigned msg_len = htonl(len);

				if((rc = send(sock, &msg_len, 4, 0)) > 0) {
					rc = send(sock, message.c_str(), len, 0);
				}

				if (rc < 0) {
					syslog(LOG_ERR, "Failure sending updated scores %s", strerror(errno));
				}
				close(sock);
			}
		}

		sleep(scorer_interval);
	}
	return NULL;
}



int run_broker_threads()
{
	char s[2048];

	if (XrootDir(s, sizeof(s)) == NULL) {
		return -1;
	}
	strncat(s, "/etc/scenario.conf", sizeof(s)-1);

	minIni ini(s);
	std::string addr = ini.gets("broker", "address");
	std::string port = ini.gets("broker", "port");

	getaddrinfo(addr.c_str(), port.c_str(), NULL, &broker_addr);

	int rc = 0;
	// start new thread to query for best cdn
	pthread_t locator;
	if (pthread_create(&locator, NULL, cdn_locator, NULL)) {
		syslog(LOG_ERR, "can't create broker thread: %s", strerror(errno));
		rc = 1;
	}

	// start new thread to query for best cdn
	pthread_t scorer;
	if (pthread_create(&scorer, NULL, cdn_scores, NULL)) {
		syslog(LOG_ERR, "can't create broker thread: %s", strerror(errno));
		rc = 1;
	}
	return rc;
}



void help(const char *name)
{
	printf("\nusage: %s [-l level] [-v] port\n", name);
	printf("where:\n");
	printf(" -n clients  : # of clients running on the host\n");
	printf(" -l level    : syslog logging level 0 = LOG_EMERG ... 7 = LOG_DEBUG (default=3:LOG_ERR)\n");
	printf(" -v          : log to the console as well as syslog\n");
	printf(" port        : port to accept proxy requests on\n");
	printf("\n");
	exit(0);
}



void config(int argc, char** argv)
{
	int c;
	unsigned level = 3;
	int verbose = 0;

	opterr = 0;

	while ((c = getopt(argc, argv, "n:l:v")) != -1) {
		switch (c) {
			case 'n':
				num_clients = MAX(1, atoi(optarg));
				break;
			case 'l':
				level = MIN(atoi(optarg), LOG_DEBUG);
				break;
			case 'v':
				verbose = LOG_PERROR;
				break;
			case '?':
			default:
				// Help Me!
				help(basename(argv[0]));
				break;
		}
	}

	if (optind != argc - 1) {
		printf("Invalid # of parameters\n");
		help(basename(argv[0]));
	} else {
		port = atoi(argv[optind]);
		if (port == 0) {
			printf("Invalid port #\n");
			help(basename(argv[0]));
		}
	}

	// note: ident must exist for the life of the app
	ident = (char *)calloc(strlen (APPNAME) + 4, 1);
	sprintf(ident, "%s", APPNAME);
	openlog(ident, LOG_CONS|LOG_NDELAY|verbose, LOG_LOCAL4);
	setlogmask(LOG_UPTO(level));
}



void cleanup(int)
{
	alive = 0;

	// FIXME: this really shouldn't be done in an interrupt handler
	// try to close the listening socket
	if (close(list_s) < 0) {
		syslog(LOG_ERR, "Error calling close()");
		exit(EXIT_FAILURE);
	}

	// exit with success
	exit(EXIT_SUCCESS);
}



void close_fd(int browser_sock)
{
	if (browser_sock >= 0) {
		Close(browser_sock);
		syslog(LOG_DEBUG, "browser socket is closed successfully");
	}
}



vector<string> split_string_on_delimiter(char* str, char* delimiter)
{
	vector<string> result;

	char * pch;
	pch = strtok (str, delimiter);
	while (pch != NULL) {
		result.push_back(pch);
		pch = strtok (NULL, delimiter);
	}

	return result;
}



bool was_cached(sockaddr_x *requested, sockaddr_x *actual)
{
	Graph g_req(requested);
	Graph g_act(actual);
	bool rc;

	if ((g_req.intent_HID().equal_to(g_act.intent_HID())) &&
		(g_req.intent_AD().equal_to(g_act.intent_AD()))) {
		rc = false;

	} else {
		rc = true;
	}

	return rc;
}



/**
 * get the xia socket to service identified by the sname
 * @param  sname service name
 */
int get_xia_socket_for_request(const char* sname)
{
	int xia_sock;
	sockaddr_x dag;
	socklen_t daglen;

	daglen = sizeof(dag);

	// get the service DAG associated with the CDN service name
	if (XgetDAGbyName(sname, &dag, &daglen) < 0) {
		syslog(LOG_WARNING, "unable to locate CDN DNS service name: %s", sname);
		return -1;
	}

	if ((xia_sock = Xsocket(AF_XIA, SOCK_STREAM, 0)) < 0) {
		syslog(LOG_WARNING, "Unable to create the listening socket");
		return -1;
	}

	if (Xconnect(xia_sock, (struct sockaddr*)&dag, daglen) < 0) {
		Xclose(xia_sock);
		syslog(LOG_WARNING, "Unable to bind to %s", sname);
		return -1;
	}

	return xia_sock;
}



int send_command(ProxyRequestCtx *ctx, const char *cmd)
{
	int n;
	if ((n = Xsend(ctx->xia_sock, cmd, strlen(cmd), 0)) < 0) {
		Xclose(ctx->xia_sock);
		syslog(LOG_WARNING, "Unable to communicate");
		return -1;
	}
	return 1;
}



int get_server_reply(ProxyRequestCtx *ctx, char *reply, int sz)
{
	int n = -1;
	if ((n = Xrecv(ctx->xia_sock, reply, sz, 0))  < 0) {
		Xclose(ctx->xia_sock);
		syslog(LOG_WARNING, "Unable to communicate with the server");
		return -1;
	}

	reply[n] = 0;

	return n;
}



int send_and_receive_reply(ProxyRequestCtx *ctx, char* cmd, char* reply)
{
	int status = send_command(ctx, cmd);

	if (get_server_reply(ctx, reply, XIA_MAXBUF) < 1) {
		syslog(LOG_WARNING, "could not get chunk count. Aborting.");
		return -1;
	}
	return status;
}



void parse_host_port(char *host_port, char *remote_host, char *remote_port)
{
	char *tmp = NULL;
	tmp = index(host_port, ':');
	if (tmp != NULL) {
		*tmp = '\0';
		strcpy(remote_port, tmp + 1);
	} else {
		strcpy(remote_port, "80");
	}
	strcpy(remote_host, host_port);
}



void process_urls_to_DAG(ProxyRequestCtx *ctx, vector<string> & dagUrls, sockaddr_x* chunkAddresses)
{
	//process the dags
	for (unsigned i = 0; i < dagUrls.size(); ++i) {
		string dagUrl = dagUrls[i];

		// make sure it looks like a dag url
		size_t found = dagUrl.find("http://");
		if (found == string::npos) {
			std::transform(dagUrl.begin(), dagUrl.end(), dagUrl.begin(), ::toupper);
			dagUrl = "http://" + dagUrl;
		}

		Graph incoming(dagUrl);

		// if it's just a cid, make dag using current best cdn
		if (incoming.num_nodes() == 1 && incoming.get_final_intent().type() == XID_TYPE_CID) {

			char d[256];

			Node cid = incoming.intent_CID();

			// *--------------------------------->CID
			//  \-------->AD---------------------/
			//             \---->HID------------/
			sprintf(d, "DAG 2 0 - %s 2 1 - %s 2 - %s", ctx->ad.c_str(), ctx->hid.c_str(), cid.to_string().c_str());
			syslog(LOG_NOTICE, "fetching %s", d);

			Graph modified(d);
			modified.fill_sockaddr(&chunkAddresses[i]);

		} else {
			// it's a full dag, so just use it
			incoming.fill_sockaddr(&chunkAddresses[i]);
			incoming.print_graph();
		}
	}
}



/**
 * hacky way to allow cross origin requests in javascript
 */
int handle_cross_origin_probe(ProxyRequestCtx *ctx)
{
	if (Rio_writen(ctx->browser_sock, (char*)http_chunk_header_status_ok, strlen(http_chunk_header_status_ok)) == -1 ||
		Rio_writen(ctx->browser_sock, (char*)http_chunk_header_same_origin, strlen(http_chunk_header_same_origin)) == -1 ||
		Rio_writen(ctx->browser_sock, (char*)http_header_allow_headers, strlen(http_header_allow_headers)) == -1 ||
		Rio_writen(ctx->browser_sock, (char*)http_header_allow_methods, strlen(http_header_allow_methods)) == -1 ||
		Rio_writen(ctx->browser_sock, (char*)http_chunk_header_end_marker, strlen(http_chunk_header_end_marker)) == -1) {

		syslog(LOG_WARNING, "unable to forward the http status ok");
		return -1;
	}

	return 1;
}



int forward_http_response_body_to_client(ProxyRequestCtx *ctx, char* data, int len)
{
	if (Rio_writen(ctx->browser_sock, data, len) < 0) {
		syslog(LOG_WARNING, "problem with rio write when write data");
		return -1;
	}

	return 0;
}



int forward_http_header_to_client(ProxyRequestCtx *ctx, int type)
{
	// forward status line (should be OK if chunk is retrieved correctly)
	if (Rio_writen(ctx->browser_sock, (char*)http_chunk_header_status_ok, strlen(http_chunk_header_status_ok)) == -1) {
		syslog(LOG_WARNING, "unable to forward the http status ok");
		return -1;
	}

	// forward the Date field
	char http_chunk_header_date[MAXLINE];
	time_t now = time(0);
	struct tm tm = *gmtime(&now);
	strftime(http_chunk_header_date, sizeof(http_chunk_header_date), http_chunk_header_date_fmt, &tm);
	if (Rio_writen(ctx->browser_sock, http_chunk_header_date, strlen(http_chunk_header_date)) == -1) {
		syslog(LOG_WARNING, "unable to forward the http header date");
		return -1;
	}

	// forward the content-type field
	if (type == CONTENT_MANIFEST) {
		if (Rio_writen(ctx->browser_sock, (char*)http_chunk_header_mpd_content_type, strlen(http_chunk_header_mpd_content_type)) == -1) {
			syslog(LOG_WARNING, "unable to forward the http header content type");
			return -1;
		}
	} else if (type == CONTENT_STREAM) {
		if (Rio_writen(ctx->browser_sock, (char*)http_chunk_header_mp4_content_type, strlen(http_chunk_header_mp4_content_type)) == -1) {
			syslog(LOG_WARNING, "unable to forward the http header content type");
			return -1;
		}
	} else {
		syslog(LOG_WARNING, "unknown content type!! ");
		return -1;
	}

	// forward the connection field
	if (Rio_writen(ctx->browser_sock, (char*)connection_str, strlen(connection_str)) == -1) {
		syslog(LOG_WARNING, "unable to forward the http status line");
		return -1;
	}

	// forward the server field
	if (Rio_writen(ctx->browser_sock, (char*)http_chunk_header_server, strlen(http_chunk_header_server)) == -1) {
		syslog(LOG_WARNING, "unable to forward the http status line");
		return -1;
	}

	// forward allowing same origin
	if (Rio_writen(ctx->browser_sock, (char*)http_chunk_header_same_origin, strlen(http_chunk_header_same_origin)) == -1) {
		syslog(LOG_WARNING, "unable to forward the http same origin line");
		return -1;
	}

	// finally terminate with \r\n
	if (Rio_writen(ctx->browser_sock, (char*)http_chunk_header_end_marker, strlen(http_chunk_header_end_marker)) == -1) {
		syslog(LOG_WARNING, "unable to forward the http status line");
		return -1;
	}

	return 0;
}



/**
 * sent back the chunks in DAG identified by chunkAddresses back to the browser with
 * the socket back to the browser.
 *
 * @param  ctx            has the browser socket
 * @param  chunkAddresses DAG addresses of the chunks
 */
int forward_chunks_to_client(ProxyRequestCtx *ctx, sockaddr_x* chunkAddresses, int numChunks)
{
	int len = -1, totalBytes = 0;
	double elapsed, elapsed2;
	char *data = NULL;
	struct timeval t1, t2;
	sockaddr_x src_addr;
	socklen_t  src_len = sizeof(sockaddr_x);
	int id = ctx->id;

	// FIXME: there's no reason for this loop, we'll only ever get 1 chunk at a time
	for (int i = 0; i < numChunks; i++) {

		gettimeofday(&t1, NULL);
		if ((len = XfetchChunkAndSource(&xcache, (void**)&data, XCF_BLOCK, &chunkAddresses[i], sizeof(chunkAddresses[i]), &src_addr, &src_len)) < 0) {
			syslog(LOG_ERR, "XcacheGetChunk Failed");
			if (data) {
				free(data);
			}
			return -1;
			//exit(-1);
		}

		gettimeofday(&t2, NULL);
		elapsed =  (t2.tv_sec - t1.tv_sec);
		elapsed += (t2.tv_usec - t1.tv_usec) / 1000000.0;   // us to s

		Graph g(&chunkAddresses[i]);
		bool cached = was_cached(&chunkAddresses[i], &src_addr);

		syslog(LOG_NOTICE, "fetched: %s", g.intent_CID_str().c_str());
		syslog(LOG_NOTICE, "bandwidth: %u", ctx->bandwidth);
		syslog(LOG_NOTICE, "cached: %s", cached ? "true" : "false");
		syslog(LOG_NOTICE, "size: %u", len);
		syslog(LOG_NOTICE, "elapsed: %0.3f", elapsed);
		syslog(LOG_NOTICE, "throughput: %0.3f mbps", len / elapsed * 8 / 1000000);

		FILE *f = fopen("proxy.log", "a");
		fprintf(f, "%s: cached %s %u bytes, %0.3f s, %0.3f mbps\n", g.intent_CID_str().c_str(),
				cached ? "1" : "0", len, elapsed, len / elapsed * 8 / 1000000);
		fclose(f);

		if (ctx->bandwidth != 0) {
			CDNStat s;
			s.cached    = cached;
			s.elapsed   = elapsed;
			s.size      = len;
			s.tput      = len / elapsed;
			s.bandwidth = ctx->bandwidth;

			if (pthread_mutex_lock(&client_state[id].cdn_lock)) {
				syslog(LOG_ERR, "cdn_mutex lock error: %s", strerror(errno));
				exit(EXIT_FAILURE);
			}

			client_state[id].last_bandwidth = ctx->bandwidth;

			CDNStatistics::iterator it = client_state[id].cdn_stats.find(ctx->cdn_host);
			if (it != client_state[id].cdn_stats.end()) {
				it->second.total_requests++;
				it->second.stats.push_back(s);
			} else {
				client_state[id].cdn_stats[ctx->cdn_host].total_requests = 1;
				client_state[id].cdn_stats[ctx->cdn_host].stats.push_back(s);
			}
			pthread_mutex_unlock(&client_state[id].cdn_lock);

		}
		totalBytes += len;

		gettimeofday(&t1, NULL);
		// send to browser socket here. Once we reach here, we know it would be success
		if (forward_http_response_body_to_client(ctx, data, len) < 0) {
			syslog(LOG_ERR, "error when sending response body to the browser");
		}
		gettimeofday(&t2, NULL);
		elapsed2 = (t2.tv_sec - t1.tv_sec);
		elapsed2 += (t2.tv_usec - t1.tv_usec) / 1000000.0;   // us to s

		//syslog(LOG_INFO, "got %d bytes in %1.3f seconds", len, elapsed);
		//syslog(LOG_INFO, "forwarded in %f seconds", elapsed2);
		if (data) {
			free(data);
			data = NULL;
		}
	}

	return totalBytes;
}



int handle_manifest_requests(ProxyRequestCtx *ctx)
{
	char cmd[MAXLINE];
	char reply[MAXLINE];

	// send the request for manifest
	snprintf(cmd, MAXLINE, "xhttp://%s%s", ctx->remote_host, ctx->remote_path);
	memset(reply, '\0', sizeof(reply));
	if (send_and_receive_reply(ctx, cmd, reply) < 0) {
		return -1;
	}

	vector<string> dagUrls = split_string_on_delimiter(reply, " ");
	int numChunks = dagUrls.size();
	sockaddr_x chunkAddresses[numChunks];
	process_urls_to_DAG(ctx, dagUrls, chunkAddresses);

	if (forward_http_header_to_client(ctx, CONTENT_MANIFEST) < 0) {
		syslog(LOG_WARNING, "unable to forward manifest to client");
		return -1;
	}

	if (forward_chunks_to_client(ctx, chunkAddresses, numChunks) < 0) {
		syslog(LOG_WARNING, "unable to forward chunks to client");
		return -1;
	}
	return 1;
}



int handle_stream_requests(ProxyRequestCtx *ctx)
{
	int id = ctx->id;
	string cname;
	vector<string> dagUrls;

	if (strcasestr(ctx->remote_host, XIA_DAG_URL) != NULL) {
		dagUrls = split_string_on_delimiter(ctx->remote_host, " ");
	} else {
		return -1;
	}

	int numChunks = dagUrls.size();
	sockaddr_x chunkAddresses[numChunks];

	ctx->cdn_host = client_state[id].cdn_host;
	process_urls_to_DAG(ctx, dagUrls, chunkAddresses);

	if (forward_http_header_to_client(ctx, CONTENT_STREAM) < 0) {
		syslog(LOG_WARNING, "unable to forward manifest to client");
		return -1;
	}

	if (forward_chunks_to_client(ctx, chunkAddresses, numChunks) < 0) {
		syslog(LOG_WARNING, "unable to forward chunks to client");
		return -1;
	}
	return 1;
}



/**
 * parse the HTTP request header in buf
 * @param  buf       buf that contains HTTP request header
 * @param  method    HTTP header method section, should be GET
 * @param  protocol  HTTP protocol
 * @param  host_port HTTP host:port
 * @param  resource  HTTP resource section
 * @param  version   HTTP version number
 */
int parse_request_line(char *buf, char *method, char *protocol, char *host_port, char *resource, char *params, char *version)
{
	char url[MAXLINE];
	char tail[MAXLINE];
	// check if it is valid buffer
	if (strstr(buf, "/") == NULL || strlen(buf) < 1) {
		return -1;
	}
	// set resource default to '/'
	strcpy(resource, "/");
	sscanf(buf, "%s %s %s", method, url, version);
	if (strstr(url, "://") != NULL) {
		// has protocol
		sscanf(url, "%[^:]://%[^/]%s", protocol, host_port, tail);
	} else {
		// no protocols
		sscanf(url, "%[^/]%s", host_port, tail);
	}

	char *p;
	if ((p = strstr(tail, "?")) != NULL) {
		*p++ = 0;
		strcpy(params, p);
	}
	strcpy(resource, tail);

	return 0;
}



/**
 * main part of proxy jobs, include video segment request handling and
 * manifest request handling
 *
 * @param  browser_sock socket to browser so the chunk can be sent back.
 */
int xia_proxy_handle_request(int browser_sock)
{
	int n;
	char buf[MAXLINE], nxtBuf[MAXLINE];
	char method[MAXLINE], protocol[MAXLINE];
	char host_port[MAXLINE];
	char remote_host[MAXLINE], remote_port[MAXLINE], resource[MAXLINE];
	char params[MAXLINE];
	char version[MAXLINE];

	rio_t rio_client;
	strcpy(remote_host, "");
	strcpy(remote_port, "80");
	params[0] = '\0';

	// read the first line of HTTP request
	Rio_readinitb(&rio_client, browser_sock);

	n = Rio_readlineb(&rio_client, buf, MAXLINE);
	if (n == -1) {
		syslog(LOG_WARNING, "problem with reading from the socket");
		return -1;
	} else if (n == 0) {
		return 1;
	}

	// finish reading the rest of the HTTP request
	// need this since socket buffer for this request
	// need to be completly drained
	while (Rio_readlineb(&rio_client, nxtBuf, MAXLINE) != 0) {
		if (strcmp(nxtBuf, "\r\n") == 0) {
			break;
		}
	}

	if (parse_request_line(buf, method, protocol, host_port,
				resource, params, version) == -1) {
		return -1;
	}
	parse_host_port(host_port, remote_host, remote_port);


	if (strcmp(remote_host, "") == 0 || (strcasestr(remote_host, XIA_VID_SERVICE) == NULL && strcasestr(remote_host, XIA_DAG_URL) == NULL)) {
		syslog(LOG_DEBUG, "[Proxy] service id not XIA type %s", remote_host);
		return -1;
	}

	if (strstr(method, "GET") != NULL || strstr(method, "OPTIONS")) {
		ProxyRequestCtx ctx;
		ctx.browser_sock = browser_sock;
		ctx.id = 0;
		strcpy(ctx.remote_host, remote_host);
		strcpy(ctx.remote_port, remote_port);
		strcpy(ctx.remote_path, resource);
		strcpy(ctx.params, params);

		if (strcasestr(ctx.remote_host, XIA_DAG_URL) != NULL || strcasestr(ctx.remote_path, "/CID") != NULL) {
			ctx.bandwidth = 0;
			ctx.id = 0;

			char s[1024];
			char *opt, *val;
			char *st, *st1;
			
			// get the client id and current video bandwidth
			strncpy(s, ctx.params, sizeof(s));
			for (st = s, opt = strtok_r(st, "=", &st1); opt; opt = strtok_r(NULL, "=", &st1)) {
				if ((val = strtok_r(NULL, "&", &st1)) != NULL) {
					if (strncmp(opt, bandwidth_str, strlen(bandwidth_str)) == 0) {
						ctx.bandwidth = atol(val);
					} else if (strncmp(opt, client_str, strlen(client_str)) == 0) {
						ctx.id = atol(val);
					} else {
						syslog(LOG_INFO, "invalid http options: %s", ctx.params);
						break;
					}
				}
			}

			// get the current cdn provided by the broker
			if (pthread_mutex_lock(&client_state[ctx.id].cdn_lock)) {
				syslog(LOG_ERR, "cdn_mutex lock error: %s", strerror(errno));
				exit(EXIT_FAILURE);
			}

			ctx.ad = client_state[ctx.id].cdn_ad;
			ctx.hid = client_state[ctx.id].cdn_hid;
			ctx.cdn_host = client_state[ctx.id].cdn_host;
			pthread_mutex_unlock(&client_state[ctx.id].cdn_lock);

			if (handle_stream_requests(&ctx) < 0) {
				syslog(LOG_WARNING, "failed to return back chunks to browser. Exit");
				return -1;
			}
		} else if (strcasestr(ctx.remote_host, XIA_VID_SERVICE) != NULL) {
			// if this is option probe,
			if (strstr(method, "OPTIONS") != NULL) {
				if (handle_cross_origin_probe(&ctx) < 0) {
					syslog(LOG_WARNING, "failed to handle cross origin probe back to browser. Exit");
					return -1;
				}
			} else {
				// manifest request must request .mpd files as extension
				if (strcasestr(ctx.remote_path, ".mpd") == NULL) {
					syslog(LOG_WARNING, "request remote path not mpd manifest type");
					return -1;
				}

				// get the XIA socket to the video server
				int xia_sock = get_xia_socket_for_request(remote_host);
				if (xia_sock < 0) {
					syslog(LOG_WARNING, "failed to create socket with the video server. Exit");
					return -1;
				}
				ctx.xia_sock = xia_sock;

				int rc = handle_manifest_requests(&ctx);
				Xclose(ctx.xia_sock);

				if (rc < 0) {
					syslog(LOG_WARNING, "failed to return back chunks to browser. Exit");
					return -1;
				}
			}
		}

		return 0;
	} else {
		syslog(LOG_WARNING, "unsupported request method %s for %s", method, host_port);
		return -1;
	}
}



/**
 * Proxy job when request comes
 * @param browser_sock socket to a given request
 * @param set          for clean up when done with request
 * @param i            index of socket of the request
 */
void *job(void *sockptr)
{
	int rc;
	int browser_sock = (int)(long int)sockptr;

	rc = xia_proxy_handle_request(browser_sock);
	if (rc == -1) {
		syslog(LOG_DEBUG, "something wrong with the xia_proxy_handle_request, close the browser socket");
	}

	close_fd(browser_sock);

	return NULL;
}



void start_new_job(long int sock)
{
	pthread_t worker;

	if (pthread_create(&worker, NULL, job, (void *)sock)) {
		syslog(LOG_WARNING, "proxy: ERROR: creating handler. Dropping request");
	}
}



int main(int argc, char **argv)
{
	struct sockaddr_in address;
	int addrlen = sizeof(address);
	int new_socket;
	struct sockaddr_in servaddr; //  socket address structure

	config(argc, argv);

	Xgethostname(hostname, sizeof(hostname));

	client_state.resize(20);
	for (int i = 0; i < num_clients; i++) {
		char buf[128];
		snprintf(buf, sizeof(buf), "%s-%d", hostname, i);
		client_state[i].hostname = buf;
		client_state[i].cdn_lock = PTHREAD_MUTEX_INITIALIZER;
	}

	// set up signal handler for ctrl-c
	// FIXME: comment out sig handlers for now to make finding leaks easier
	// (void) signal(SIGINT, cleanup);

	// write on closed pipe (socket)
	// (void) signal (SIGPIPE, SIG_IGN);

	// create the listening socket
	if ((list_s = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
		syslog(LOG_ERR, "Error creating listening socket.");
		exit(EXIT_FAILURE);
	}

	// Enable the socket to reuse the address
	if (setsockopt(list_s, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int)) == -1) {
		syslog(LOG_ERR, "Let us reuse the address on the socket");
		exit(EXIT_FAILURE);
	}

	// set all bytes in socket address structure to zero, and fill in the relevant data members
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port        = htons(port);

	// bind to the socket address
	if (bind(list_s, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0 ) {
		syslog(LOG_ERR, "Error calling bind()");
		exit(EXIT_FAILURE);
	}

	// Listen on socket list_s
	if ((listen(list_s, 10)) == -1) {
		syslog(LOG_ERR, "Error Listening");
		exit(EXIT_FAILURE);
	}

	// initilize xcache
	XcacheHandleInit(&xcache);

	if (run_broker_threads() != 0) {
		return -1;
	}

	while (alive) {
		// Accept incoming connection requests from clients
		new_socket = accept(list_s, (struct sockaddr *)&address,
				(socklen_t *) &addrlen);
		if (new_socket < 0) {
			perror("proxy: ERROR: accept failed");
			continue;
		}

		pthread_t worker;

		if (pthread_create(&worker, NULL, job, (void *)(long int)new_socket)) {
			syslog(LOG_WARNING, "proxy: ERROR: creating handler. Dropping request");
		}
	}

	close(list_s);
	return 0;
}
