#include "stage_utils.h"

using namespace std;

char myAD[MAX_XID_SIZE];
char myHID[MAX_XID_SIZE];
char my4ID[MAX_XID_SIZE];

int stageServerSock;

pthread_mutex_t profileLock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t bufLock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t startStage = PTHREAD_COND_INITIALIZER;
pthread_mutex_t stageMutex = PTHREAD_MUTEX_INITIALIZER;
//pthread_mutex_t timeLock = PTHREAD_MUTEX_INITIALIZER;
//pthread_mutex_unlock(&profileLock);
struct chunkProfile {
    int fetchState;
    long fetchStartTimestamp;
    long fetchFinishTimestamp;
    sockaddr_x oldDag;
    sockaddr_x newDag;
};

ofstream stageServerTime("stageServerTime.log");
// Used by different service to communicate with each other.
map<string, chunkProfile> CIDProfile;   // stage state
//map<string, vector<sockaddr_x> > SIDToBuf; // chunk buffer to stage
//map<string, long> SIDToTime; // timestamp last seen

// TODO: non-blocking fasion -- stage manager can send another stage request before get a ready response
// put the CIDs into the stage buffer, and "ready" msg one by one
int chunkSock;
XcacheHandle xcache;
void stageControl(int sock, char *cmd)
{
    //pthread_mutex_lock(&timeLock);
    //SIDToTime[remoteSID] = now_msec();
    //pthread_mutex_unlock(&timeLock);

    char remoteAD[MAX_XID_SIZE];
    char remoteHID[MAX_XID_SIZE];
    char remoteSID[MAX_XID_SIZE];

    XgetRemoteAddr(sock, remoteAD, remoteHID, remoteSID); // get stage manager's remoteSID

    //vector<string> CIDs ;//= strVector(cmd);
    vector<string> CIDs = strVector(cmd);
/*
    while(1){
	if (strncmp(cmd, "stageEnd", 8) == 0) {
	    break;
	}
	say("Successfully receive stage command from stage manager. CMD: %s\n",cmd);
	if (strncmp(cmd, "stageCont", 9) == 0) {
            say("Receive a stage message: %s\n", cmd);
            
        }
	char str_arr[strlen(cmd)+1];
	strcpy(str_arr, cmd+10);
	char *saveptr;
	char *str = strtok_r(str_arr, " ", &saveptr);
	CIDs.push_back(str);
	int n;
	if (( n = Xrecv(sock, cmd, XIA_MAXBUF, 0))  < 0) {
            warn("socket error while waiting for data, closing connection\n");
            break;
	} 
    }
   */
    pthread_mutex_lock(&profileLock);
    for (auto CID : CIDs) {
		if(CIDProfile[CID].fetchState == READY) continue;
        CIDProfile[CID].fetchState = BLANK;
        //url_to_dag(&CIDProfile[CID].oldDag, (char*)CID.c_str(), CID.size());
		Graph g((char*)CID.c_str());
		g.fill_sockaddr(&CIDProfile[CID].oldDag);
		
        CIDProfile[CID].fetchStartTimestamp = 0;
        CIDProfile[CID].fetchFinishTimestamp = 0;
    }

    // send the chunk ready msg one by one
    char url[256];
    //char buf[CHUNKSIZE];
	void *buf;// = (char*)malloc(CHUNKSIZE);
    int ret;
    for (auto CID : CIDs) {
        if (CIDProfile[CID].fetchStartTimestamp == 0) {
            CIDProfile[CID].fetchStartTimestamp = now_msec();
        }
		
        /*if ((ret = XfetchChunk(&xcache, buf, CHUNKSIZE, XCF_BLOCK, &CIDProfile[CID].oldDag, sizeof(CIDProfile[CID].oldDag))) < 0) {
            die(-1,"unable to request chunks\n");
            //add unlock function   --Lwy   1.16
            //pthread_mutex_unlock(&bufLock);
            //pthread_exit(NULL);
        }*/
		if(CIDProfile[CID].fetchState != READY){
			int retry=5;
			while(retry--){
				if ((ret = XfetchChunk(&xcache, &buf, XCF_BLOCK, &CIDProfile[CID].oldDag, sizeof(CIDProfile[CID].oldDag))) < 0) {
					//die(-1, "XfetchChunk Failed\n");
					say("unable to request chunks, retrying");
				}
				else break;
			}
			if(ret < 0)
				die(-1, "unable to request chunks\n");
			
			if (XputChunk(&xcache, (const char* )buf, ret, &CIDProfile[CID].newDag) < 0) {
				die(-1,"unable to put chunks\n");
				//pthread_exit(NULL);
			}
			if (CIDProfile[CID].fetchFinishTimestamp == 0) {
				CIDProfile[CID].fetchFinishTimestamp = now_msec();
			}
			CIDProfile[CID].fetchState = READY;
		}
        //add the lock and unlock action    --Lwy   1.16
        char reply[XIA_MAX_BUF] = "";
        //dag_to_url(url, 256, &CIDProfile[CID].newDag);
		Graph g(&CIDProfile[CID].newDag);
		g.fill_sockaddr(&CIDProfile[CID].newDag);
		strcpy(url, g.http_url_string().c_str());
		
		
		char oldUrl[256];
		//dag_to_url(oldUrl, 256, &CIDProfile[CID].oldDag);
		Graph oldg(&CIDProfile[CID].oldDag);
		oldg.fill_sockaddr(&CIDProfile[CID].oldDag);
		strcpy(oldUrl, oldg.http_url_string().c_str());
	
        memset(reply, 0 ,sizeof(reply));
        sprintf(reply, "ready %s %s %ld", oldUrl, url,
                CIDProfile[CID].fetchFinishTimestamp -
                CIDProfile[CID].fetchStartTimestamp);
//        hearHello(sock);
        stageServerTime << "OldDag: " << oldUrl << " NewDag: " << url << " StageTime: " << CIDProfile[CID].fetchFinishTimestamp -
                        CIDProfile[CID].fetchStartTimestamp << endl;

        // Send chunk ready message to state manager.
        sendStreamCmd(sock, reply);
        say("xsend return ----- xsend return ---- xsend return ----  %s", CID.c_str());
        //pthread_mutex_unlock(&profileLock);

        // Determine the intervals to check the state of current chunk.
        //usleep(SCAN_DELAY_MSEC * 1000); // chenren: check timing issue
    }
	pthread_mutex_unlock(&profileLock);
	//free(buf);
//pthread_mutex_lock(&profileLock);
    //CIDProfile.erase(remoteSID);
//pthread_mutex_unlock(&profileLock);
//pthread_mutex_lock(&bufLock);
//SIDToBuf.erase(remoteSID);
//pthread_mutex_unlock(&bufLock);
//pthread_mutex_lock(&timeLock);
//SIDToTime.erase(remoteSID);
//pthread_mutex_unlock(&timeLock);

    return;
}

void preStage(int sock, char *cmd)
{
    char remoteAD[MAX_XID_SIZE];
    char remoteHID[MAX_XID_SIZE];
    char remoteSID[MAX_XID_SIZE];
	
	XgetRemoteAddr(sock, remoteAD, remoteHID, remoteSID); // get stage manager's remoteSID
	
    vector<string> CIDs = strVector(cmd);
	pthread_mutex_lock(&profileLock);
    for (auto CID : CIDs) {
        CIDProfile[CID].fetchState = BLANK;
		Graph g((char*)CID.c_str());
		g.fill_sockaddr(&CIDProfile[CID].oldDag);
		
        CIDProfile[CID].fetchStartTimestamp = 0;
        CIDProfile[CID].fetchFinishTimestamp = 0;
    }

    // send the chunk ready msg one by one
    char url[256];
	void *buf;// = (char*)malloc(CHUNKSIZE);
    int ret;
    for (auto CID : CIDs) {
        if (CIDProfile[CID].fetchStartTimestamp == 0) {
            CIDProfile[CID].fetchStartTimestamp = now_msec();
        }
		
        /*if ((ret = XfetchChunk(&xcache, buf, CHUNKSIZE, XCF_BLOCK, &CIDProfile[CID].oldDag, sizeof(CIDProfile[CID].oldDag))) < 0) {
            die(-1,"unable to request chunks\n");
            //add unlock function   --Lwy   1.16
            //pthread_mutex_unlock(&bufLock);
            //pthread_exit(NULL);
        }*/
		int retry=5;
		while(retry--){
			if ((ret = XfetchChunk(&xcache, &buf, XCF_BLOCK, &CIDProfile[CID].oldDag, sizeof(CIDProfile[CID].oldDag))) < 0) {
				//die(-1, "XfetchChunk Failed\n");
				say("unable to request chunks, retrying");
			}
			else break;
		}
		if(ret < 0)
			die(-1, "unable to request chunks\n");
		
        if (XputChunk(&xcache, (const char* )buf, ret, &CIDProfile[CID].newDag) < 0) {
            die(-1,"unable to put chunks\n");
            //pthread_exit(NULL);
        }
        if (CIDProfile[CID].fetchFinishTimestamp == 0) {
            CIDProfile[CID].fetchFinishTimestamp = now_msec();
        }
        CIDProfile[CID].fetchState = READY;
        //add the lock and unlock action    --Lwy   1.16
        //char reply[XIA_MAX_BUF] = "";
        //dag_to_url(url, 256, &CIDProfile[CID].newDag);
		Graph g(&CIDProfile[CID].newDag);
		g.fill_sockaddr(&CIDProfile[CID].newDag);
		strcpy(url, g.http_url_string().c_str());
		
		
	char oldUrl[256];
	//dag_to_url(oldUrl, 256, &CIDProfile[CID].oldDag);
	Graph oldg(&CIDProfile[CID].oldDag);
	oldg.fill_sockaddr(&CIDProfile[CID].oldDag);
	strcpy(oldUrl, oldg.http_url_string().c_str());
      
    stageServerTime << "OldDag: " << oldUrl << " NewDag: " << url << " StageTime: " << CIDProfile[CID].fetchFinishTimestamp -
                        CIDProfile[CID].fetchStartTimestamp << endl;


    }
	pthread_mutex_unlock(&profileLock);
	//free(buf);
    //CIDProfile.erase(remoteSID);

    return;
}



// TODO: paralize getting chunks for each SID, i.e. fair scheduling
// read the CID from the stage buffer, execute staging, and update profile
/*
void *stageData(void *)
{
    int chunkSock;

    XcacheHandle xcache;
    XcacheHandleInit(&xcache);
    // Create socket with server.
    if ((chunkSock = Xsocket(AF_XIA, SOCK_STREAM, 0)) < 0) {
        die(-1, "unable to create chunk socket\n");
    }

    while (1) {
        pthread_cond_wait(&startStage, &stageMutex);
        // pop out the chunks for staging
        pthread_mutex_lock(&bufLock);
        // For each stage manager.
        for (auto I : SIDToBuf) {
            if (I.second.size() > 0) {
                string SID = I.first;

                char buf[CHUNKSIZE];
                //char buf[1024 * 1024];
                int ret;
                say("Fetching chunks from server.\n");
                for (auto addr : I.second) {
                    char CID[256];

                    //sockaddr_x addr;
                    //url_to_dag(&addr, (char*)CID.c_str(), CID.size());
                    dag_to_url(CID, 256, &addr);
                    //if ((ret = XfetchChunk(&xcache, buf, 1024 * 1024, XCF_BLOCK, &addr, sizeof(addr))) < 0) {
                    if (CIDProfile[SID][CID].fetchStartTimestamp == 0) {
                        CIDProfile[SID][CID].fetchStartTimestamp = now_msec();
                    }
                    if ((ret = XfetchChunk(&xcache, buf, CHUNKSIZE, XCF_BLOCK, &addr, sizeof(addr))) < 0) {
                        say("unable to request chunks\n");
                        //add unlock function   --Lwy   1.16
                        pthread_mutex_unlock(&bufLock);
                        pthread_exit(NULL);
                    }

                    pthread_mutex_lock(&profileLock);
                    if (XputChunk(&xcache, (const char* )buf, ret, &CIDProfile[SID][CID].newDag) < 0) {
                        say("unable to put chunks\n");
                        pthread_mutex_unlock(&bufLock);
                        pthread_mutex_unlock(&profileLock);
                        pthread_exit(NULL);
                    }
                    if (CIDProfile[SID][CID].fetchFinishTimestamp == 0) {
                        CIDProfile[SID][CID].fetchFinishTimestamp = now_msec();
                    }
                    CIDProfile[SID][CID].fetchState = READY;
                    pthread_mutex_unlock(&profileLock);

                }
                //I.second.clear(); // clear the buf
                // TODO: timeout the chunks by free(cs[i].cid); cs[j].cid = NULL; cs[j].cidLen = 0;
            }
        }
        pthread_mutex_unlock(&bufLock);
        usleep(SCAN_DELAY_MSEC * 1000);
    }
    pthread_exit(NULL);
}
*/
void *stageCmd(void *socketid)
{
    
    char cmd[XIA_MAXBUF];
    int sock = *((int*)socketid);
    int n = -1;

    while (1) {
        say("In stageCmd.\n");
        memset(cmd, '\0', sizeof(cmd));
        // Receive the stage command sent by stage_manager.
        if ((n = Xrecv(sock, cmd, sizeof(cmd), 0))  < 0) {
            warn("socket error while waiting for data, closing connection\n");
            break;
        }
        if (strncmp(cmd, "xping", 5) == 0) {
            say("Xping to %s\n", cmd);
            int rtt = getRTT(cmd);
            sprintf(cmd, "rtt %d", rtt);
            say("Xping Response: %s\n", cmd);
            if (Xsend(sock, cmd, strlen(cmd), 0) < 0) {
                die(-1, "unable to connect to manager");
            }
            continue;
        }
        say("Successfully receive stage command from stage manager. CMD: %s\n",cmd);
        if (strncmp(cmd, "stage", 5) == 0) {
            say("Receive a stage message: %s\n", cmd+6);

            char cmd1[XIA_MAXBUF];
			char * start, *end;
			start = cmd;
			while((end = strstr(start+6, "stage")) > 0){
				n = end - start;
				printf("n = %d\n", n);
				strncpy(cmd1, start, end - start);
				start = end;
				*(cmd1+(end-start))=0;
				say("Successfully devide command . CMD: %s\n",cmd1);
				stageControl(sock, cmd1 + 6);
			}
            stageControl(sock, start + 6);
        }
		else if (strncmp(cmd, "prestage", 8) == 0) {
            say("Receive a prestage message: %s\n", cmd);
			
			char cmd1[XIA_MAXBUF];
			char * start, *end;
			start = cmd;
			while((end = strstr(start+9, "prestage")) > 0){
				n = end - start;
				printf("n = %d\n", n);
				strncpy(cmd1, start, end - start);
				start = end;
				*(cmd1+(end-start))=0;
				say("Successfully devide command . CMD: %s\n",cmd1);
				preStage(sock, cmd1 + 9);
			}
            preStage(sock, start + 9);
        }
    }

    Xclose(sock);
    say("Socket closed\n");
    pthread_exit(NULL);
}

int main()
{
    //pthread_t thread_stage;
    //pthread_create(&thread_stage, NULL, stageData, NULL); // dequeue, stage and update profile

    XcacheHandleInit(&xcache);
    // Create socket with server.
say("after XcacheHandleInit");
    if ((chunkSock = Xsocket(AF_XIA, SOCK_STREAM, 0)) < 0) {
        die(-1, "unable to create chunk socket\n");
    }
say("before registerStreamReceiver");
    stageServerSock = registerStreamReceiver(getStageServiceName(), myAD, myHID, my4ID);
	
    say("The current stageServerSock is %d\n", stageServerSock);
    blockListener((void *)&stageServerSock, stageCmd);
say("after blockListener");
    return 0;
}