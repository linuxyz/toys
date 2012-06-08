#include <stdio.h>
#include <stdlib.h>

#define _USE_32BIT_TIME_T
#include <time.h>

#ifdef _WIN32
//#include <windows.h>
#pragma comment(lib,"Ws2_32.lib")
#include <winsock2.h>
void sleep (int sec) {
	Sleep(sec * 1000);
}

int init() {
	WORD wVersionRequested;
	WSADATA wsaData;

	wVersionRequested = MAKEWORD(2, 2);
	return WSAStartup(wVersionRequested, &wsaData);
}

#define time _time32
#define close closesocket
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
int init() {
	return 0;
}
#endif

#include <signal.h>

#include "encode.h"

int http_post(const char *servip, short port, 
		const char *uri, const char *ctxt, 
		char*resp, int rlen) 
{
	int	sd;
	struct sockaddr_in pin;
	char buf[1024], status[200], *pos;
	int size, len;

	/* fill in the socket structure with host information */
	memset(&pin, 0, sizeof(pin));
	pin.sin_family = AF_INET;
	pin.sin_addr.s_addr = inet_addr(servip);
	pin.sin_port = htons(port);

	/* grab an Internet domain socket */
	if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	/* connect to PORT on HOST */
	if (connect(sd,(struct sockaddr *)  &pin, sizeof(pin)) == -1) {
		perror("connect");
		return -1;
	}

	/* build up the HTTP Headers */
	size = sprintf(buf, 
			"POST %s HTTP/1.0\r\n"
			"Content-Type: application/x-www-form-urlencoded\r\n"
			"User-Agent: my session\r\n"
			"Host: %s:%d\r\n"
			"Content-Length: %d\r\n"
			"Cache-Control: no-cache\r\n"
			"\r\n"
			"%s", 
			uri, servip, port, strlen(ctxt), ctxt);

	/* send a message to the server PORT on machine HOST */
	if (send(sd, buf, size, 0) == -1) {
		perror("send");
		return -2;
	}

	/* wait for a message to come back from the server */
	size = recv(sd, buf, sizeof(buf)-1, 0);
	if (size == -1) {
		perror("recv");
		return -3;
	}
	buf [size] = '\0';

	/* spew-out the results and bail out of here! */
	//printf("%s\n", buf);
	pos = strstr(buf, "\r\n");
	if (pos == NULL) {
		perror("invalid HTTP protocol");
		return -4;
	}
	// copy status
	strncpy(status, buf, pos-buf-1);
	if (strstr(status, " 200 ")==NULL) {
		perror(status);
		return -5;
	}

	/* got to the content directly */
	pos = strstr(pos, "\r\n\r\n");
	if (pos == NULL) {
		perror("Invalid HTTP headers");
		return -6;
	}

	/* copy the content to you */
	strncpy(resp, pos + 4, rlen);

	close(sd);

	return 0;
}


int main (int argc, char*argv[])
{
	int	udp;
	struct sockaddr_in pin;
	char resp[2048], req[1024], epwd[50], emac[50], buf[100], heartbeat[48]; 
	char *pos;
	long ltime;
	//char uid[32];
	long long uid;
	int min = 120, cnt = 0;
	int retry = 0;

	if (argc < 5) {
		//perror("Usage: tunet4 uid pwd IP MAC [Auth-Server-IP:port] [Heartbeat-Server-IP:port]\n");
		perror("Usage: tunet4 uid pwd IP MAC [min=120]\n");
		return 0;
	}

	init();

	if (argc >= 6)
		min = atoi(argv[5]);
	if (min==0) {
		min = 120;
	}

	printf("[tunet] login interval %d\n", min);
	//printf("Encode: %s\t%s\n", str, Encode(str, out, NULL));
	// Build the login string
	ltime = time(NULL);

LOGIN:	
	//ltime /= 60;
	sprintf(buf, "%u", ltime/60);
	Encode(argv[2], buf, epwd);
	Encode(argv[4], buf, emac);

	sprintf(req, "username=%s&password=%s&drop=0&type=2&n=100&mac=%s&ip=%u&mbytes=0&minutes=%d",
			argv[1], epwd, emac, inet_addr(argv[3]), min);

	// Login
	if (http_post("166.111.8.120", 3333, "/cgi-bin/do_login", req, resp, sizeof(resp)) < 0) {
		perror("HTTP POST: Communication error with server");
		exit (-1);
	}
	
	// debug
	printf("[tunet] post respones =%s\n", resp);
	
	// response 
	pos = strstr(resp, "@");
	if (pos) {
		printf("[tunet] time diff with server - reset it\n");
		sscanf(pos+1, "%lu", &ltime);
		goto LOGIN;
	} 

	// normal
	sscanf(resp, "%lld", &uid);
	pos = strstr(resp, ",");
	if (pos==NULL || strstr(pos, ",") == NULL) {
		if (++retry < 60) {
			perror("[tunet] retry ... ");
			sleep(1);
			++ ltime;
			goto LOGIN;
		}
		//strncpy(uid, resp, pos - resp);
		perror("[tunet] Unable to find the UID in response");
		exit(-2);
	}
	printf("[tunet] TUNET LOGIN: %lld / %s\n", uid, resp);
	retry = 0;


	// heartbeat!
	memset(&pin, 0, sizeof(pin));
	pin.sin_family = AF_INET;
	pin.sin_addr.s_addr = inet_addr("166.111.8.120");
	pin.sin_port = htons(3335);

	/* grab an Internet domain socket */
	if ((udp = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	/* connect to PORT on HOST */
	if (connect(udp, (struct sockaddr *)  &pin, sizeof(pin)) == -1) {
		perror("[tunet] connect failed!");
		return -1;
	}
	
	memset(heartbeat, 0, sizeof(heartbeat));
	heartbeat[0] = 0xff & uid;
	heartbeat[1] = 0xff & uid >> 8;
	heartbeat[2] = 0xff & uid >> 16;
	heartbeat[3] = 0xff & uid >> 24;
	heartbeat[4] = 0xff & uid >> 32;
	heartbeat[5] = 0xff & uid >> 40;
	heartbeat[6] = 0xff & uid >> 48;
	heartbeat[7] = 0xff & uid >> 56;
	memset(heartbeat+8, -1, 8);
	sleep(1);
	cnt = 0;
	while (cnt++<min) {
		send(udp, heartbeat, sizeof(heartbeat), 0);
		sleep(60);
		ltime += 60;
	}
	close(udp);

	// logout
	printf("[tunet] logout uid=%lld\n", uid);
	sprintf(req, "uid=%lld", uid);
	if (http_post("166.111.8.120", 3333, "/cgi-bin/do_logout", req, resp, sizeof(resp)) < 0) {
		perror("HTTP POST: Communication error with server");
	}
	printf("[tunet] logout response: %s\n", resp);

	// relogin
	sleep(1);
	//ltime += min * 60 + 60;
	goto LOGIN;

	return 0;
}



