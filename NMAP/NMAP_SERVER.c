#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_ICMP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h>  // struct icmp, ICMP_ECHO
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <time.h>
#include <sys/time.h>
#include <sys/cdefs.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <errno.h>            // errno, perror()
#include<pthread.h>
#include <math.h>
#include <byteswap.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/udp.h>
#include <fcntl.h>
// Define some constants.
#define IP4_HDRLEN 20         // IPv4 header length
#define ICMP_HDRLEN 8         // ICMP header length for echo request, excludes data
#define checkError(eno,msg)               \
  ({                                      \
          if((eno)<0)                       \
          {                               \
                  perror(msg);            \
                  exit(EXIT_FAILURE);     \
         }                                \
 })

#define srcport 8000
#define PORT_COUNT 25

char *hello = "Hello from client";
struct sockaddr_in address,myAddress;
struct in_addr hostAddress[1000];
int liveFlag[1000];
int hostCount = 0;
pthread_t rawsockthread_id;
char buffer[40];
char IPAddress[32];
char SubnetMask[32];
char HOSTIP[INET_ADDRSTRLEN];

struct results{
  	char ip[33];
  	short port;
  	char res[50];
};

struct liveServer{
	struct sockaddr_in hostServers;
	int flag;
	int alivePORTS[PORT_COUNT];
	int aliveTCPPORTS[PORT_COUNT];
	int one;
	int tcpfd[PORT_COUNT];	
};

struct liveServer hostServers[1000];
int liveServerCount = 0;
time_t timeout_in_seconds = 30; //set recieve timeout in seconds

int udp_client_fd;
int tcp_client_fd;



void inputParser(int subnetmask){
	int count = (int)subnetmask/8;
	//printf("count is %d\n",count);
	while(count!=0){
		strcat(SubnetMask,"255.");
		count--;
	}
	//printf("SubnetMask is %s\n",SubnetMask);
	count = subnetmask%8;
	//printf("count is %d\n",count);
	int a = 0;
	int b = 7;
	while(count > 0){
		//printf("count is %d\n",count);
		a = a + pow(2,b);
		count = count - 1;
		b = b - 1;
	}
	//printf("a is %d\n",a);
	char arr[3];
	snprintf(arr,10,"%d", a);
	strcat(SubnetMask,arr);
	printf("SubnetMask is %s\n",SubnetMask);
}

int tokenizer(){
	char* token = strtok(buffer, "/");
	//printf("IPAddress %s\n",token);
	strcpy(IPAddress,token);
	//printf("%s\n",IPAddress );
	token = strtok(NULL, "/");
	int subnetmask = (token[0]-48)*10 + token[1]-48;
	//printf("Subnet mask %d\n",subnetmask);
	return subnetmask;
}

void addressCalculator(){
	
    char NETMASK[INET_ADDRSTRLEN];
    struct in_addr host, mask, broadcast;
    char broadcast_address[INET_ADDRSTRLEN];

	if (inet_pton(AF_INET, IPAddress, &host) == 1 && inet_pton(AF_INET, SubnetMask, &mask) == 1){
		//printf("Host %d\n",host.s_addr);
		//printf("Netmask %d\n",mask.s_addr);
		host.s_addr = host.s_addr & mask.s_addr;
		//broadcast.s_addr = host.s_addr | mask.s_addr;
		broadcast.s_addr = host.s_addr | ~mask.s_addr;
	}else {
        printf("Failed converting strings to numbers\n");
    }

	if (inet_ntop(AF_INET, &broadcast, NETMASK, INET_ADDRSTRLEN) != NULL){
        //printf("Broadcast address of %s with netmask is %s is %s\n", IPAddress,SubnetMask, NETMASK);
	}
    else {
        //printf("Failed converting number to string\n");
    }

    if (inet_ntop(AF_INET, &host, HOSTIP, INET_ADDRSTRLEN) != NULL){
        printf("Network Id is %s \n",IPAddress);
    }
    else {
        //printf("Failed converting number to string\n");
    }

    printf("Hosts In The Network Are\n");
    while(host.s_addr!=broadcast.s_addr){
	    host.s_addr = bswap_32(host.s_addr);
	    host.s_addr = host.s_addr + 1;
	    host.s_addr = bswap_32(host.s_addr);

	    hostServers[hostCount].hostServers.sin_addr.s_addr = host.s_addr;
	    hostServers[hostCount].flag = 0;
	    hostAddress[hostCount++].s_addr = host.s_addr;

	    if (inet_ntop(AF_INET, &host, HOSTIP, INET_ADDRSTRLEN) != NULL){
	        if(hostCount%4==0)
	        	printf(" %s\n",HOSTIP);
	        else
	        	printf(" %s\t",HOSTIP);
	    }
	    else {
	        //printf("Failed converting number to string\n");
	    }
	}
	hostCount--;
	printf("\n");
	printf("\n Network Size Is %d\n",hostCount);
}

static void * processICMP(){
	struct timeval tv;
	tv.tv_sec = timeout_in_seconds;
	tv.tv_usec = 0;
	int raw_socket=0;
	char IP[32];
 	if ((raw_socket = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
    	perror ("socket() failed to get socket descriptor for using ioctl() ");
    	exit (EXIT_FAILURE);
  	}
	int hlen1,icmplen,hlen2;
	struct udphdr *udp;
	int len=0;
	int recvlen =0;
	struct ip *ip,*hip;
	struct icmp *icmp;
	setsockopt(raw_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
	while(1)
	{
		struct sockaddr_in client_address;
		memset (&client_address, 0, sizeof (client_address));
		int len =sizeof(client_address);

	  	char recvbuf[1500];
	  	recvlen = recvfrom (raw_socket, recvbuf, sizeof(recvbuf) , 0,(struct sockaddr *) &client_address,&len);
	  	if(errno==EWOULDBLOCK)
	  	{
	  		printf("alarm generated\n");
	  		//break;
	  		pthread_exit(NULL);
	  	}
	  	checkError(recvlen,"Recv From");
	  
	  	//printf("len is %d\n",recvlen);

		ip = (struct ip * ) recvbuf;
		hlen1 = ip->ip_hl << 2;

		icmp = (struct icmp*)(recvbuf + hlen1);

		icmplen = recvlen - hlen1;
		
		if(icmplen < 8){
			continue;		/*Not enough to look at ICMP header*/
		}
	  
		if(icmplen < 8 + sizeof(struct ip)){
			continue;			/*not enough data to look at inner IP	*/
		}

		hip = (struct ip *)(recvbuf + hlen1 + 8);
		hlen2 = hip->ip_hl << 2;

		if(icmplen < 8 + hlen2 + 4)
			continue;

		if(icmplen < 8 + hlen2 + 4){
			continue;			/*Not enough data to look at UDP ports*/
		}

		udp = (struct udphdr *)(recvbuf + hlen1 + 8 + hlen2);

		if(hip->ip_p == IPPROTO_UDP && ntohs(udp->source)==srcport){
	    //printf("UDP done");
	    //printf("Recv source port is %d \n",ntohs(udp->source));
	    //printf("Recv dest port is %d \n",ntohs(udp->dest));

	    //printf("Recv source IP is %d \n",hip->ip_src);
	    //printf("Recv dest IP is %d \n",hip->ip_dst);
	    if(icmp->icmp_type == ICMP_DEST_UNREACH){
	  		if(icmp->icmp_code == ICMP_HOST_UNREACH){
				for(int i = 0;i < hostCount;i++){
					if(hostServers[i].hostServers.sin_addr.s_addr == hip->ip_dst.s_addr){
						hostServers[i].flag = 1;
					}
				}
				if (inet_ntop(AF_INET, &hip->ip_dst, IP, INET_ADDRSTRLEN) != NULL){
				   	//printf(" IP Address %s", IP);
				}
				else 
				   	printf("Failed converting number to string\n");
				//printf("is unreachable\n");
				continue;
			}
		}

	  }	
	}
	return NULL;
}

void thread_make(){
	pthread_create (&rawsockthread_id, NULL, &processICMP, NULL);
}

void sendUDPPackets(int udp_client_fd){
	int upper = 1024, count = 1,rc=0;
	myAddress.sin_family = AF_INET;
	myAddress.sin_port = htons(srcport);
	myAddress.sin_addr.s_addr = INADDR_ANY;
	bind(udp_client_fd,(struct sockaddr *)&myAddress,sizeof(myAddress));
	perror("bind");

	 for (int i = 0; i < count; i++) { 
	 		int rand1=rand();
	 		//printf("rans is %d\n",rand1 );
	        int PORT = (rand1 % upper); 
	        //printf("PORT used is %d \n", PORT); 
	    for(int i=0;i<hostCount;i++)
	    {

			if (inet_ntop(AF_INET, &hostAddress[i], HOSTIP, INET_ADDRSTRLEN) != NULL){
		        //printf("First IP Address of %s with netmask is %s\n", IPAddress, HOSTIP);
		    }
		    else {
		        printf("Failed converting number to string\n");
		    }
		    address.sin_family = AF_INET;
		    address.sin_port = htons(PORT);
		    address.sin_addr=hostAddress[i];
			rc = sendto(udp_client_fd, (const char *)hello, strlen(hello), 0, (const struct sockaddr *) &address,sizeof(address)); 

			//printf("packet sent\n;");
			checkError(rc,"sendError");
		}
	}
}

void printLiveServers(){
	printf("Active Hosts\n");
	char IP[32];
	int flag = 0;
	for(int i = 0;i < hostCount;i++){
		if(hostServers[i].flag == 0){
			if (inet_ntop(AF_INET, &hostServers[i].hostServers.sin_addr.s_addr, IP, INET_ADDRSTRLEN) != NULL){
	  			if(flag%2==0){
	  				printf("%s\t", IP);
	  			}else{
	  				printf("%s\n", IP);
	  			}
	  			flag++;
			}
			else 
				printf("Failed converting number to string\n");
		}
	}
	printf("\n");
	//printf("flag is %d\n",flag );
}

void checkTCPPorts(){

	struct timeval tv;
	fd_set myset;
	struct sockaddr_in liveaddr;
	socklen_t lon;
	int valopt;
	for(int i = 0;i < hostCount;i++){
		if(hostServers[i].flag==0){
			liveaddr = hostServers[i].hostServers;
			liveaddr.sin_family = AF_INET;
			FD_ZERO(&myset);
			int maxFd = 0; 
			int ret;
			for(int j = 1;j < PORT_COUNT;j++){
				//printf("HI\n");
				liveaddr.sin_port = htons(j);
				hostServers[i].tcpfd[j] = socket(AF_INET, SOCK_STREAM, 0);
				int fd_flags = fcntl(hostServers[i].tcpfd[j],F_GETFL);
				if(-1==fcntl(hostServers[i].tcpfd[j],F_SETFL,fd_flags | O_NONBLOCK)){
					printf("Error While FD Blocking\n");
				}
				FD_SET(hostServers[i].tcpfd[j], &myset);
				if(hostServers[i].tcpfd[j] > maxFd)
					maxFd = hostServers[i].tcpfd[j];
				ret = connect(hostServers[i].tcpfd[j], (struct sockaddr *)&liveaddr, sizeof(liveaddr));
		    	//perror("connect");
		    	//close(hostServers[i].tcpfd[j]); 
			}
			tv.tv_sec = 10;
			tv.tv_usec = 0;
			select(100,NULL,NULL,NULL,&tv);
			//perror("select ");
			for(int j = 1;j < PORT_COUNT;j++){
				getsockopt(hostServers[i].tcpfd[j], SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
				//printf("valopt %d %d \n",j, valopt);
				if(valopt == 0){
					//printf("Error In Connection For Port %s\n",j);
					//printf("Time our for port %d found \n", j);
					hostServers[i].alivePORTS[j] = 1;
					hostServers[i].one = 1;
				}else{
					hostServers[i].alivePORTS[j] = -1;
					hostServers[i].one = 1;
				}
				close(hostServers[i].tcpfd[j]);
			}
		}
	}
}

void printPorts(){
	int flag =0;
	for(int i = 0;i < hostCount;i++){
		if(hostServers[i].flag==0 && hostServers[i].one==1){
			char IP[32];
			if (inet_ntop(AF_INET, &hostServers[i].hostServers.sin_addr.s_addr, IP, INET_ADDRSTRLEN) != NULL){
	  			for(int j = 1;j < PORT_COUNT;j++){
	  				if(hostServers[i].alivePORTS[j]==0){
	  					if(flag%2==0){
	  						printf(" %s Port %d \t", IP,j);
	  					}else{
	  						printf(" %s Port %d \n", IP,j);
	  					}
	  					flag++;
	  				}else{
	  					hostServers[i].alivePORTS[j]=0;
	  				}
	  			}
			}
			else{ 
				printf("Failed converting number to string\n");
			}
		}
	}
	printf("\n");
}

void printTCPPorts(){
	int flag =0;
	for(int i = 0;i < hostCount;i++){
		if(hostServers[i].flag==0){
			char IP[32];
			if (inet_ntop(AF_INET, &hostServers[i].hostServers.sin_addr.s_addr, IP, INET_ADDRSTRLEN) != NULL){
	  			for(int j = 1;j < PORT_COUNT;j++){
	  				if(hostServers[i].alivePORTS[j]==1){
	  					if(flag%2==0){
	  						printf(" %s Port %d \t", IP,j);
	  					}else{
	  						printf(" %s Port %d \n", IP,j);
	  					}
	  					flag++;
	  				}else{
	  					hostServers[i].alivePORTS[j]=0;
	  				}
	  			}
			}
			else{ 
				printf("Failed converting number to string\n");
			}
		}
	}
	printf("\n");
}

void checkUDPports(int udp_client_fd){
	char IP[32];
	struct sockaddr_in liveaddr;
	for(int i=0;i<hostCount;i++)
	{
		if(hostServers[i].flag==0)
		{

			if (inet_ntop(AF_INET, &hostServers[i].hostServers.sin_addr.s_addr, IP, INET_ADDRSTRLEN) != NULL){
		        //printf("First IP Address of %s with netmask is %s\n", IPAddress, IP);
		    }
		    else {
		        printf("Failed converting number to string\n");
		    }
			//the server is alive.
			liveaddr=hostServers[i].hostServers;
			liveaddr.sin_family = AF_INET;

			for(int j=1;j<PORT_COUNT;j++)
			{
				liveaddr.sin_port = htons(j);
				int rc = sendto(udp_client_fd, (const char *)hello, strlen(hello), 0, (const struct sockaddr *) &liveaddr,sizeof(liveaddr));
				//printf("port used is %d\n",j);
				checkError(rc,"sendError");


			}
		}	
	}
}


static void * processICMPforUDP(){
	errno = 0;
	struct timeval tv;
	tv.tv_sec = timeout_in_seconds;
	tv.tv_usec = 0;
	int raw_socket=0;
	char IP[32];
 	if ((raw_socket = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
    	perror ("socket() failed to get socket descriptor for using ioctl() ");
    	exit (EXIT_FAILURE);
  	}
	int hlen1,icmplen,hlen2;
	struct udphdr *udp;
	int len=0;
	int recvlen =0;
	struct ip *ip,*hip;
	struct icmp *icmp;
	setsockopt(raw_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
	while(1)
	{
		struct sockaddr_in client_address;
		memset (&client_address, 0, sizeof (client_address));
		int len =sizeof(client_address);

	  	char recvbuf[1500];
	  	recvlen = recvfrom (raw_socket, recvbuf, sizeof(recvbuf) , 0,(struct sockaddr *) &client_address,&len);
	  	//printf("in new method\n");
	  	if(errno==EWOULDBLOCK)
	  	{
	  		printf("alarm generated\n");
	  		//break;
	  		pthread_exit(NULL);
	  	}
	  	checkError(recvlen,"Recv From");
	  
	  	//printf("len is %d\n",recvlen);

		ip = (struct ip * ) recvbuf;
		hlen1 = ip->ip_hl << 2;

		icmp = (struct icmp*)(recvbuf + hlen1);

		icmplen = recvlen - hlen1;
		
		if(icmplen < 8){
			continue;		/*Not enough to look at ICMP header*/
		}
	  
		if(icmplen < 8 + sizeof(struct ip)){
			continue;			/*not enough data to look at inner IP	*/
		}

		hip = (struct ip *)(recvbuf + hlen1 + 8);
		hlen2 = hip->ip_hl << 2;

		if(icmplen < 8 + hlen2 + 4)
			continue;

		if(icmplen < 8 + hlen2 + 4){
			continue;			/*Not enough data to look at UDP ports*/
		}

		udp = (struct udphdr *)(recvbuf + hlen1 + 8 + hlen2);

		if(hip->ip_p == IPPROTO_UDP && ntohs(udp->source)==srcport){
	    //printf("UDP done");
	    //printf("Recv source port is %d \n",ntohs(udp->source));
	    //printf("Recv dest port is %d \n",ntohs(udp->dest));
		if(icmp->icmp_type == ICMP_DEST_UNREACH || icmp->icmp_code == ICMP_PORT_UNREACH){
			for(int i = 0;i < hostCount;i++)
			{
				if(hostServers[i].hostServers.sin_addr.s_addr == hip->ip_dst.s_addr)
				{
					if (inet_ntop(AF_INET, &hip->ip_dst, IP, INET_ADDRSTRLEN) != NULL){
			   			//printf(" IP Address %s\n", IP);
					}
					else{ 
			   			printf("Failed converting number to string\n");
			   		}
					//printf("Port %d is unreachable\n",ntohs(udp->dest));
					hostServers[i].alivePORTS[ntohs(udp->dest)] = 1;//not reachable
					hostServers[i].one = 1;
				}
			}
		}
		else
		{

			if (inet_ntop(AF_INET, &hip->ip_dst, IP, INET_ADDRSTRLEN) != NULL)
			{
		    	printf(" IP Address %s and UDP port %d is open\n", IP,ntohs(udp->dest));
		    	
			}

		}
	  }
	}
	return NULL;
}

void thread_make_one(){
	pthread_create (&rawsockthread_id, NULL, &processICMPforUDP, NULL);
}

int main (int argc, char *argv[]){
	if(argc < 2){
			printf("Please provide Ip address and Subnet mask\n");
			exit(0);
	}
	memset (&address, 0, sizeof (address));
	memset (&myAddress, 0, sizeof (myAddress));
	udp_client_fd = socket (AF_INET, SOCK_DGRAM, 0);
	checkError (udp_client_fd, "UDPSOCKETfailed");
	checkError (tcp_client_fd,"TCPSOCKETfailed");
	strcpy(buffer,argv[1]);
	int subnetmask = tokenizer();
	inputParser(subnetmask);
	addressCalculator();
	//timeout_in_seconds = timeout_in_seconds + hostCount;
	int rc = 0;
	thread_make();
	srand(time(0));
	sendUDPPackets(udp_client_fd); 			//To check Live hosts in the subnet
	pthread_join(rawsockthread_id,NULL);
	printLiveServers();
	thread_make_one();
	checkUDPports(udp_client_fd);
	pthread_join(rawsockthread_id,NULL);
	printf("\n UDP Active Ports \n");
	printPorts();
	checkTCPPorts();
	printf("\n TCP Active Ports\n");
	printTCPPorts();
	return 0;
}

