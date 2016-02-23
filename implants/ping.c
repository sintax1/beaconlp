#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/signal.h>
#include <string.h>
 
#define DEFDATALEN      56
#define MAXIPLEN        60
#define MAXICMPLEN      76
 
static char *hostname = NULL;

typedef struct {
  unsigned char type;
  char uuid[16];
  unsigned short data_length;
  char data[2];
} Message;

static int in_cksum(unsigned short *buf, int sz)
{
  int nleft = sz;
  int sum = 0;
  unsigned short *w = buf;
  unsigned short ans = 0;
   
  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }
   
  if (nleft == 1) {
    *(unsigned char *) (&ans) = *(unsigned char *) w;
    sum += ans;
  }
   
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  ans = ~sum;
  return (ans);
}
 
static void noresp(int ign)
{
  printf("No response from %s\n", hostname);
  exit(0);
}
 
static void ping(const char *host)
{
  struct hostent *h;
  struct sockaddr_in pingaddr;
  struct icmp *pkt;
  int pingsock, c;
  char packet[DEFDATALEN + MAXIPLEN + MAXICMPLEN];
  
  Message message = {
    .type = 0x2,
    .uuid = "\x01\x23\x45\x67\x89\x0a\xbc\xde\xf0\x12\x34\x56\x78\x9a\xbc\xde",
    //.data_length = 0x2,
    //.data = "ls",
  };
 
  if ((pingsock = socket(AF_INET, SOCK_RAW, 1)) < 0) {       /* 1 == ICMP */
    perror("ping: creating a raw socket");
    exit(1);
  }
   
  /* drop root privs if running setuid */
  setuid(getuid());
   
  memset(&pingaddr, 0, sizeof(struct sockaddr_in));
   
  pingaddr.sin_family = AF_INET;
  if (!(h = gethostbyname(host))) {
    fprintf(stderr, "ping: unknown host %s\n", host);
    exit(1);
  }
  memcpy(&pingaddr.sin_addr, h->h_addr, sizeof(pingaddr.sin_addr));
  hostname = h->h_name;

  Message msg;
  

  pkt = (struct icmp *) packet;
  memset(pkt, 0, sizeof(packet));
  pkt->icmp_type = ICMP_ECHO;
  memcpy(packet + 8, &message, sizeof(message));
  pkt->icmp_cksum = in_cksum((unsigned short *) pkt, sizeof(packet));
   
  c = sendto(pingsock, packet, sizeof(packet), 0,
             (struct sockaddr *) &pingaddr, sizeof(struct sockaddr_in));
   
  if (c < 0 || c != sizeof(packet)) {
    if (c < 0)
      perror("ping: sendto");
    fprintf(stderr, "ping: write incomplete\n");
    exit(1);
  }
   
  signal(SIGALRM, noresp);
  alarm(2);                                     /* give the host 5000ms to respond */
  /* listen for replies */
  while (1) {
    struct sockaddr_in from;
    size_t fromlen = sizeof(from);
     
    if ((c = recvfrom(pingsock, packet, sizeof(packet), 0,
                      (struct sockaddr *) &from, &fromlen)) < 0) {
      if (errno == EINTR)
        continue;
      perror("ping: recvfrom");
      continue;
    }
    if (c >= 76) {                   /* ip + icmp */
      struct iphdr *iphdr = (struct iphdr *) packet;
       
      pkt = (struct icmp *) (packet + (iphdr->ihl << 2));      /* skip ip hdr */
      if (pkt->icmp_type == ICMP_ECHOREPLY) {
        unsigned char ret_type;
        //memcpy(&ret_type, &pkt + 8, 1);
        printf("ret_type: %d\n", ret_type);

        break;
      }
    }
  }
  printf("%s is alive!\n", hostname);
  return;
}
 
int main ()
{
  ping ("172.16.201.245");
 
}
