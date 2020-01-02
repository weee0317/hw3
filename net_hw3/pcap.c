#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <linux/if_link.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define STR_BUF 16
#define MAC_ADDRSTRLEN 20
#define IPADDR_STRLEN 20
#define SIZE 100
#define FILE_NAME_SIZE 20

static const char *ip_ntoa(void *i);
static const char *mac_ntoa(u_int8_t *d);
static void dump_ethernet(const u_char *content);
static void dump_ip(const u_char *content);
static void dump_tcp(const u_char *content);
static void dump_udp(const u_char *content);

struct ip_address
{
    char src_ip[IPADDR_STRLEN];
    char dst_ip[IPADDR_STRLEN];
    int count;
};
typedef struct ip_address ip_address;
ip_address ip_table[SIZE];
int ip_table_index=0;


int main(int argc,char **argv){
    char errbuf[PCAP_ERRBUF_SIZE]={0};
    const char filename[FILE_NAME_SIZE];

    strcpy(filename,argv[2]);

    pcap_t *handle = pcap_open_offline(filename,errbuf);
    if(!handle){
        fprintf(stderr,"pcap_open_offline(): %s\n",errbuf);
        exit(1);
    }
    printf("Open: %s\n",filename);

    int total = 0;
    //catch packet
    while(1){
        struct pcap_pkthdr *header = NULL;
        const u_char *content =NULL;
        int ret;
        ret = pcap_next_ex(handle,&header,&content);
        if(ret == 1){
            struct tm *ltime;
            char timestr[30];
            time_t local_tv_sec;

            local_tv_sec = header->ts.tv_sec;
            ltime = localtime(&local_tv_sec);
            strftime(timestr,sizeof timestr, "%Y/%m/%d %H:%M:%S",ltime);
            total++;

            printf("#####################TIME###################\n");
            printf("    %s.%.6d\n",timestr, (int)header->ts.tv_usec);

            //dump ethernet
            dump_ethernet(content);

            printf("\n");
        }
        if(ret == 0){
            printf("Timeout\n");
        }
        else if(ret == -1){
            fprintf(stderr,"pcap_next_ex(): %s\n",pcap_geterr(handle));
        }
        else if(ret == -2){
            printf("No more packet from %s\n",filename);
            break;
        }
    }
    for(int i=0;i<ip_table_index;i++){
        printf("[%s , %s]: %d\n",ip_table[i].src_ip,ip_table[i].dst_ip,ip_table[i].count);
    }
    printf("\n");
    printf("Read total: %d\n",total);

    return 0;
}

static const char *ip_ntoa(void *i) {
    static char ip[STR_BUF][INET_ADDRSTRLEN];
    static int which = -1;

    which = (which + 1 == STR_BUF ? 0 : which + 1);
    
    memset(ip[which], 0, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, i, ip[which], sizeof(ip[which]));
    
    return ip[which];
}//end ip_ntoa

static const char *mac_ntoa(u_int8_t *d) {
    static char mac[STR_BUF][MAC_ADDRSTRLEN];
    static int which = -1;

    which = (which + 1 == STR_BUF ? 0 : which + 1);

    memset(mac[which], 0, MAC_ADDRSTRLEN);
    snprintf(mac[which], sizeof(mac[which]), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

    return mac[which];
}//end mac_ntoa

static void dump_ethernet(const u_char *content) {
    char dst_mac[MAC_ADDRSTRLEN] = {0};
    char src_mac[MAC_ADDRSTRLEN] = {0};
    u_int16_t type;
    
    struct ether_header *ethernet = (struct ether_header *)content;

    //copy header
    snprintf(dst_mac, sizeof(dst_mac), "%s", mac_ntoa(ethernet->ether_dhost));
    snprintf(src_mac, sizeof(src_mac), "%s", mac_ntoa(ethernet->ether_shost));
    type = ntohs(ethernet->ether_type);
    
    if(type==ETHERTYPE_IP){
        dump_ip(content);
    }

    //print
    printf("#####################MAC####################\n");
    printf("Destination MAC Address:  %17s\n", dst_mac);
    printf("Source MAC Address:       %17s\n", src_mac);
    printf("\n");
    
}//end dump_ethernet

static void dump_ip(const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    u_char protocol = ip->ip_p;
    char src_ip[INET_ADDRSTRLEN] = {0};
    char dst_ip[INET_ADDRSTRLEN] = {0};

    //copy ip address
    snprintf(src_ip, sizeof(src_ip), "%s", ip_ntoa(&ip->ip_src));
    snprintf(dst_ip, sizeof(dst_ip), "%s", ip_ntoa(&ip->ip_dst));
    
    int flag = 0;
    for(int i=0;i<SIZE;i++){
        if(strcmp(ip_table[i].src_ip,src_ip)==0 && strcmp(ip_table[i].dst_ip,dst_ip)==0){
            flag = 1;
            ip_table[i].count++;
            break;
        }
    }
    if(!flag){
        ip_table[ip_table_index].count++;
        strcpy(ip_table[ip_table_index].src_ip,src_ip);
        strcpy(ip_table[ip_table_index].dst_ip,dst_ip);
        ip_table_index++;
    }
    //print
    printf("#####################IP#####################\n");
    printf("Source IP Address:       %15s\n", src_ip);
    printf("Destination IP Address:  %15s\n", dst_ip);
    
    switch (protocol) {
        case IPPROTO_UDP:
            printf("Protocol is UDP\n");
            dump_udp(content);
            break;
            
        case IPPROTO_TCP:
            printf("Protocol is TCP\n");
            dump_tcp(content);
            break;
    }//end switch

}//end dump_ip

static void dump_tcp(const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct tcphdr *tcp = (struct tcphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));
    
    //copy header
    u_int16_t source_port = ntohs(tcp->th_sport);
    u_int16_t destination_port = ntohs(tcp->th_dport);
    
    //print
    printf("Source Port:       %5u", source_port);
    printf("Destination Port:  %5u\n",destination_port);
}//end dump_tcp

static void dump_udp(const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));
    
    u_int16_t source_port = ntohs(udp->uh_sport);
    u_int16_t destination_port = ntohs(udp->uh_dport);

    
    printf("Source Port:       %5u\n", source_port);
    printf("Destination Port:  %5u\n", destination_port);
}//end dump_udp