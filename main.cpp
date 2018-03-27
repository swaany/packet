#include <iostream>
#include <pcap.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <cstdio>

using namespace std;

struct ip *iph;
struct tcphdr *tcph;

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void print_Mac_Add(u_int8_t *addr);
int lengthRet(int length, int minusLen);

int main(int argc, char* argv[]){

    pcap_t *pcd;
    pcap_loop(pcd, 0, callback, NULL);
    return 0;
}

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    struct ether_header *ep;
    unsigned short ether_type;
    int length=pkthdr->len;

    ep=(struct ether_header *)packet;
    cout<<"Ethernet Header"<<endl;
    cout<<"Dst Mac Address"<<endl;
    print_Mac_Add(ep->ether_dhost);
    cout<<"Src Mac Address : ";
    print_Mac_Add(ep->ether_shost);
    cout<<endl<<endl;

    packet += sizeof(struct ether_header);

    if(ether_type==ETHERTYPE_IP){
        iph=(struct ip *)packet;
        cout<<"IP Header"<<endl;
        cout<<"Src IP Address : "<<inet_ntoa(iph->ip_src)<<endl;
        cout<<"Dst IP Address : "<<inet_ntoa(iph->ip_dst)<<endl;
        cout<<endl<<endl;

        if(iph->ip_p==IPPROTO_TCP)
        {
            tcph=(struct tcphdr *)(packet+iph->ip_hl*4);
            cout<<"TCP Protocol"<<endl;
            cout<<"Src port : "<<ntohs(tcph->source)<<endl;
            cout<<"Dst port : "<<ntohs(tcph->dest)<<endl;
            cout<<endl<<endl;
        }
    }
}

void print_Mac_Add(u_int8_t *addr){
    int Mac=6;
    for(int i=0;i<Mac;i++){
        printf("%02x", addr[i]);
    }
    cout<<endl;
}
