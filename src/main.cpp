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

std::string target_mac(const char *interface) {
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
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    
    const char *interface = argv[1];
    std::string macAddress = target_mac(interface);
    
    printf("target mac = %s\n", macAddress.c_str());
    
    EthArpPacket packet;
    
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // Broadcast MAC address
    packet.eth_.smac_ = Mac("00:00:00:00:00:00"); // Sender's MAC address
    packet.eth_.type_ = htons(EthHdr::Arp);
    
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac("00:00:00:00:00:00"); // Sender's MAC address
    packet.arp_.sip_ = htonl(Ip(argv[2])); // Sender's IP address
    packet.arp_.tmac_ = Mac(macAddress.c_str()); // Target's MAC address (Unknown)
    packet.arp_.tip_ = htonl(Ip(argv[3])); // Target's IP address (Supplied as argument)
    
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    
    pcap_close(handle);
}
