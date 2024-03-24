#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <arpa/inet.h> // for htonl

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
    
int main(int argc, char* argv[]) {
    if (argc != 3) {
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
    packet.arp_.sip_ = htonl(Ip("0.0.0.0")); // Sender's IP address
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // Target's MAC address (Unknown)
    packet.arp_.tip_ = htonl(Ip(argv[2])); // Target's IP address (Supplied as argument)

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* recv_packet;
        int res = pcap_next_ex(handle, &header, &recv_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthHdr* eth_header = (EthHdr*)recv_packet;
        if (eth_header->type() == EthHdr::Arp) {
            ArpHdr* arp_header = (ArpHdr*)(recv_packet + sizeof(EthHdr));
            if (arp_header->op() == ArpHdr::Reply && arp_header->sip() == packet.arp_.tip_) {
                printf("Target MAC Address: %s\n", arp_header->smac().operator std::string().c_str());
                break;
            }
        }
    }

    pcap_close(handle);
}
