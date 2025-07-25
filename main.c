
#include <pcap.h>
#include <winsock2.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define NETWORK_DEVICE "eth0"
#define PACKET_MAX_SIZE 65536
#define TIMEOUT_MILI 1000
#define IS_PROMISCUOUS true

#define err_exit(...) ({printf("ERROR: \n\t"__VA_ARGS__); printf("\n"); getchar(); exit(EXIT_FAILURE); })
#define print_todo(...) ({printf("TODO: \n\t"__VA_ARGS__); printf("\n"); })
#define assert(cond) if (!(cond)) err_exit("Assertion failed: "#cond)

void dump_bytes(const u_char *bytes, int len, int row_length) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", bytes[i]);
        if ((i + 1) % row_length == 0) printf("\n");
    }
    printf("\n");
}

typedef struct Userdata {
    int link_type;
} Userdata;

typedef enum DatalinkType {
    DL_LOOPBACK = DLT_NULL,
    DL_ETHERNET = DLT_EN10MB,
    DL_RAW = DLT_RAW,
    DL_WIFI = DLT_IEEE802_11
} DatalinkType;

#define PACKED __attribute__((packed))

typedef struct MacAddr {
    u_char data[6];
} MacAddr;


#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_IPV6 0x86DD
#define ETH_TYPE_ARP  0x0806


typedef uint16_t EtherType;

typedef struct EthPacket {
    MacAddr dst_addr;
    MacAddr src_addr;
    EtherType eth_type;
    const u_char *data;
} EthPacket;

const char *get_dl_name(DatalinkType t) {
    switch (t) {
        case DL_LOOPBACK: return "loopback";
        case DL_ETHERNET: return "ethernet";
        case DL_RAW:      return "raw";
        case DL_WIFI:     return "wifi";
        default:          return "Invalid DatalinkType";
    }
}

const char *get_eth_type_name(EtherType t) {
    switch (t) {
        case ETH_TYPE_IPV4: return "IPv4";
        case ETH_TYPE_IPV6: return "IPv6";
        case ETH_TYPE_ARP:  return "ARP";
        default:            return "Invalid EtherType";
    }
} 

void print_mac_addr(MacAddr addr) {
    for (int i = 0; i < 6; i++) {
        if (i > 0) printf(":");
        printf("%02X", addr.data[i]);
    }
    printf("\n");
}

EthPacket parse_eth_packet(const u_char *bytes) {
    EthPacket p = {.data = bytes + 14};
    memcpy(p.dst_addr.data, bytes, 6);
    memcpy(p.src_addr.data, bytes + 6, 6);
    memcpy(&p.eth_type, bytes + 12, 2);
    p.eth_type = ntohs(p.eth_type);

    return p;
}

void analyze_and_print_packet(const struct pcap_pkthdr *packet_header,  const u_char *bytes, const Userdata *data) {
    printf("PACKET: \n\tlen: %d \n", packet_header->len);

    DatalinkType link_type = data->link_type;

    switch (link_type) {
        case DL_ETHERNET:;
            EthPacket p = parse_eth_packet(bytes);
            printf("\tdst MAC address: ");
            print_mac_addr(p.dst_addr);
            printf("\tsrc MAC address: ");
            print_mac_addr(p.src_addr);
            printf("eth type: %s (id: %d) \n", get_eth_type_name(p.eth_type), p.eth_type);
            
        break;
        
        default:
            err_exit("Unsupported link type: %s \n", get_dl_name(link_type));
        break;
    }
    

}

void on_packet_received(u_char *user_data, const struct pcap_pkthdr *packet_header, const u_char *bytes) {
    
    printf("Received packet! \n");
    
    assert(user_data);
    Userdata *data = (Userdata *)user_data;

    analyze_and_print_packet(packet_header, bytes, data);
}

void print_devices(void) {
    char err[PCAP_ERRBUF_SIZE] = {0};

    pcap_if_t *interface_list;

    if (pcap_findalldevs(&interface_list, err) == PCAP_ERROR) err_exit(
        "pcap_findalldevs() failed: %s",
        err
    );

    for (pcap_if_t *node = interface_list; node; node = node->next) {
        printf("Device name: %s \n", node->name);
        printf("Description: %s \n", node->description);
    }

    pcap_freealldevs(interface_list);
}

#define ETH_DEV_NAME_BUF_SIZE 512


typedef enum DeviceType {
    DEV_ETH,
    DEV_WIFI,
    DEV_END
} DeviceType;

#define DEVICE_ETH 1
#define DEVICE_WIFI 2
void get_device_name(char *buf) {

    char err[PCAP_ERRBUF_SIZE] = {0};

    pcap_if_t *interface_list;

    if (pcap_findalldevs(&interface_list, err) == PCAP_ERROR) err_exit(
        "pcap_findalldevs() failed: %s",
        err
    );

    
    int i = 0;
    for (pcap_if_t *node = interface_list; node; node = node->next) {
        printf("%d: %s \n", i, node->description);
        i++;
    }
    
    printf("Select a device by index (0-%d): ", i - 1);
    int idx;
    scanf("%d", &idx);

    assert(idx < i && idx >= 0);

    for (pcap_if_t *node = interface_list; node; node = node->next) {
        if (idx == 0) {
            strcpy(buf, node->name);
            return;
        }
        idx--;
    }

}

int main() {

    char ethernet_dev_name[ETH_DEV_NAME_BUF_SIZE] = {0};

    get_device_name(ethernet_dev_name);

    char err_buf[PCAP_ERRBUF_SIZE] = {0};


    pcap_t* handle = pcap_open_live(ethernet_dev_name, PACKET_MAX_SIZE, IS_PROMISCUOUS, TIMEOUT_MILI, err_buf);
    if (!handle) {
        err_exit("Couldn't open device: %s\n", err_buf);
    }

    int link_type = pcap_datalink(handle);

    Userdata user_data = {
        .link_type = link_type
    };

    printf("Sniffing... \n");
    pcap_loop(
        handle,
        -1,
        on_packet_received,
        (u_char *)&user_data
    );
}