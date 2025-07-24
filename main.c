
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



void on_packet_received(u_char *user_data, const struct pcap_pkthdr *packet_header, const u_char *bytes) {
    assert(!user_data);

    printf("packet timestamp: %ds \n", packet_header->ts.tv_sec);
    printf("packet length: %d \n", packet_header->len);
    printf("packet cap: %d \n", packet_header->caplen);

    dump_bytes(bytes, (int)packet_header->len, 8);
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
int get_ethernet_device_name(char *buf) {

    bool found = false;

    char err[PCAP_ERRBUF_SIZE] = {0};

    pcap_if_t *interface_list;

    if (pcap_findalldevs(&interface_list, err) == PCAP_ERROR) err_exit(
        "pcap_findalldevs() failed: %s",
        err
    );

    for (pcap_if_t *node = interface_list; node; node = node->next) {
        if (strstr(node->description, "Ethernet")) {
            strcpy(buf, node->name);
            found = true;
            goto cleanup;
        }
    }

    

cleanup:
    pcap_freealldevs(interface_list);

    return found? 0 : PCAP_ERROR;
}

int main() {

    char ethernet_dev_name[ETH_DEV_NAME_BUF_SIZE] = {0};

    if (get_ethernet_device_name(ethernet_dev_name) == PCAP_ERROR) err_exit(
        "Couldn't find an ethernet device!"
    );

    char err_buf[PCAP_ERRBUF_SIZE] = {0};

    pcap_t* handle = pcap_open_live(ethernet_dev_name, PACKET_MAX_SIZE, IS_PROMISCUOUS, TIMEOUT_MILI, err_buf);
    if (!handle) {
        err_exit("Couldn't open device: %s\n", err_buf);
    }

    pcap_loop(
        handle,
        -1,
        on_packet_received,
        NULL
    );
}