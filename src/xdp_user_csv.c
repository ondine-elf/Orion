/*
    The following program just reads in the flow map created in
    xdp_prog.c and writes the entries to a csv file. It is just a
    proof of concept program meant to show how to access a pinned
    bpf map from user-space.

    To compile: gcc -Wall -Wextra -O2 src/xdp_user_csv.c -o dump -lbpf
    To run: sudo ./dump
*/

#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#define MAP_PATH "/sys/fs/bpf/flow_map"
#define CSV_OUTPUT "data/flow_data.csv"

struct flow_key_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

struct flow_value_t {
    __u64 packets;
    __u64 bytes;
};

int main() {
    // Open the pinned flow map created in xdp_prog.c
    int map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        exit(EXIT_FAILURE);
    }

    // Opening the csv file to be written to
    struct flow_key_t key = {0}, next_key;
    struct flow_value_t value;
    FILE* fp = fopen(CSV_OUTPUT, "w");
    if (!fp) {
        perror("fopen");
        close(map_fd);
        exit(EXIT_FAILURE);
    }

    // Write the flow data after converting the IPs to presentation form
    fprintf(fp, "src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes\n");
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];

            // inet_ntop expects network byte order so no need to call ntohl
            inet_ntop(AF_INET, &next_key.src_ip, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &next_key.dst_ip, dst_ip, sizeof(dst_ip));
            __u16 src_port = ntohs(next_key.src_port);
            __u16 dst_port = ntohs(next_key.dst_port);

            fprintf(fp, "%s,%s,%u,%u,%u,%llu,%llu\n",
                    src_ip, dst_ip, src_port, dst_port, next_key.protocol,
                    value.packets, value.bytes);
        }
        key = next_key;
    }

    fclose(fp);
    close(map_fd);

    exit(EXIT_SUCCESS);
}