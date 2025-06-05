#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_RING_BUFFER_ENTRIES 16384

typedef struct {
    __u64 timestamp_ns;
    __u32 pkt_len;
    //__u8 pkt_data[];
} packet_event_t;

static int handle_event(void* ctx, void* data, size_t data_sz) {
    if (data_sz < sizeof(packet_event_t)) {
        fprintf(stderr, "event too small: %zu bytes\n", data_sz);
        return 0;
    }

    packet_event_t* event = data;
    printf("Packet length: %u bytes, timestamp: %llu ns\n",
           event->pkt_len, (unsigned long long)event->timestamp_ns);
    return 0;
}


int main(int argc, char** argv) {
    struct ring_buffer* rb;
    int map_fd;
    int err;

    map_fd = bpf_obj_get("/sys/fs/bpf/ring_buffer");
    if (map_fd < 0) {
        perror("Failed to open ring buffer map");
        exit(EXIT_FAILURE);
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        exit(EXIT_FAILURE);
    }

    printf("listening for packet events...\n");

    while (1) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    close(map_fd);

    exit(EXIT_SUCCESS);
}