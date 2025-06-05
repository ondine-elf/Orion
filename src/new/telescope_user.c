#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "telescope.h"
#include "telescope_skeleton.h"

#define IFACE "wlp170s0" // TODO: Make this an argument


static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct packet_event_t *event = data;

    // Process the event
    struct in_addr src_addr;
    src_addr.s_addr = event->src_ip;
    printf("Received from: %s\n", inet_ntoa(src_addr));

    // Write PCAP here!

    return 0;
}

int main(int argc, char **argv) {

    struct telescope_bpf *skel;
    struct ring_buffer *rb = NULL;
    int ifindex;
    int err;

    // Grab interface
    ifindex = if_nametoindex(IFACE);
    if (ifindex == 0) {
        fprintf(stderr, "Error: Interface '%s' not found: %s\n", IFACE, strerror(errno));
        return EXIT_FAILURE;
    }

    // Load BPF skeleton
    skel = telescope_bpf__open();
    if (!skel) {
        fprintf(stderr, "Error: Failed to open BPF skeleton\n");
        return EXIT_FAILURE;
    }

    // Load and verify the BPF program
    err = telescope_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to load BPF skeleton: %s\n", strerror(-err));
        telescope_bpf__destroy(skel);
        return EXIT_FAILURE;
    }

    // Attach the BPF program
    err = telescope_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to attach BPF skeleton: %s\n", strerror(-err));
        telescope_bpf__destroy(skel);
        return EXIT_FAILURE;
    }

    /* Attach the XDP program to the specified interface */
    skel->links.telescope_capture = bpf_program__attach_xdp(skel->progs.telescope_capture, ifindex);
    if (!skel->links.telescope_capture)
    {
        err = -errno;
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
        telescope_bpf__destroy(skel);
        return EXIT_FAILURE;
    }

    printf("Successfully attached XDP program to interface %s\n", IFACE);

    rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf_map), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Error: Failed to create ring buffer: %s\n", strerror(errno));
        telescope_bpf__destroy(skel);
        return EXIT_FAILURE;
    }

    while (1) {
        err = ring_buffer__poll(rb, -1);
        if (err == -EINTR) {
            // Interrupted, continue polling
            continue;
        } else if (err < 0) {
            fprintf(stderr, "Error: Failed to poll ring buffer: %s\n", strerror(-err));
            break;
        }
    }

    ring_buffer__free(rb);
    telescope_bpf__destroy(skel);
    return EXIT_SUCCESS;
}