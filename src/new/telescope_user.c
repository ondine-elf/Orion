#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/utsname.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xpcapng.h"

#include "telescope.h"
#include "telescope_skeleton.h"

#define APP_INFO "Orion Telescope Capture v0.1"

#define IFACE "wlp170s0" // TODO: Make this an argument
#define OUT_FILE "telescope.pcapng" // TODO: Make this an argument

int return_code = EXIT_SUCCESS;

struct callback_ctx_t {
    size_t sz; // Size of this struct, for forward/backward compatibility
    struct xpcapng_dumper *dumper;
    uint32_t ifindex;
};

static int handle_event(void *_ctx, void *data, size_t data_sz) {
    struct callback_ctx_t *ctx = _ctx;
    struct packet_event_t *event = data;
    if (data_sz < sizeof(struct packet_event_t)) {
        fprintf(stderr, "Error: Received event data size is smaller than expected\n");
        return -1; // Invalid data size
    }

    // Process the event
    struct in_addr src_addr;
    src_addr.s_addr = event->src_ip;
    printf("Received from: %s\n", inet_ntoa(src_addr));

    // Write PCAP here!
    // Trying to use XPCAPNG for this
    xpcapng_dump_enhanced_pkt(
        ctx->dumper, 
        01, // interface id; TEMP TODO: Set this properly
        event->pkt_data, // Packet data
        event->pkt_len, // Packet length
        event->pkt_len, // Capture length (same as pkt_len for now)
        event->timestamp_ns, // Timestamp in nanoseconds
        &(struct xpcapng_epb_options_s){
            .flags = 0, // No flags for now
            .dropcount = 0, // No drops for now
            .packetid = NULL, // No packet ID for now
            .queue = NULL, // No queue for now
            .xdp_verdict = NULL, // No XDP verdict for now
            .comment = "Captured by Orion Telescope" // Comment
        }
    );

    return 0;
}

int main(int argc, char **argv) {

    struct telescope_bpf *skel = NULL;;
    struct ring_buffer *rb = NULL;
    struct xpcapng_dumper *dumper = NULL;
    int ifindex;
    int err;

    // Grab interface
    ifindex = if_nametoindex(IFACE);
    if (ifindex == 0) {
        fprintf(stderr, "Error: Interface '%s' not found: %s\n", IFACE, strerror(errno));
        return_code = EXIT_FAILURE;
        goto exit;
    }

    struct callback_ctx_t ctx = {
        .sz = sizeof(struct callback_ctx_t),
        .dumper = NULL, // Will be set later
        .ifindex = ifindex // Store the interface index
    };

    // Load BPF skeleton
    skel = telescope_bpf__open();
    if (!skel) {
        fprintf(stderr, "Error: Failed to open BPF skeleton\n");
        return_code = EXIT_FAILURE;
        goto exit;
    }

    // Load and verify the BPF program
    err = telescope_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to load BPF skeleton: %s\n", strerror(-err));
        return_code = EXIT_FAILURE;
        goto exit;
    }

    // Attach the BPF program
    err = telescope_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to attach BPF skeleton: %s\n", strerror(-err));
        return_code = EXIT_FAILURE;
        goto exit;
    }

    /* Attach the XDP program to the specified interface */
    skel->links.telescope_capture = bpf_program__attach_xdp(skel->progs.telescope_capture, ifindex);
    if (!skel->links.telescope_capture)
    {
        err = -errno;
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
        return_code = EXIT_FAILURE;
        goto exit;
    }

    printf("Successfully attached XDP program to interface %s\n", IFACE);

    // Open PCAPNG dumper
    // get hardware and os info
    struct utsname utinfo;
    char os_info[256]; 

    memset(&utinfo, 0, sizeof(utinfo));
    if (uname(&utinfo) < 0) {
        fprintf(stderr, "Error: Failed to get system information: %s\n", strerror(errno));
        return_code = EXIT_FAILURE;
        goto exit;
    }
    
    snprintf(os_info, sizeof(os_info), "%s %s %s", utinfo.sysname, utinfo.release, utinfo.version);
    printf("System Info: %s\n", os_info);

    // Open the dumper
    dumper = xpcapng_dump_open(
        "output.pcapng", // Output file name char*
        "pcapng comment", // comment char*
        utinfo.machine, // hardware char*
        os_info, // os char*
        APP_INFO // application info char*
    );

    if (!dumper) {
        fprintf(stderr, "Error: Failed to open PCAPNG dumper\n");
        return_code = EXIT_FAILURE;
        goto exit;
    }
    printf("Successfully opened PCAPNG dumper\n");

    ctx.dumper = dumper; // Set the dumper in the context

    // Open the ring buffer for events
    rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf_map), handle_event, &ctx, NULL);
    if (!rb) {
        fprintf(stderr, "Error: Failed to create ring buffer: %s\n", strerror(errno));
        return_code = EXIT_FAILURE;
        goto exit;
    }

    printf("Successfully created ring buffer for events\n");

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

exit:
    if (rb) {
        ring_buffer__free(rb);
    }
    if (skel) {
        telescope_bpf__destroy(skel);
    }
    xpcapng_dump_close(dumper);
    return EXIT_SUCCESS;
}