#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <zlib.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAX_PACKET_SIZE 256

struct packet_event {
	__u64 timestamp_ns;
	__u32 pkt_len;
	__u8 pkt_data[MAX_PACKET_SIZE];
};

struct pcap_global_header {
	uint32_t magic_number;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t  thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t network;
};

struct pcap_packet_header {
	uint32_t ts_sec;
	uint32_t ts_usec;
	uint32_t incl_len;
	uint32_t orig_len;
};

static gzFile pcap_gz = NULL;

static int handle_event(void* ctx, void* data, size_t size) {
	struct packet_event* event = data;

	struct timespec ts;
	ts.tv_sec = event->timestamp_ns / 1000000000ULL;
	ts.tv_nsec = event->timestamp_ns % 1000000000ULL;

	struct pcap_packet_header pkt_hdr = {
		.ts_sec = (uint32_t)ts.tv_sec,
		.ts_usec = (uint32_t)(ts.tv_nsec / 1000),
		.incl_len = event->pkt_len,
		.orig_len = event->pkt_len
	};

	if (gzwrite(pcap_gz, &pkt_hdr, sizeof(pkt_hdr)) != sizeof(pkt_hdr)) {
		perror("gzwrite (pkt_hdr)");
		return -1;
	}

	if (gzwrite(pcap_gz, event->pkt_data, event->pkt_len) != (int)event->pkt_len) {
		perror("gzwrite (pkt_data)");
		return -1;
	}

	printf("Packet written: %u bytes at %llu ns\n", event->pkt_len, event->timestamp_ns);
	return 0;
}

int main() {
	struct ring_buffer* rb = NULL;
	int map_fd;

	pcap_gz = gzopen("output.pcap.gz", "wb");
	if (!pcap_gz) {
		perror("gzopen");
		exit(EXIT_FAILURE);
	}

	struct pcap_global_header gh = {
		.magic_number = 0xa1b2c3d4,
		.version_major = 2,
		.version_minor = 4,
		.thiszone = 0,
		.sigfigs = 0,
		.snaplen = MAX_PACKET_SIZE,
		.network = 1 // Ethernet
	};

	if (gzwrite(pcap_gz, &gh, sizeof(gh)) != sizeof(gh)) {
		perror("gzwrite (global header)");
		exit(EXIT_FAILURE);
	}

	// Attach to ring buffer
	if ((map_fd = bpf_obj_get("/sys/fs/bpf/packet_events")) < 0) {
		perror("bpf_obj_get");
		exit(EXIT_FAILURE);
	}

	rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		exit(EXIT_FAILURE);
	}

	while (1) {
		int err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) break;
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

	ring_buffer__free(rb);
	gzclose(pcap_gz);

	exit(EXIT_SUCCESS);
}
