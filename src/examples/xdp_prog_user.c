#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAX_PACKET_SIZE 256

struct packet_event {
	__u64 timestamp_ns;
	__u32 pkt_len;
	__u8 pkt_data[MAX_PACKET_SIZE];
};

static int handle_event(void* ctx, void* data, size_t size) {
	struct packet_event* event = data;
	printf("Packet received at %llu ns, length = %lu\n",
	       event->timestamp_ns, event->pkt_len);

	return 0;
}

int main() {
	struct ring_buffer* rb = NULL;
	int map_fd;

	if ((map_fd = bpf_obj_get("/sys/fs/bpf/packet_events")) < 0) {
		perror("bpf_obj_get");
		exit(EXIT_FAILURE);
	}

	if (!(rb = ring_buffer__new(map_fd, handle_event, NULL, NULL))) {
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
	exit(EXIT_SUCCESS);
}