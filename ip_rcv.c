#include "libbpf.h"
#include <unistd.h>

#define MAX_ERRNO 4095
bool IS_ERR(const void *ptr) {
     if((long)ptr >= -MAX_ERRNO && (long)ptr < 0) {
         return true;
     }
     return false;
}

long ERR_VAL(const void *ptr) {
      return (long) ptr;
}

int main() {
	const char *filename = "ip_rcv.bpf.o";
	struct bpf_object *obj;
	int err;

	obj = bpf_object__open(filename);
	if (!obj) {
		printf("error opening file %s\n", filename);
		return -1;
	}
	if (IS_ERR(obj)) {
		printf("error opening file %s %ld\n", filename, ERR_VAL(obj));
		return -1;
	}
	err = bpf_object__load(obj);
	if (err) {
		printf("error loading file\n");
		return -1;
	}
	struct bpf_program *prog = bpf_object__find_program_by_name(obj,"ip_rcv");
	if (prog == NULL) {
		printf("error finding program\n");
		return -1;
	}
	struct bpf_link *link = bpf_program__attach_kprobe(prog, false, "ip_rcv");
	if (link == NULL) {
		printf("error attaching kprobe\n");
		return -1;
	}
	sleep(1000);
	return 0;
}
