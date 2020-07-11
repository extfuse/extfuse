/* ExtFUSE library */
#ifndef __LIBEXTFUSE_H
#define __LIBEXTFUSE_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define PASSTHRU 1
#define RETURN 0
#define UPCALL -ENOSYS

#ifndef MAX_MAPS
#undef MAX_MAPS
#define MAX_MAPS 32
#endif

typedef struct ebpf_context {
        int ctrl_fd;
        int data_fd[MAX_MAPS];
}ebpf_context_t;

typedef struct ebpf_ctrl_key {
	int opcode;
} ebpf_ctrl_key_t;

typedef struct ebpf_handler {
	int prog_fd; 
} ebpf_handler_t;

/* init/finalize */
ebpf_context_t* ebpf_init(char *filename);
void ebpf_fini(ebpf_context_t *con);

/* updating rules */
int ebpf_ctrl_update(ebpf_context_t *context,
                ebpf_ctrl_key_t *key,
                ebpf_handler_t *handler);

int ebpf_ctrl_delete(ebpf_context_t *context,
                ebpf_ctrl_key_t *key);

/* Data handling abstractions */
int ebpf_data_next(ebpf_context_t *context, void *key, void *next, int idx);
int ebpf_data_lookup(ebpf_context_t *context, void *key, void *val, int idx);
int ebpf_data_update(ebpf_context_t *context, void *key, void *val, int idx,
		int overwrite);
int ebpf_data_delete(ebpf_context_t *context, void *key, int idx);

#endif
