/* ExtFUSE library */
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <ebpf.h>
#include <libbpf.h>
#include <bpf_load.h>

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,9,0)
#define bpf_map_update_elem bpf_update_elem
#define bpf_map_lookup_elem bpf_lookup_elem
#define bpf_map_delete_elem bpf_delete_elem
#endif

//#define DEBUG

#ifdef DEBUG
#define DBG(fmt, ...)   fprintf(stdout, fmt, ##__VA_ARGS__)
#else
#define DBG(fmt, ...)
#endif
#define ERROR(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

ebpf_context_t* ebpf_init(char *filename)
{
	int i;
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    ebpf_context_t *con;
	uid_t uid=getuid();

	if (!uid && setrlimit(RLIMIT_MEMLOCK, &r)) {
		ERROR("Failed to increase rlimits: %s\n", strerror(errno));
    }

	con = (ebpf_context_t* ) calloc(1, sizeof(ebpf_context_t));
	if (!con) {
		ERROR("Failed to allocate memory\n");
		goto err;
	}

    if (load_bpf_file(filename)) {
		ERROR("Failed to load bpf file %s: %s\n",
				filename, strerror(errno));
		goto err;
    }

    if (!prog_fd[0] || !map_fd[0]) {
		ERROR("invalid prog_fd[0]=%d and map_fd[0]=%d\n",
			prog_fd[0], map_fd[0]);
		goto err;
    }

	con->ctrl_fd = prog_fd[0];
	for (i = 0; i < MAX_MAPS; i++)
		con->data_fd[i] = map_fd[i];

	DBG("main context created 0x%lx ctrl_fd=%d data_fd=%d\n",
		(unsigned long)con, con->ctrl_fd, con->data_fd);
    return con;

err:
	if (con)
		free(con);
	return NULL;
}

void ebpf_fini(ebpf_context_t *con)
{
	int i;
	DBG("freeing main context 0x%lx ctrl_fd=%d data_fd=%d\n",
		(unsigned long)con, con->ctrl_fd, con->data_fd);
	if (con->ctrl_fd && close(con->ctrl_fd))
		ERROR("Failed to close ctrl_fd %d: %s!",
			con->ctrl_fd, strerror(errno));
	for (i = 0; i < MAX_MAPS; i++)
		if (con->data_fd[i] && close(con->data_fd[i]))
			ERROR("Failed to close data_fd %d: %s!",
				con->data_fd[i], strerror(errno));
	free(con);
	return;
}

/* Control handling abstractions */
int ebpf_ctrl_update(ebpf_context_t *context,
                ebpf_ctrl_key_t *key,
                ebpf_handler_t *handler)
{
	unsigned long long flags = BPF_ANY;
	return bpf_map_update_elem(context->ctrl_fd, (void *) key,
                        (void *) handler, flags);
}

int ebpf_ctrl_delete(ebpf_context_t *context,
                ebpf_ctrl_key_t *key)
{
	return bpf_map_delete_elem(context->ctrl_fd, (void *) key);
}

int ebpf_data_next(ebpf_context_t *context, void *key, void *next, int idx)
{
	DBG("ebpf_next_data fd: %d\n", context->data_fd[idx]);
	return bpf_map_get_next_key(context->data_fd[idx], &key, &next);
}

/* Data handling abstractions */
int ebpf_data_lookup(ebpf_context_t *context, void *key, void *val, int idx)
{
	DBG("ebpf_data_lookup fd: %d\n", context->data_fd[idx]);
	return bpf_map_lookup_elem(context->data_fd[idx], key, val);
}

int ebpf_data_update(ebpf_context_t *context, void *key, void *val, int idx,
		int overwrite)
{
	unsigned long long flags = BPF_NOEXIST;
	if (overwrite)
		flags = BPF_ANY;
	DBG("ebpf_data_update fd: %d\n", context->data_fd[idx]);
	return bpf_map_update_elem(context->data_fd[idx], key, val, flags);
}

int ebpf_data_delete(ebpf_context_t *context, void *key, int idx)
{
	DBG("ebpf_data_delete fd: %d\n", context->data_fd[idx]);
	return bpf_map_delete_elem(context->data_fd[idx], key);
}

