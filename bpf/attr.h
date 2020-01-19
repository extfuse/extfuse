#ifndef __EBPF_ATTR_H__
#define __EBPF_ATTR_H__

#include <fuse.h>

typedef struct lookup_attr_key {
    /* node id */
    uint64_t nodeid;
} lookup_attr_key_t;

typedef struct lookup_attr_value {
	uint32_t stale;
	/* node attr */
    struct fuse_attr_out out;
} lookup_attr_val_t;

/* number of entries in hash lookup table */
#undef MAX_ENTRIES
#define MAX_ENTRIES (2 << 16)

#endif /* __EBPF_ATTR_H__ */
