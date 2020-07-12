#ifndef __EBPF_LOOKUP_H__
#define __EBPF_LOOKUP_H__

typedef struct lookup_entry_key {
    /* parent node id */
    uint64_t nodeid;
    /* node name */
    char name[NAME_MAX];
} lookup_entry_key_t;

typedef struct lookup_entry_value {
	uint32_t stale;
    uint64_t nlookup;	/* ref cnt */
    uint64_t nodeid;	/* child node id */
    uint64_t generation;
    uint64_t entry_valid;
    uint32_t entry_valid_nsec;
} lookup_entry_val_t;

/* number of entries in hash lookup table */
#define MAX_ENTRIES (2 << 16)

#endif /* __EBPF_LOOKUP_H__ */
