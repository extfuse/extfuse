/*
 * This module has the kernel code for ExtFUSE
 */
#define KBUILD_MODNAME "extfuse"
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

#include <linux/version.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fs_stack.h>

#include <ebpf.h>
#include <extfuse.h>

#include "lookup.h"
#include "attr.h"

/********************************************************************
	HELPERS
*********************************************************************/

//#define DEBUGNOW

/* #define HAVE_PASSTHRU */

#ifndef DEBUGNOW
#define PRINTK(fmt, ...)
#else
#define PRINTK(fmt, ...)                                               \
                ({                                                      \
                        char ____fmt[] = fmt;                           \
                        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                                     ##__VA_ARGS__);                    \
                })
#endif

#define HANDLER(F) SEC("extfuse/"__stringify(F)) int bpf_func_##F

/*
	BPF_MAP_TYPE_PERCPU_HASH: each CPU core gets its own hash-table.
	BPF_MAP_TYPE_LRU_PERCPU_HASH: all cores share one hash-table but have they own LRU structures of the table.
*/
struct bpf_map_def SEC("maps") entry_map = {
	.type			= BPF_MAP_TYPE_HASH,	// simple hash list
	.key_size		= sizeof(lookup_entry_key_t),
	.value_size		= sizeof(lookup_entry_val_t),
	.max_entries	= MAX_ENTRIES,
	.map_flags		= BPF_F_NO_PREALLOC,
};

/* order of maps is important */
struct bpf_map_def SEC("maps") attr_map = {
	.type			= BPF_MAP_TYPE_HASH,	// simple hash list
	.key_size		= sizeof(lookup_attr_key_t),
	.value_size		= sizeof(lookup_attr_val_t),
	.max_entries	= MAX_ENTRIES,
	.map_flags		= BPF_F_NO_PREALLOC,
};

/* BPF_MAP_TYPE_PROG_ARRAY must ALWAYS be the last one */
struct bpf_map_def SEC("maps") handlers = {
   .type = BPF_MAP_TYPE_PROG_ARRAY,
   .key_size = sizeof(u32),
   .value_size = sizeof(u32),
   .max_entries = FUSE_OPS_COUNT << 1,
};

int SEC("extfuse") fuse_xdp_main_handler(void *ctx)
{
    struct extfuse_req *args = (struct extfuse_req *)ctx;
    int opcode = (int)args->in.h.opcode;

    PRINTK("Opcode %d\n", opcode);

	bpf_tail_call(ctx, &handlers, opcode);
	return UPCALL;
}

static int gen_entry_key(void *ctx, int param, const char *op, lookup_entry_key_t *key)
{
	int64_t ret = bpf_extfuse_read_args(ctx, NODEID, &key->nodeid, sizeof(u64));
	if (ret < 0) {
		PRINTK("%s: Failed to read nodeid: %d!\n", op, ret);
		return ret;
	}

	ret = bpf_extfuse_read_args(ctx, param, key->name, NAME_MAX);
	if (ret < 0) {
		PRINTK("%s: Failed to read param %d: %d!\n", op, param, ret);
		return ret;
	}

	return 0;	
}

static int gen_attr_key(void *ctx, int param, const char *op, lookup_attr_key_t *key)
{
	int64_t ret = bpf_extfuse_read_args(ctx, NODEID, &key->nodeid, sizeof(u64));
	if (ret < 0) {
		PRINTK("%s: Failed to read nodeid: %d!\n", op, ret);
		return ret;
	}

	return 0;
}

static void create_lookup_entry(struct fuse_entry_out *out,
				lookup_entry_val_t *entry, struct fuse_attr_out *attr)
{
	memset(out, 0, sizeof(*out));
	out->nodeid				= entry->nodeid;
	out->generation			= entry->generation;
	out->entry_valid		= entry->entry_valid;
	out->entry_valid_nsec	= entry->entry_valid_nsec;
	if (attr) {
		out->attr_valid			= attr->attr_valid;
		out->attr_valid_nsec	= attr->attr_valid_nsec;
    	out->attr.ino			= attr->attr.ino;
    	out->attr.mode			= attr->attr.mode;
    	out->attr.nlink			= attr->attr.nlink;
    	out->attr.uid			= attr->attr.uid;
    	out->attr.gid			= attr->attr.gid;
    	out->attr.rdev			= attr->attr.rdev;
    	out->attr.size			= attr->attr.size;
    	out->attr.blksize		= attr->attr.blksize;
    	out->attr.blocks		= attr->attr.blocks;
    	out->attr.atime			= attr->attr.atime;
    	out->attr.mtime			= attr->attr.mtime;
    	out->attr.ctime			= attr->attr.ctime;
    	out->attr.atimensec		= attr->attr.atimensec;
    	out->attr.mtimensec		= attr->attr.mtimensec;
    	out->attr.ctimensec		= attr->attr.ctimensec;
	}
}

HANDLER(FUSE_LOOKUP)(void *ctx)
{
	struct extfuse_req *args = (struct extfuse_req *)ctx;
	//unsigned numargs = args->in.numargs;
	int ret = UPCALL;

#ifdef DEBUGNOW
	u64 nid = args->in.h.nodeid;
	const char *name = (const char *)args->in.args[0].value;
	const unsigned int len = args->in.args[0].size - 1;

	PRINTK("LOOKUP: parent nodeid: 0x%llx name: %s(%d)\n",
			nid, name, len);
#endif

	lookup_entry_key_t key = {0, {0}};

	memset(key.name, 0, NAME_MAX);
	ret = gen_entry_key(ctx, IN_PARAM_0_VALUE, "LOOKUP", &key);
	if (ret < 0)
		return UPCALL;

	//PRINTK("key name: %s nodeid: 0x%llx\n", key.name, key.nodeid);
	
	lookup_entry_val_t *entry = bpf_map_lookup_elem(&entry_map, &key);
	if (!entry || entry->stale) {
		if (entry && entry->stale)
			PRINTK("LOOKUP: STALE key name: %s nodeid: 0x%llx\n",
				key.name, key.nodeid);
		else
			PRINTK("LOOKUP: No entry for node %s\n", key.name);
		return UPCALL;
	}

	PRINTK("LOOKUP(0x%llx, %s): nlookup %lld\n",
		key.nodeid, key.name, entry->nlookup);

	/* prepare output */
	struct fuse_entry_out out;
	uint64_t nodeid = entry->nodeid;


	/* negative entries have no attr */
	if (!nodeid) {
		create_lookup_entry(&out, entry, NULL);
	} else {
		lookup_attr_val_t *attr = bpf_map_lookup_elem(&attr_map, &nodeid);
		if (!attr || attr->stale) {
			if (attr && attr->stale)
				PRINTK("LOOKUP: STALE attr for node: 0x%llx\n", nodeid);
			else {
				PRINTK("LOOKUP: No attr for node 0x%llx\n", nodeid);
				return UPCALL;
			}
		}

		PRINTK("LOOKUP nodeid 0x%llx attr ino: 0x%llx\n",
				entry->nodeid, attr->out.attr.ino);

		create_lookup_entry(&out, entry, &attr->out);
	}

	/* populate output */
	ret = bpf_extfuse_write_args(ctx, OUT_PARAM_0, &out, sizeof(out));
	if (ret) {
		PRINTK("LOOKUP: Failed to write param 0: %d!\n", ret);
		return UPCALL;
	}

	/* atomic incr to avoid data races with user/other cpus */
	__sync_fetch_and_add(&entry->nlookup, 1);
	return RETURN;
}

HANDLER(FUSE_GETATTR)(void *ctx)
{
	lookup_attr_key_t key = {0};
	int ret = gen_attr_key(ctx, IN_PARAM_0_VALUE, "GETATTR", &key);
	if (ret < 0)
		return UPCALL;

	/* get cached attr value */
	lookup_attr_val_t *attr = bpf_map_lookup_elem(&attr_map, &key);
	if (!attr) {
		PRINTK("GETATTR: No attr for node 0x%llx\n", key.nodeid);
		return UPCALL;
	}

	/* check if the attr is stale */
	if (attr->stale) {
		/* what does the caller want? */
		struct fuse_getattr_in inarg;
		ret = bpf_extfuse_read_args(ctx, IN_PARAM_0_VALUE, &inarg, sizeof(inarg));
		if (ret < 0) {
			PRINTK("GETATTR: Failed to read param 0: %d!\n", ret);
			return UPCALL;
		}

		/* check if the attr that the caller wants is stale */
		if (attr->stale & inarg.dummy) {
			PRINTK("GETATTR: STALE attr mask: 0x%x stale: 0x%x for node: 0x%llx\n",
				inarg.dummy, attr->stale, key.nodeid);
			return UPCALL;
		}
	}

	PRINTK("GETATTR(0x%llx): %lld\n", key.nodeid, attr->out.attr.ino);

	/* populate output */
	ret = bpf_extfuse_write_args(ctx, OUT_PARAM_0, &attr->out, sizeof(attr->out));
	if (ret) {
		PRINTK("GETATTR: Failed to write param 0: %d!\n", ret);
		return UPCALL;
	}

	return RETURN;
}

HANDLER(FUSE_READ)(void *ctx)
{
	lookup_attr_key_t key = {0};
	int ret = gen_attr_key(ctx, IN_PARAM_0_VALUE, "READ", &key);
	if (ret < 0)
		return UPCALL;

	/* get cached attr value */
	lookup_attr_val_t *attr = bpf_map_lookup_elem(&attr_map, &key);
	if (!attr)
		return UPCALL;

#ifndef HAVE_PASSTHRU
	if (attr->stale & FATTR_ATIME)
			return UPCALL;
#endif

	/* mark as stale to prevent future references to cached attrs */
	__sync_fetch_and_add(&attr->stale, FATTR_ATIME);									
																			
	/* delete to prevent future cached attrs */
	//bpf_map_delete_elem(&attr_map, &key.nodeid);
	PRINTK("READ: marked stale attr for node 0x%llx\n", key.nodeid);

#ifdef HAVE_PASSTHRU
	return PASSTHRU;
#else
	return UPCALL;
#endif
}

HANDLER(FUSE_WRITE)(void *ctx)
{
	lookup_attr_key_t key = {0};
	int ret = gen_attr_key(ctx, IN_PARAM_0_VALUE, "WRITE", &key);
	if (ret < 0)
		return UPCALL;

	/* get cached attr value */
	lookup_attr_val_t *attr = bpf_map_lookup_elem(&attr_map, &key);
	if (!attr)
		return UPCALL;

#ifndef HAVE_PASSTHRU
	if (attr->stale & (FATTR_ATIME | FATTR_SIZE | FATTR_MTIME))
		return UPCALL;
#endif
	/* mark as stale to prevent future references to cached attrs */
	__sync_fetch_and_add(&attr->stale, (FATTR_ATIME | FATTR_SIZE | FATTR_MTIME));

	/* delete to prevent future cached attrs */
	//bpf_map_delete_elem(&attr_map, &key.nodeid);
	PRINTK("WRITE: marked stale attr for node 0x%llx\n", key.nodeid);

#ifdef HAVE_PASSTHRU
	return PASSTHRU;
#else
	return UPCALL;
#endif
}

HANDLER(FUSE_SETATTR)(void *ctx)
{
	lookup_attr_key_t key = {0};
	int ret = gen_attr_key(ctx, IN_PARAM_0_VALUE, "SETATTR", &key);
	if (ret < 0)
		return UPCALL;

	/* delete to prevent future cached attrs */
	bpf_map_delete_elem(&attr_map, &key.nodeid);
	PRINTK("SETATTR: deleted stale attr for node 0x%llx\n", key.nodeid);

	return UPCALL;
}

HANDLER(FUSE_GETXATTR)(void *ctx)
{
	PRINTK("GETXATTR: returning ENODATA\n");
	return -ENODATA;
}

HANDLER(FUSE_FLUSH)(void *ctx)
{
	return RETURN;
}

#ifndef DEBUGNOW
static int remove(void *ctx, int param, char *op, lookup_entry_key_t *key)
{																			
	memset(key->name, 0, NAME_MAX);											
																			
	if (gen_entry_key(ctx, param, op, key))								
		return UPCALL;														
																			
	/* lookup entry using its key <parent inode number, name> */			
	lookup_entry_val_t *entry = bpf_map_lookup_elem(&entry_map, key);		
	if (!entry || entry->stale)												
		return UPCALL;														
																			
	/* mark as stale to prevent future cached lookups for this entry */		
	__sync_fetch_and_add(&entry->stale, 1);									
																			
	PRINTK("%s key name: %s nodeid: 0x%llx", op, key->name, key->nodeid);		
	PRINTK("\t nlookup %lld Marked Stale!\n", entry->nlookup);				
																			
	/*																		
	 * if the entry is negative (i.e., nodeid=0) or has only one reference	
	 * (i.e., nlookup=1), delete it because the user-space does not track	
	 * negative entries, and knows about entries with single reference.		
	 */																		
	uint64_t nodeid = entry->nodeid;										
	if (nodeid) {															
		bpf_map_delete_elem(&attr_map, &nodeid);							
		PRINTK("\t Deleted stale attr for node 0x%llx\n", nodeid);			
	}																		
	if (entry->nlookup <= 1) {												
		bpf_map_delete_elem(&entry_map, key);								
		PRINTK("\t Deleted stale node 0x%llx\n", nodeid);					
	}																		
																			
	return UPCALL;															
}
#endif

HANDLER(FUSE_RENAME)(void *ctx)
{
#ifndef DEBUGNOW
	lookup_entry_key_t key = {0, {0}};										
	remove(ctx, IN_PARAM_1_VALUE, "RENAME", &key);
	return remove(ctx, IN_PARAM_2_VALUE, "RENAME", &key);
#else
	lookup_entry_key_t key = {0, {0}};

	/* do it for IN_PARAM_1_VALUE */
	memset(key.name, 0, NAME_MAX);
	if (gen_entry_key(ctx, IN_PARAM_1_VALUE, "RENAME", &key))
		return UPCALL;

	/* lookup by key */
	lookup_entry_val_t *entry = bpf_map_lookup_elem(&entry_map, &key);
	if (!entry || entry->stale)
		return UPCALL;

	/* mark as stale to prevent future lookups */
	__sync_fetch_and_add(&entry->stale, 1);

	PRINTK("RENAME key name: %s nodeid: 0x%llx nlookup %lld Marked Stale!\n",
		key.name, key.nodeid, entry->nlookup);

	/*
	 * if the entry is negative (i.e., nodeid=0) or has only one reference
	 * (i.e., nlookup=1), delete it because the user-space does not track
	 * negative entries, and knows about entries with single reference.
	 */
	uint64_t nodeid = entry->nodeid;
	if (nodeid) {
		bpf_map_delete_elem(&attr_map, &nodeid);
		PRINTK("\t Deleted stale attr for node 0x%llx\n", nodeid);
	}
	if (entry->nlookup <= 1) {
		bpf_map_delete_elem(&entry_map, &key);
		PRINTK("\t Deleted stale node 0x%llx\n", nodeid);
	}

	/* do it for IN_PARAM_2_VALUE */
	memset(key.name, 0, NAME_MAX);
	if (gen_entry_key(ctx, IN_PARAM_2_VALUE, "RENAME", &key))
		return UPCALL;

	/* lookup by key */
	entry = bpf_map_lookup_elem(&entry_map, &key);
	if (!entry || entry->stale)
		return UPCALL;

	/* mark as stale to prevent future lookups */
	__sync_fetch_and_add(&entry->stale, 1);

	PRINTK("RENAME key name: %s nodeid: 0x%llx nlookup %lld Marked Stale!\n",
		key.name, key.nodeid, entry->nlookup);

	/*
	 * if the entry is negative (i.e., nodeid=0) or has only one reference
	 * (i.e., nlookup=1), delete it because the user-space does not track
	 * negative entries, and knows about entries with single reference.
	 */
	nodeid = entry->nodeid;
	if (nodeid) {
		bpf_map_delete_elem(&attr_map, &nodeid);
		PRINTK("\t Deleted stale attr for node 0x%llx\n", nodeid);
	}
	if (entry->nlookup <= 1) {
		bpf_map_delete_elem(&entry_map, &key);
		PRINTK("\t Deleted stale node 0x%llx\n", nodeid);
	}

	return UPCALL;
#endif
}

HANDLER(FUSE_RMDIR)(void *ctx)
{
#ifndef DEBUGNOW
	lookup_entry_key_t key = {0, {0}};										
	return remove(ctx, IN_PARAM_0_VALUE, "RMDIR", &key);
#else
	lookup_entry_key_t key = {0, {0}};
	memset(key.name, 0, NAME_MAX);
	if (gen_entry_key(ctx, IN_PARAM_0_VALUE, "RMDIR", &key))
		return UPCALL;

	/* lookup by key */
	lookup_entry_val_t *entry = bpf_map_lookup_elem(&entry_map, &key);
	if (!entry || entry->stale)
		return UPCALL;

	/* mark as stale to prevent future lookups */
	__sync_fetch_and_add(&entry->stale, 1);

	PRINTK("RMDIR key name: %s nodeid: 0x%llx nlookup %lld Marked Stale!\n",
		key.name, key.nodeid, entry->nlookup);

	/*
	 * if the entry is negative (i.e., nodeid=0) or has only one reference
	 * (i.e., nlookup=1), delete it because the user-space does not track
	 * negative entries, and knows about entries with single reference.
	 */
	uint64_t nodeid = entry->nodeid;
	if (nodeid) {
		bpf_map_delete_elem(&attr_map, &nodeid);
		PRINTK("\t Deleted stale attr for node 0x%llx\n", nodeid);
	}
	if (entry->nlookup <= 1) {
		bpf_map_delete_elem(&entry_map, &key);
		PRINTK("\t Deleted stale node 0x%llx\n", nodeid);
	}

	return UPCALL;
#endif
}

HANDLER(FUSE_UNLINK)(void *ctx)
{
#ifndef DEBUGNOW
	lookup_entry_key_t key = {0, {0}};
	return remove(ctx, IN_PARAM_0_VALUE, "UNLINK", &key);
#else
	lookup_entry_key_t key = {0, {0}};
	memset(key.name, 0, NAME_MAX);
	if (gen_entry_key(ctx, IN_PARAM_0_VALUE, "UNLINK", &key))
		return UPCALL;

	/* lookup by key */
	lookup_entry_val_t *entry = bpf_map_lookup_elem(&entry_map, &key);
	if (!entry || entry->stale)
		return UPCALL;

	/* mark as stale to prevent future lookups */
	__sync_fetch_and_add(&entry->stale, 1);

	PRINTK("UNLINK key name: %s nodeid: 0x%llx nlookup %lld Marked Stale!\n",
		key.name, key.nodeid, entry->nlookup);

	uint64_t nodeid = entry->nodeid;
	if (nodeid) {
		bpf_map_delete_elem(&attr_map, &nodeid);
		PRINTK("\t Deleted stale attr for node 0x%llx\n", nodeid);
	}
	if (entry->nlookup <= 1) {
		bpf_map_delete_elem(&entry_map, &key);
		PRINTK("\t Deleted stale node 0x%llx\n", nodeid);
	}

	return UPCALL;
#endif
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = LINUX_VERSION_CODE;
