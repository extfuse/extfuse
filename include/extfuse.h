#ifndef __EXTFUSE_H__
#define __EXTFUSE_H__

#include <linux/fuse.h>
#include <uapi/linux/extfuse.h>
#include <extfuse_i.h>

typedef struct extfuse_req *extfuse_req_t;

#define FUSE_LOOKUP   	   1
#define FUSE_FORGET   	   2
#define FUSE_GETATTR  	   3
#define FUSE_SETATTR  	   4
#define FUSE_READLINK 	   5
#define FUSE_SYMLINK  	   6
#define FUSE_MKNOD    	   8
#define FUSE_MKDIR    	   9
#define FUSE_UNLINK   	   10
#define FUSE_RMDIR    	   11
#define FUSE_RENAME   	   12
#define FUSE_LINK     	   13
#define FUSE_OPEN     	   14
#define FUSE_READ     	   15
#define FUSE_WRITE    	   16
#define FUSE_STATFS   	   17
#define FUSE_RELEASE       18
#define FUSE_FSYNC         20
#define FUSE_SETXATTR      21
#define FUSE_GETXATTR      22
#define FUSE_LISTXATTR     23
#define FUSE_REMOVEXATTR   24
#define FUSE_FLUSH         25
#define FUSE_INIT          26
#define FUSE_OPENDIR       27
#define FUSE_READDIR       28
#define FUSE_RELEASEDIR    29
#define FUSE_FSYNCDIR      30
#define FUSE_GETLK         31
#define FUSE_SETLK         32
#define FUSE_SETLKW        33
#define FUSE_ACCESS        34
#define FUSE_CREATE        35
#define FUSE_INTERRUPT     36
#define FUSE_BMAP          37
#define FUSE_DESTROY       38
#define FUSE_IOCTL         39
#define FUSE_POLL          40
#define FUSE_NOTIFY_REPLY  41
#define FUSE_BATCH_FORGET  42
#define FUSE_FALLOCATE     43
#define FUSE_READDIRPLUS   44
#define FUSE_RENAME2       45
#define FUSE_LSEEK         46
#define FUSE_OPS_COUNT		64

#endif /* __EXTFUSE_H__ */
