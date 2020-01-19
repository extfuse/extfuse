#ifndef __UTILS_H__
#define __UTILS_H__

#include <sys/types.h>

/* A simple error-handling function: print an error message based
   on the value in 'errno' and terminate the calling process */
#define errExit(msg)    do { perror(msg); goto error; } while (0)

enum {
	SETGROUPS_NONE = -1,
	SETGROUPS_DENY = 0,
	SETGROUPS_ALLOW = 1,
};

#define ROOT_UID "0"
#define ROOT_GID "0"

void stats(const char *msg);
int setgroups_control(pid_t pid, int action);
int update_uid_map(pid_t pid, const char *inside_id, int outside_id, int v);
int update_gid_map(pid_t pid, const char *inside_id, int outside_id, int v);
int update_map(char *mapping, char *map_file);
void reset_caps(void);
void display_creds_and_caps(char *str);
void print_mount_points(void);

#endif /* __UTILS_H__ */
