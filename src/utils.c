/* Run this program as root.  As mount and unshare requires higher privileges. */
#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/mount.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <ebpf.h>

#include <mntent.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <grp.h>

#include <utils.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static const char *setgroups_strings[] =
{
	[SETGROUPS_DENY] = "deny",
	[SETGROUPS_ALLOW] = "allow"
};

int setgroups_control(pid_t pid, int action)
{
    char path[PATH_MAX];
	const char *cmd;
	int fd;

	if (action < 0 || (size_t) action >= ARRAY_SIZE(setgroups_strings))
		return -1;

	cmd = setgroups_strings[action];

    snprintf(path, PATH_MAX, "/proc/%ld/setgroups", (long) pid);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			return -1;
		fprintf(stderr, "cannot open %s: %s!\n",
			path, strerror(errno));
		return -1;
	}

	if (write(fd, cmd, strlen(cmd)) != strlen(cmd)) {
		fprintf(stderr, "write failed %s:%s!\n",
				path, strerror(errno));
		fprintf(stderr, "%s\n", cmd);
		return -1;
	}
	close(fd);
	return 0;
}

/* Update the mapping file 'map_file', with the value provided in
   'mapping', a string that defines a UID or GID mapping. A UID or
   GID mapping consists of one or more newline-delimited records
   of the form:

       ID_inside-ns    ID-outside-ns   length

   Requiring the user to supply a string that contains newlines is
   of course inconvenient for command-line use. Thus, we permit the
   use of commas to delimit records in this string, and replace them
   with newlines before writing the string to the file. */
int update_map(char *mapping, char *map_file)
{
    int fd, j;
    size_t map_len;     /* Length of 'mapping' */

    /* Replace commas in mapping string with newlines */
    map_len = strlen(mapping);
    for (j = 0; j < map_len; j++)
        if (mapping[j] == ',')
            mapping[j] = '\n';

    fd = open(map_file, O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "open %s: %s\n", map_file, strerror(errno));
        return -1;
    }

    if (write(fd, mapping, map_len) != map_len) {
        fprintf(stderr, "write %s: %s\n", map_file, strerror(errno));
        return -1;
    }

    close(fd);
	return 0;
}

int update_uid_map(pid_t pid, const char *inside_id, int outside_id, int v)
{
    char map_path[PATH_MAX];
    char uid_map[512];
	size_t len = strlen(inside_id);
    sprintf(map_path, "/proc/%ld/uid_map", (long) pid);
    sprintf(uid_map, "%s %ld %ju", inside_id, (long) outside_id, len);
    if (update_map(uid_map, map_path))
		return -1;
    if (v)
		printf("Mapped outside user %ld to inside user %s(%d): %s\n",
			(long) outside_id, inside_id, len, uid_map);
	return 0;
}

int update_gid_map(pid_t pid, const char *inside_id, int outside_id, int v)
{
    char map_path[PATH_MAX];
    char gid_map[512];
	size_t len = strlen(inside_id);
    sprintf(map_path, "/proc/%ld/gid_map", (long) pid);
    sprintf(gid_map, "%s %ld %ju", inside_id, (long) outside_id, len);
    if (update_map(gid_map, map_path))
		return -1;
    if (v)
		printf("Mapped outside group %ld to inside group %s(%d): %s\n",
			(long) outside_id, inside_id, len, gid_map);
	return 0;
}

void reset_caps(void)
{
	struct __user_cap_header_struct cap_hdr;
	cap_hdr.version = _LINUX_CAPABILITY_VERSION_3;
	cap_hdr.pid = 0;
	struct __user_cap_data_struct cap_data[_LINUX_CAPABILITY_U32S_3];
	bzero(cap_data, sizeof(cap_data));
	if (capset(&cap_hdr, &cap_data[0]) < 0) {
	        perror("capset()");
	}
}

void display_creds_and_caps(char *str)
{
    cap_t caps;
    char *s;

    caps = cap_get_proc();
    if (caps == NULL) {
		perror("cap_get_proc");
		return;
	}

    s = cap_to_text(caps, NULL);
    if (s == NULL) {
        perror("cap_to_text");
		return;
	}

	printf("Credentials and Capabilities %s\n\n", s);

    cap_free(caps);
    cap_free(s);
}

void print_mount_points(void)
{
  struct mntent *ent;
  FILE *aFile;

  aFile = setmntent("/proc/mounts", "r");
  if (aFile == NULL) {
	perror("setmntent");
	return;
  }

  printf("Mount Points:\n");
  while (NULL != (ent = getmntent(aFile)))
	printf("\t%s %s\n", ent->mnt_fsname, ent->mnt_dir);
  endmntent(aFile);
}

void stats(const char *msg)
{
	printf("\n%s\n", msg);
	printf("UID: %d EUID: %d\n", getuid(), geteuid());
	printf("PID: %d TID: %ld\n", getpid(), syscall(SYS_gettid));
	print_mount_points();
	display_creds_and_caps("");
}

