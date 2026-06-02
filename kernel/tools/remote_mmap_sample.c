#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define KSU_INSTALL_MAGIC1 0xDEADBEEF
#define KSU_INSTALL_MAGIC2 0xCAFEBABE

#define WKSU_MMAP_REMOTE_MAX_STATUS 64
#define KSU_MMAP_F_SNAPSHOT (1U << 0)
#define WKSU_MMAP_REMOTE_F_WRITABLE (1U << 0)
#define WKSU_MMAP_REMOTE_F_MAPPED   (1U << 1)
#define WKSU_MMAP_REMOTE_F_SNAPSHOT (1U << 2)

struct ksu_mmap_cmd {
	int32_t pid;
	uint32_t fd;
	uint64_t remote_addr;
	uint64_t length;
	uint32_t prot;
	uint32_t flags;
};

struct wksu_mmap_remote_info {
	uint64_t id;
	int32_t creator_pid;
	int32_t creator_tgid;
	int32_t fd;
	uint32_t flags;
	uint64_t remote_addr;
	uint64_t mapped_addr;
	uint64_t length;
	uint32_t nr_pages;
	uint32_t pinned_pages;
	uint64_t created_ns;
	uint64_t mapped_ns;
};

struct ksu_mmap_status_cmd {
	uint32_t max_entries;
	uint32_t entry_count;
	uint32_t total_entries;
	uint32_t _pad;
	struct wksu_mmap_remote_info entries[WKSU_MMAP_REMOTE_MAX_STATUS];
};

#define KSU_IOCTL_MMAP_REMOTE _IOWR('K', 33, struct ksu_mmap_cmd)
#define KSU_IOCTL_MMAP_REMOTE_STATUS _IOWR('K', 37, struct ksu_mmap_status_cmd)

static int parse_fd(const char *arg)
{
	char *end;
	long fd;

	if (!strcmp(arg, "auto")) {
		int out = -1;

		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, 0, &out);
		return out;
	}

	errno = 0;
	fd = strtol(arg, &end, 0);
	if (errno || !arg[0] || *end || fd < 0 || fd > INT32_MAX)
		return -1;

	return (int)fd;
}

static uint64_t parse_u64(const char *arg, const char *name)
{
	char *end;
	uint64_t value;

	errno = 0;
	value = strtoull(arg, &end, 0);
	if (errno || !arg[0] || *end) {
		fprintf(stderr, "invalid %s: %s\n", name, arg);
		exit(2);
	}

	return value;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage:\n"
		"  %s status <driver_fd|auto>\n"
		"  %s map <driver_fd|auto> <pid> <remote_addr> <length> [rw|snapshot]\n",
		prog, prog);
}

static int do_status(int driver_fd)
{
	struct ksu_mmap_status_cmd cmd;
	uint32_t i;

	memset(&cmd, 0, sizeof(cmd));
	cmd.max_entries = WKSU_MMAP_REMOTE_MAX_STATUS;

	if (ioctl(driver_fd, KSU_IOCTL_MMAP_REMOTE_STATUS, &cmd) < 0) {
		perror("KSU_IOCTL_MMAP_REMOTE_STATUS");
		return 1;
	}

	printf("remote mmap: total=%u returned=%u\n",
	       cmd.total_entries, cmd.entry_count);

	for (i = 0; i < cmd.entry_count; i++) {
		struct wksu_mmap_remote_info *e = &cmd.entries[i];

		printf("#%" PRIu64 " pid=%d tgid=%d fd=%d flags=%s%s%s remote=0x%" PRIx64
		       " mapped=0x%" PRIx64 " len=0x%" PRIx64
		       " pages=%u pinned=%u\n",
		       e->id, e->creator_pid, e->creator_tgid, e->fd,
		       (e->flags & WKSU_MMAP_REMOTE_F_WRITABLE) ? "W" : "R",
		       (e->flags & WKSU_MMAP_REMOTE_F_MAPPED) ? "|MAPPED" : "",
		       (e->flags & WKSU_MMAP_REMOTE_F_SNAPSHOT) ? "|SNAPSHOT" : "",
		       e->remote_addr, e->mapped_addr, e->length, e->nr_pages,
		       e->pinned_pages);
	}

	return 0;
}

static int do_map(int driver_fd, int argc, char **argv)
{
	struct ksu_mmap_cmd cmd;
	uint64_t remote_addr;
	uint64_t length;
	int prot = PROT_READ;
	uint32_t flags = 0;
	void *mapped;

	if (argc < 6 || argc > 7) {
		usage(argv[0]);
		return 2;
	}

	remote_addr = parse_u64(argv[4], "remote_addr");
	length = parse_u64(argv[5], "length");
	if (argc == 7) {
		if (!strcmp(argv[6], "rw"))
			prot |= PROT_WRITE;
		else if (!strcmp(argv[6], "snapshot"))
			flags = KSU_MMAP_F_SNAPSHOT;
		else {
			usage(argv[0]);
			return 2;
		}
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.pid = (int32_t)parse_u64(argv[3], "pid");
	cmd.remote_addr = remote_addr;
	cmd.length = length;
	cmd.prot = prot;
	cmd.flags = flags;

	if (ioctl(driver_fd, KSU_IOCTL_MMAP_REMOTE, &cmd) < 0) {
		perror("KSU_IOCTL_MMAP_REMOTE");
		return 1;
	}

	mapped = mmap(NULL, length, prot, MAP_SHARED, (int)cmd.fd, 0);
	if (mapped == MAP_FAILED) {
		perror("mmap");
		close((int)cmd.fd);
		return 1;
	}

	printf("remote=0x%" PRIx64 " len=0x%" PRIx64 " fd=%u local=%p\n",
	       remote_addr, length, cmd.fd, mapped);

	close((int)cmd.fd);
	munmap(mapped, length);
	return 0;
}

int main(int argc, char **argv)
{
	int driver_fd;

	if (argc < 3) {
		usage(argv[0]);
		return 2;
	}

	driver_fd = parse_fd(argv[2]);
	if (driver_fd < 0) {
		fprintf(stderr, "invalid driver fd: %s\n", argv[2]);
		return 2;
	}

	if (!strcmp(argv[1], "status"))
		return do_status(driver_fd);
	if (!strcmp(argv[1], "map"))
		return do_map(driver_fd, argc, argv);

	usage(argv[0]);
	return 2;
}
