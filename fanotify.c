#define _GNU_SOURCE     /* Needed to get O_LARGEFILE definition */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fanotify.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>

static int out_off = 0;
static int fan_response = FAN_ALLOW;
static char *app_name = NULL;

int fa_printf(char *fmt, ...)
{
	va_list ap;
	int len = 0;

	va_start(ap, fmt);
	if (!out_off)
		len = vfprintf(stdout, fmt, ap); 
	va_end(ap);

	return len;
}

/* Read all available fanotify events from the file descriptor 'fd' */
	static void
handle_events(int fd)
{
	const struct fanotify_event_metadata *metadata;
	struct fanotify_event_metadata buf[8192];
	ssize_t len;
	char path[PATH_MAX];
	ssize_t path_len;
	char procfd_path[PATH_MAX];
	struct fanotify_response response;

	/* Loop while events can be read from fanotify file descriptor */

	for(;;) {
		/* Read some events */
		len = read(fd, (void *) &buf, sizeof(buf));
		if (len == -1 && errno != EAGAIN) {
			perror("read");
			exit(EXIT_FAILURE);
		}
		/* Check if end of available data reached */
		if (len <= 0)
			break;

		/* Point to the first event in the buffer */
		metadata = buf;
		/* Loop over all events in the buffer */
		while (FAN_EVENT_OK(metadata, len)) {
			/* Check that run-time and compile-time structures match */
			if (metadata->vers != FANOTIFY_METADATA_VERSION) {
				fprintf(stderr,
						"Mismatch of fanotify metadata version.\n");
				exit(EXIT_FAILURE);
			}

			/* metadata->fd contains either FAN_NOFD, indicating a
			   queue overflow, or a file descriptor (a nonnegative
			   integer). Here, we simply ignore queue overflow. */
			if (metadata->fd >= 0) {
				/* Handle open permission event */
				if (metadata->mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM)) {
					response.fd = metadata->fd;
					response.response = fan_response;
					write(fd, &response,
							sizeof(struct fanotify_response));
					if (metadata->mask & FAN_OPEN_PERM)
						fa_printf("FAN_OPEN_PERM: ");
					if (metadata->mask & FAN_ACCESS_PERM)
						fa_printf("FAN_ACCESS_PERM: ");
					if (metadata->mask & FAN_OPEN_EXEC_PERM)
						fa_printf("FAN_OPEN_EXEC_PERM: ");

				}

				/* Handle closing of writable file event */
				if (metadata->mask & FAN_CLOSE_WRITE)
					fa_printf("FAN_CLOSE_WRITE: ");
				if (metadata->mask & FAN_OPEN_EXEC)
					fa_printf("FAN_OPEN_EXEC: ");

				/* Retrieve and print pathname of the accessed file */
				snprintf(procfd_path, sizeof(procfd_path),
						"/proc/self/fd/%d", metadata->fd);
				path_len = readlink(procfd_path, path,
						sizeof(path) - 1);
				if (path_len == -1) {
					perror("readlink");
					exit(EXIT_FAILURE);
				}

				path[path_len] = '\0';
				fa_printf("File %s\n", path);

				/* Close the file descriptor of the event */
				close(metadata->fd);
			}
			/* Advance to next event */
			metadata = FAN_EVENT_NEXT(metadata, len);
		}
	//	sleep(300);
	}
}

static int add_mark(int fd, char *path)
{
	int ret = -1;
	if (fd < 0 || !path)
		return ret;

	fprintf(stdout, "add mark: %s\n", path);
	ret = fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
			FAN_OPEN_EXEC_PERM,  AT_FDCWD,
			//FAN_OPEN_PERM | FAN_OPEN_EXEC | FAN_CLOSE_WRITE | FAN_ACCESS_PERM |
			//FAN_OPEN_EXEC_PERM, AT_FDCWD,
			path);
	if (ret < 0) { 
		perror("fanotify_mark");
		exit(EXIT_FAILURE);
	}

	return ret;
}

static int add_mount_mark(int fa_fd, char *mount_path)
{
	FILE *fd  = NULL;
	char line[1024];
	char dev[64];
	char path[1024];
	char *ptr = NULL;
	int len = 0;
	int ret = -1;

	if (mount_path) {
		ret = add_mark(fa_fd, mount_path);
	} else {
		if (!(fd = fopen("/proc/mounts", "r")))
			return ret; 
		while (!ferror(fd) && !feof(fd)) {
			if (!fgets(line, sizeof(line), fd))
				continue;

			sscanf(line, "%1024s %4096s\n", dev, path);
			if (strncmp(dev, "/dev/", 5))
				continue; 
			ret = add_mark(fa_fd, path);
			if (ret < 0)
				break;
		}

		if (!feof(fd))
			ret = 0;

		fclose(fd);
	}
	return ret;
}

void usage(void) 
{
	fprintf(stderr, "Usage: %s [-h] [-s] [-r allow|deny] [-d mount_point]\n",
				app_name);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	char buf;
	int fd, poll_num;
	nfds_t nfds;
	struct pollfd fds[2];
	char *mount_path = NULL;
	int opt = 0;

	app_name = argv[0];
	while ((opt = getopt(argc, argv, "sr:d:")) != -1) {
		switch (opt) {
		case 's':
			out_off = 1;
			break;
		case 'r':
			if (!strcmp(optarg, "allow")) {
				fan_response = FAN_ALLOW;
			} else if (!strcmp(optarg, "deny")) {
				fan_response = FAN_DENY;
			} else {
				usage();
			}
			break;
		case 'd':
			mount_path = strdup(optarg);
			break;
		case 'h':      //fall through
		default: /* '?' */
			usage();
			break;
		}
	}
	if (optind != argc) 
		usage();

	printf("Press enter key to terminate.\n");

	/* Create the file descriptor for accessing the fanotify API */
	fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK,
			O_RDONLY | O_LARGEFILE);
	if (fd == -1) {
		perror("fanotify_init");
		exit(EXIT_FAILURE);
	}

	add_mount_mark(fd, mount_path);

	/* Prepare for polling */
	nfds = 2;
	/* Console input */
	fds[0].fd = STDIN_FILENO;
	fds[0].events = POLLIN;

	/* Fanotify input */
	fds[1].fd = fd;
	fds[1].events = POLLIN;

	/* This is the loop to wait for incoming events */
	printf("Listening for events.\n");
	while (1) {
		poll_num = poll(fds, nfds, -1);
		if (poll_num == -1) {
			if (errno == EINTR)     /* Interrupted by a signal */
				continue;           /* Restart poll() */

			perror("poll");         /* Unexpected error */
			exit(EXIT_FAILURE);
		}

		if (poll_num > 0) {
			if (fds[0].revents & POLLIN) {
				/* Console input is available: empty stdin and quit */
				while (read(STDIN_FILENO, &buf, 1) > 0 && buf != '\n')
					continue;
				//break;
			}

			if (fds[1].revents & POLLIN) {
				/* Fanotify events are available */
				handle_events(fd);
			}
		}
	}

	printf("Listening for events stopped.\n");
	if (mount_path)
		free(mount_path);
	exit(EXIT_SUCCESS);
}
