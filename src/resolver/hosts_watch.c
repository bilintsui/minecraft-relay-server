/*
 * resolver/hosts_watch.c: Local static host-name table file monitoring
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

/* section: headers (self) */
#include "hosts_watch.h"

/* section: defines */
#define HOSTS_WATCH_BUFFER_SIZE	4096
#define HOSTS_WATCH_DIRECTORY_MASK	(IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO | IN_ONLYDIR | IN_UNMOUNT)
#define HOSTS_WATCH_FILE_MASK	(IN_ATTRIB | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF | IN_UNMOUNT)
#define HOSTS_WATCH_PATH_LIMIT	128
#define HOSTS_WATCH_READ_BATCH_LIMIT	8
#define HOSTS_WATCH_SYMLINK_LIMIT	40

/* section: types */
typedef struct {
	char *basename;
	int directory_watch;
} hosts_watch_path_entry;

struct hosts_watch {
	int fd;
	int file_watch;
	hosts_watch_path_entry paths[HOSTS_WATCH_PATH_LIMIT];
	size_t path_count;
};

/* section: functions (local) */
static bool hosts_watch_entry_add(hosts_watch *watch, int directory_watch, const char *basename, size_t basename_length) {
	if (watch->path_count == HOSTS_WATCH_PATH_LIMIT) {
		errno = ELOOP;
		return false;
	}
	char *basename_copy = malloc(basename_length + 1U);
	if (basename_copy == NULL) {
		errno = ENOMEM;
		return false;
	}
	memcpy(basename_copy, basename, basename_length);
	basename_copy[basename_length] = '\0';
	watch->paths[watch->path_count++] = (hosts_watch_path_entry){ .basename = basename_copy, .directory_watch = directory_watch };
	return true;
}

static bool hosts_watch_event_name_matches(const hosts_watch_path_entry *entry, const struct inotify_event *event, const char *name) {
	if (event->len == 0) {
		return false;
	}
	size_t basename_length = strlen(entry->basename);
	return basename_length < event->len && name[basename_length] == '\0' && memcmp(name, entry->basename, basename_length) == 0;
}

static bool hosts_watch_path_add(hosts_watch *watch, const char *path, size_t symlink_depth) {
	if (symlink_depth >= HOSTS_WATCH_SYMLINK_LIMIT) {
		errno = ELOOP;
		return false;
	}
	char prefix[PATH_MAX + 1U];
	bool absolute = path[0] == '/';
	memcpy(prefix, absolute ? "/" : ".", 2U);
	size_t prefix_length = 1U;
	const char *cursor = path;
	while (*cursor != '\0') {
		while (*cursor == '/') {
			cursor++;
		}
		if (*cursor == '\0') {
			break;
		}
		const char *component = cursor;
		while (*cursor != '\0' && *cursor != '/') {
			cursor++;
		}
		size_t component_length = (size_t)(cursor - component);
		const char *remainder = cursor;
		while (*remainder == '/') {
			remainder++;
		}
		if (prefix_length + 1U + component_length > PATH_MAX) {
			errno = ENAMETOOLONG;
			return false;
		}
		int directory_watch = inotify_add_watch(watch->fd, prefix, HOSTS_WATCH_DIRECTORY_MASK);
		if (directory_watch == -1) {
			return (errno == ENOENT || errno == ENOTDIR) && watch->path_count != 0;
		}
		if (prefix_length != 1U || !absolute) {
			prefix[prefix_length++] = '/';
		}
		memcpy(prefix + prefix_length, component, component_length);
		prefix_length += component_length;
		prefix[prefix_length] = '\0';
		if (!hosts_watch_entry_add(watch, directory_watch, component, component_length)) {
			return false;
		}
		struct stat info;
		if (lstat(prefix, &info) == -1) {
			return errno == ENOENT || errno == ENOTDIR;
		}
		if (S_ISLNK(info.st_mode)) {
			char target[PATH_MAX + 1U];
			ssize_t target_length = readlink(prefix, target, PATH_MAX);
			if (target_length == -1) {
				/* The parent watch records a replacement between lstat and readlink. */
				return errno == ENOENT || errno == EINVAL;
			}
			target[target_length] = '\0';
			char expanded[PATH_MAX + 1U];
			size_t parent_length = prefix_length - component_length - (absolute && prefix_length == component_length + 1U ? 0U : 1U);
			int length = target[0] == '/' ? snprintf(expanded, sizeof(expanded), "%s%s%s", target, *remainder == '\0' ? "" : "/", remainder)
				: snprintf(expanded, sizeof(expanded), "%.*s%s%s%s%s", (int)parent_length, prefix, parent_length == 1U && absolute ? "" : "/", target, *remainder == '\0' ? "" : "/", remainder);
			if (length < 0 || (size_t)length >= sizeof(expanded)) {
				errno = ENAMETOOLONG;
				return false;
			}
			return hosts_watch_path_add(watch, expanded, symlink_depth + 1U);
		}
		cursor = remainder;
	}
	return watch->path_count != 0;
}

static bool hosts_watch_process_event(hosts_watch *watch, const struct inotify_event *event, const char *name, hosts_watch_events *events) {
	if (event->mask & IN_Q_OVERFLOW) {
		events->changed = true;
		events->refresh = true;
		return true;
	}
	bool recognized = false;
	if (event->wd == watch->file_watch) {
		recognized = true;
		if (event->mask & (IN_ATTRIB | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_IGNORED | IN_MOVE_SELF | IN_UNMOUNT)) {
			events->changed = true;
			events->refresh = true;
		}
	}
	for (size_t index = 0; index < watch->path_count; index++) {
		const hosts_watch_path_entry *entry = &watch->paths[index];
		if (event->wd != entry->directory_watch) {
			continue;
		}
		recognized = true;
		if (event->mask & (IN_DELETE_SELF | IN_IGNORED | IN_MOVE_SELF | IN_UNMOUNT)) {
			events->changed = true;
			events->refresh = true;
			continue;
		}
		if (!hosts_watch_event_name_matches(entry, event, name)) {
			continue;
		}
		if (event->mask & (IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO)) {
			events->changed = true;
			events->refresh = true;
		}
	}
	if (!recognized) {
		errno = EIO;
	}
	return recognized;
}

/* section: functions (exported) */
hosts_watch_create_status hosts_watch_create(const char *filename, hosts_watch **result) {
	if (filename == NULL || filename[0] == '\0' || filename[strlen(filename) - 1U] == '/' || result == NULL || *result != NULL) {
		errno = EINVAL;
		return HOSTS_WATCH_CREATE_BAD_ARGUMENT;
	}
	hosts_watch *watch = calloc(1, sizeof(*watch));
	if (watch == NULL) {
		return HOSTS_WATCH_CREATE_MEMORY;
	}
	watch->fd = -1;
	watch->file_watch = -1;
	watch->fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
	if (watch->fd == -1) {
		int saved_errno = errno;
		hosts_watch_destroy(watch);
		errno = saved_errno;
		return HOSTS_WATCH_CREATE_IO;
	}
	if (!hosts_watch_path_add(watch, filename, 0)) {
		int saved_errno = errno;
		hosts_watch_destroy(watch);
		errno = saved_errno;
		return saved_errno == ENOMEM ? HOSTS_WATCH_CREATE_MEMORY : HOSTS_WATCH_CREATE_IO;
	}
	watch->file_watch = inotify_add_watch(watch->fd, filename, HOSTS_WATCH_FILE_MASK);
	if (watch->file_watch == -1 && errno != ENOENT && errno != ENOTDIR) {
		int saved_errno = errno;
		hosts_watch_destroy(watch);
		errno = saved_errno;
		return HOSTS_WATCH_CREATE_IO;
	}
	*result = watch;
	return HOSTS_WATCH_CREATE_OK;
}

int hosts_watch_descriptor(const hosts_watch *watch) {
	if (watch == NULL) {
		errno = EINVAL;
		return -1;
	}
	return watch->fd;
}

void hosts_watch_destroy(hosts_watch *watch) {
	if (watch == NULL) {
		return;
	}
	if (watch->fd != -1) {
		close(watch->fd);
	}
	for (size_t index = 0; index < watch->path_count; index++) {
		free(watch->paths[index].basename);
	}
	free(watch);
}

hosts_watch_read_status hosts_watch_read(hosts_watch *watch, hosts_watch_events *events) {
	if (watch == NULL || events == NULL) {
		errno = EINVAL;
		return HOSTS_WATCH_READ_BAD_ARGUMENT;
	}
	events->changed = false;
	events->refresh = false;
	uint8_t buffer[HOSTS_WATCH_BUFFER_SIZE];
	for (size_t batch = 0; batch < HOSTS_WATCH_READ_BATCH_LIMIT; batch++) {
		ssize_t bytes = read(watch->fd, buffer, sizeof(buffer));
		if (bytes == -1 && errno == EINTR) {
			continue;
		}
		if (bytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return HOSTS_WATCH_READ_OK;
		}
		if (bytes <= 0) {
			if (bytes == 0) {
				errno = EIO;
			}
			return HOSTS_WATCH_READ_IO;
		}
		size_t offset = 0;
		while (offset < (size_t)bytes) {
			if ((size_t)bytes - offset < sizeof(struct inotify_event)) {
				errno = EIO;
				return HOSTS_WATCH_READ_IO;
			}
			struct inotify_event event;
			memcpy(&event, buffer + offset, sizeof(event));
			offset += sizeof(event);
			if (event.len > (size_t)bytes - offset || !hosts_watch_process_event(watch, &event, (const char *)buffer + offset, events)) {
				if (event.len > (size_t)bytes - offset) {
					errno = EIO;
				}
				return HOSTS_WATCH_READ_IO;
			}
			offset += event.len;
		}
	}
	/* A bounded drain may leave events queued; force a fresh watch and reload the latest table. */
	events->changed = true;
	events->refresh = true;
	return HOSTS_WATCH_READ_OK;
}
