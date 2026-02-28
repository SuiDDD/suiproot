#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "build.h"
#include "cli/note.h"
#include "compat.h"
#include "extension/extension.h"
#include "path/binding.h"
#include "path/canon.h"
#include "path/path.h"
#include "path/proc.h"

typedef int (*foreach_fd_t)(const Tracee *tracee, int fd, char path[PATH_MAX]);

#ifndef PATH_CACHE_SIZE
#define PATH_CACHE_SIZE 128
#endif

static struct {
  char guest[PATH_MAX];
  char host[PATH_MAX];
} path_cache[PATH_CACHE_SIZE];

static int cache_index = 0;

static int get_from_cache(const char *guest_path, char *host_path) {
  int i;
  for (i = 0; i < PATH_CACHE_SIZE; i++) {
    if (strcmp(path_cache[i].guest, guest_path) == 0) {
      strcpy(host_path, path_cache[i].host);
      return 0;
    }
  }
  return -1;
}

static void add_to_cache(const char *guest_path, const char *host_path) {
  strcpy(path_cache[cache_index].guest, guest_path);
  strcpy(path_cache[cache_index].host, host_path);
  cache_index = (cache_index + 1) % PATH_CACHE_SIZE;
}

int join_paths(int number_paths, char result[PATH_MAX], ...) {
  va_list paths;
  size_t length;
  int status;
  int i;

  result[0] = '\0';
  length = 0;
  status = 0;

  va_start(paths, result);
  for (i = 0; i < number_paths; i++) {
    const char *path;
    size_t path_length;
    size_t new_length;

    path = va_arg(paths, const char *);
    if (path == NULL)
      continue;
    path_length = strlen(path);

    if (length > 0 && result[length - 1] != '/' && path[0] != '/') {
      new_length = length + path_length + 1;
      if (new_length + 1 >= PATH_MAX) {
        status = -ENAMETOOLONG;
        break;
      }
      strcat(result + length, "/");
      strcat(result + length, path);
      length = new_length;
    } else if (length > 0 && result[length - 1] == '/' && path[0] == '/') {
      new_length = length + path_length - 1;
      if (new_length + 1 >= PATH_MAX) {
        status = -ENAMETOOLONG;
        break;
      }
      strcat(result + length, path + 1);
      length += path_length - 1;
    } else {
      new_length = length + path_length;
      if (new_length + 1 >= PATH_MAX) {
        status = -ENAMETOOLONG;
        break;
      }
      strcat(result + length, path);
      length += path_length;
    }
    status = 0;
  }
  va_end(paths);
  return status;
}

int which(Tracee *tracee, const char *paths, char host_path[PATH_MAX],
          const char *command) {
  char path[PATH_MAX];
  const char *cursor;
  struct stat statr;
  int status;
  bool is_explicit;
  bool found;

  assert(command != NULL);
  is_explicit = (strchr(command, '/') != NULL);

  status = realpath2(tracee, host_path, command, true);
  if (status == 0 && stat(host_path, &statr) == 0) {
    if (is_explicit && !S_ISREG(statr.st_mode)) {
      note(tracee, ERROR, USER, "'%s' is not a regular file", command);
      return -EACCES;
    }
    if (is_explicit && (statr.st_mode & S_IXUSR) == 0) {
      note(tracee, ERROR, USER, "'%s' is not executable", command);
      return -EACCES;
    }
    found = true;
    (void)realpath2(tracee, host_path, command, false);
  } else
    found = false;

  if (is_explicit) {
    if (found)
      return 0;
    else
      goto not_found;
  }

  paths = paths ?: getenv("PATH");
  if (paths == NULL || strcmp(paths, "") == 0)
    goto not_found;

  cursor = paths;
  do {
    size_t length;
    length = strcspn(cursor, ":");
    cursor += length + 1;
    if (length >= PATH_MAX)
      continue;
    else if (length == 0)
      strcpy(path, ".");
    else {
      strncpy(path, cursor - length - 1, length);
      path[length] = '\0';
    }
    if (length + strlen(command) + 2 >= PATH_MAX)
      continue;
    strcat(path, "/");
    strcat(path, command);
    status = realpath2(tracee, host_path, path, true);
    if (status == 0 && stat(host_path, &statr) == 0 && S_ISREG(statr.st_mode) &&
        (statr.st_mode & S_IXUSR) != 0) {
      (void)realpath2(tracee, host_path, path, false);
      return 0;
    }
  } while (*(cursor - 1) != '\0');

not_found:
  status = getcwd2(tracee, path);
  if (status < 0)
    strcpy(path, "<unknown>");
  note(tracee, ERROR, USER, "'%s' not found (root = %s, cwd = %s, $PATH=%s)",
       command, get_root(tracee), path, paths);
  if (found && !is_explicit)
    note(tracee, ERROR, USER,
         "to execute a local program, use the './' prefix, for example: ./%s",
         command);
  return -1;
}

int realpath2(Tracee *tracee, char host_path[PATH_MAX], const char *path,
              bool deref_final) {
  int status;
  if (tracee == NULL)
    status = (realpath(path, host_path) == NULL ? -errno : 0);
  else
    status = translate_path(tracee, host_path, AT_FDCWD, path, deref_final);
  return status;
}

int getcwd2(Tracee *tracee, char guest_path[PATH_MAX]) {
  if (tracee == NULL) {
    if (getcwd(guest_path, PATH_MAX) == NULL)
      return -errno;
  } else {
    if (strlen(tracee->fs->cwd) >= PATH_MAX)
      return -ENAMETOOLONG;
    strcpy(guest_path, tracee->fs->cwd);
  }
  return 0;
}

void chop_finality(char *path) {
  size_t length = strlen(path);
  if (path[length - 1] == '.') {
    assert(length >= 2);
    if (length == 2)
      path[length - 1] = '\0';
    else
      path[length - 2] = '\0';
  } else if (path[length - 1] == '/') {
    if (length > 1)
      path[length - 1] = '\0';
  }
}

int readlink_proc_pid_fd(pid_t pid, int fd, char path[PATH_MAX]) {
  char link[32];
  int status;
  status = snprintf(link, sizeof(link), "/proc/%d/fd/%d", pid, fd);
  if (status < 0)
    return -EBADF;
  if ((size_t)status >= sizeof(link))
    return -EBADF;
  status = readlink(link, path, PATH_MAX);
  if (status < 0)
    return -EBADF;
  if (status >= PATH_MAX)
    return -ENAMETOOLONG;
  path[status] = '\0';
  return 0;
}
int translate_path(Tracee *tracee, char result[PATH_MAX], int dir_fd,
                   const char *user_path, bool deref_final) {
  char guest_path[PATH_MAX];
  int status;

  if (user_path[0] == '/') {
    strcpy(guest_path, user_path);
  } else {
    char base_path[PATH_MAX];
    if (dir_fd != AT_FDCWD) {
      status = readlink_proc_pid_fd(tracee->pid, dir_fd, base_path);
      if (status < 0)
        return status;
      status = detranslate_path(tracee, base_path, NULL);
      if (status < 0)
        return status;
    } else {
      status = getcwd2(tracee, base_path);
      if (status < 0)
        return status;
    }
    status = join_paths(2, guest_path, base_path, user_path);
    if (status < 0)
      return status;
  }

  if (get_from_cache(guest_path, result) == 0) {
    VERBOSE(tracee, 3, "fast cache hit: %s", guest_path);
    goto notify;
  }

  status = notify_extensions(tracee, GUEST_PATH, 0, (intptr_t)user_path);
  if (status < 0)
    return status;
  if (status > 0)
    goto notify;

  strcpy(result, "/");
  status = canonicalize(tracee, guest_path, deref_final, result, 0);
  if (status < 0)
    return status;

  status = substitute_binding(tracee, GUEST, result);
  if (status < 0)
    return status;

  add_to_cache(guest_path, result);

notify:
  status = notify_extensions(tracee, TRANSLATED_PATH, (intptr_t)result, 0);
  if (status < 0)
    return status;
  return 0;
}
int detranslate_path(Tracee *tracee, char path[PATH_MAX],
                     const char t_referrer[PATH_MAX]) {
  size_t prefix_length;
  ssize_t new_length;
  bool sanity_check;
  bool follow_binding;
  if (strnlen(path, PATH_MAX) >= PATH_MAX)
    return -ENAMETOOLONG;
  if (path[0] != '/')
    return 0;
  if (t_referrer != NULL) {
    Comparison comparison;
    sanity_check = false;
    follow_binding = false;
    comparison = compare_paths("/proc", t_referrer);
    if (comparison == PATH1_IS_PREFIX) {
      char proc_path[PATH_MAX];
      strcpy(proc_path, path);
      new_length = readlink_proc2(tracee, proc_path, t_referrer);
      if (new_length < 0)
        return new_length;
      if (new_length != 0) {
        strcpy(path, proc_path);
        return new_length + 1;
      }
      follow_binding = true;
    } else if (!belongs_to_guestfs(tracee, t_referrer)) {
      const char *binding_referree;
      const char *binding_referrer;
      binding_referree = get_path_binding(tracee, HOST, path);
      binding_referrer = get_path_binding(tracee, HOST, t_referrer);
      assert(binding_referrer != NULL);
      if (binding_referree != NULL) {
        comparison = compare_paths(binding_referree, binding_referrer);
        follow_binding = (comparison == PATHS_ARE_EQUAL);
      }
    }
  } else {
    sanity_check = true;
    follow_binding = true;
  }
  if (follow_binding) {
    switch (substitute_binding(tracee, HOST, path)) {
    case 0:
      return 0;
    case 1:
      return strlen(path) + 1;
    default:
      break;
    }
  }
  switch (compare_paths(get_root(tracee), path)) {
  case PATH1_IS_PREFIX:
    prefix_length = strlen(get_root(tracee));
    if (prefix_length == 1)
      prefix_length = 0;
    new_length = strlen(path) - prefix_length;
    memmove(path, path + prefix_length, new_length);
    path[new_length] = '\0';
    break;
  case PATHS_ARE_EQUAL:
    new_length = 1;
    strcpy(path, "/");
    break;
  default:
    if (sanity_check)
      return -EPERM;
    else
      return 0;
  }
  return new_length + 1;
}

bool belongs_to_guestfs(const Tracee *tracee, const char *host_path) {
  Comparison comparison;
  comparison = compare_paths(get_root(tracee), host_path);
  return (comparison == PATHS_ARE_EQUAL || comparison == PATH1_IS_PREFIX);
}

Comparison compare_paths2(const char *path1, size_t length1, const char *path2,
                          size_t length2) {
  size_t length_min;
  bool is_prefix;
  char sentinel;
#if defined DEBUG_OPATH
  assert(length(path1) == length1);
  assert(length(path2) == length2);
#endif
  assert(length1 > 0);
  assert(length2 > 0);
  if (!length1 || !length2) {
    return PATHS_ARE_NOT_COMPARABLE;
  }
  if (path1[length1 - 1] == '/')
    length1--;
  if (path2[length2 - 1] == '/')
    length2--;
  if (length1 < length2) {
    length_min = length1;
    sentinel = path2[length_min];
  } else {
    length_min = length2;
    sentinel = path1[length_min];
  }
  if (sentinel != '/' && sentinel != '\0')
    return PATHS_ARE_NOT_COMPARABLE;
  is_prefix = (strncmp(path1, path2, length_min) == 0);
  if (!is_prefix)
    return PATHS_ARE_NOT_COMPARABLE;
  if (length1 == length2)
    return PATHS_ARE_EQUAL;
  else if (length1 < length2)
    return PATH1_IS_PREFIX;
  else if (length1 > length2)
    return PATH2_IS_PREFIX;
  assert(0);
  return PATHS_ARE_NOT_COMPARABLE;
}

Comparison compare_paths(const char *path1, const char *path2) {
  return compare_paths2(path1, strlen(path1), path2, strlen(path2));
}

static int foreach_fd(const Tracee *tracee, foreach_fd_t callback) {
  struct dirent *dirent;
  char path[PATH_MAX];
  char proc_fd[32];
  int status;
  DIR *dirp;
  status = snprintf(proc_fd, sizeof(proc_fd), "/proc/%d/fd", tracee->pid);
  if (status < 0 || (size_t)status >= sizeof(proc_fd))
    return 0;
  dirp = opendir(proc_fd);
  if (dirp == NULL)
    return 0;
  while ((dirent = readdir(dirp)) != NULL) {
    char tmp[PATH_MAX];
    if (strlen(proc_fd) + strlen(dirent->d_name) + 1 >= PATH_MAX)
      continue;
    strcpy(tmp, proc_fd);
    strcat(tmp, "/");
    strcat(tmp, dirent->d_name);
    status = readlink(tmp, path, PATH_MAX);
    if (status < 0 || status >= PATH_MAX)
      continue;
    path[status] = '\0';
    if (path[0] != '/')
      continue;
    status = callback(tracee, atoi(dirent->d_name), path);
    if (status < 0)
      goto end;
  }
  status = 0;
end:
  closedir(dirp);
  return status;
}

static int list_open_fd_callback(const Tracee *tracee, int fd,
                                 char path[PATH_MAX]) {
  VERBOSE(tracee, 1,
          "pid %d: access to \"%s\" (fd %d) won't be translated until closed",
          tracee->pid, path, fd);
  return 0;
}

int list_open_fd(const Tracee *tracee) {
  return foreach_fd(tracee, list_open_fd_callback);
}

size_t substitute_path_prefix(char path[PATH_MAX], size_t old_prefix_length,
                              const char *new_prefix,
                              size_t new_prefix_length) {
  size_t path_length;
  size_t new_length;
  path_length = strlen(path);
  assert(old_prefix_length < PATH_MAX);
  assert(new_prefix_length < PATH_MAX);
  if (new_prefix_length == 1) {
    new_length = path_length - old_prefix_length;
    if (new_length != 0)
      memmove(path, path + old_prefix_length, new_length);
    else {
      path[0] = '/';
      new_length = 1;
    }
  } else if (old_prefix_length == 1) {
    new_length = new_prefix_length + path_length;
    if (new_length >= PATH_MAX)
      return -ENAMETOOLONG;
    if (path_length > 1) {
      memmove(path + new_prefix_length, path, path_length);
      memcpy(path, new_prefix, new_prefix_length);
    } else {
      memcpy(path, new_prefix, new_prefix_length);
      new_length = new_prefix_length;
    }
  } else {
    new_length = path_length - old_prefix_length + new_prefix_length;
    if (new_length >= PATH_MAX)
      return -ENAMETOOLONG;
    memmove(path + new_prefix_length, path + old_prefix_length,
            path_length - old_prefix_length);
    memcpy(path, new_prefix, new_prefix_length);
  }
  assert(new_length < PATH_MAX);
  path[new_length] = '\0';
  return new_length;
}