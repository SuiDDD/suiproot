#ifndef PATH_H
#define PATH_H

#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/types.h>

#include "tracee/tracee.h"

typedef enum {
  REGULAR,
  SYMLINK,
} Type;

typedef enum {
  GUEST,
  HOST,
  PENDING,
} Side;

typedef struct {
  char path[PATH_MAX];
  size_t length;
  Side side;
} Path;

typedef enum { NOT_FINAL, FINAL_NORMAL, FINAL_SLASH, FINAL_DOT } Finality;

#define IS_FINAL(a) ((a) != NOT_FINAL)

typedef enum Comparison {
  PATHS_ARE_EQUAL,
  PATH1_IS_PREFIX,
  PATH2_IS_PREFIX,
  PATHS_ARE_NOT_COMPARABLE,
} Comparison;

#ifndef PATH_CACHE_SIZE
#define PATH_CACHE_SIZE 2048
#endif

extern int which(Tracee *tracee, const char *paths, char host_path[PATH_MAX],
                 const char *command);
extern int realpath2(Tracee *tracee, char host_path[PATH_MAX], const char *path,
                     bool deref_final);
extern int getcwd2(Tracee *tracee, char guest_path[PATH_MAX]);
extern void chop_finality(char *path);
extern int translate_path(Tracee *tracee, char result[PATH_MAX], int dir_fd,
                          const char *user_path, bool deref_final);
extern int detranslate_path(Tracee *tracee, char path[PATH_MAX],
                            const char t_referrer[PATH_MAX]);
extern bool belongs_to_guestfs(const Tracee *tracee, const char *path);

extern int join_paths(int number_paths, char result[PATH_MAX], ...);
extern int list_open_fd(const Tracee *tracee);

extern Comparison compare_paths(const char *path1, const char *path2);
extern Comparison compare_paths2(const char *path1, size_t length1,
                                 const char *path2, size_t length2);

extern size_t substitute_path_prefix(char path[PATH_MAX],
                                     size_t old_prefix_length,
                                     const char *new_prefix,
                                     size_t new_prefix_length);

extern int readlink_proc_pid_fd(pid_t pid, int fd, char path[PATH_MAX]);

#define AT_FD(dirfd, path)                                                     \
  ((dirfd) != AT_FDCWD && ((path) != NULL && (path)[0] != '/'))

#endif
