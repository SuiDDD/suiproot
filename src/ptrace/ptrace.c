#include "ptrace/ptrace.h"
#include "arch.h"
#include "cli/note.h"
#include "compat.h"
#include "ptrace/user.h"
#include "syscall/sysnum.h"
#include "tracee/abi.h"
#include "tracee/event.h"
#include "tracee/mem.h"
#include "tracee/reg.h"
#include "tracee/tracee.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#if defined(ARCH_X86_64) || defined(ARCH_X86)
#include <asm/ldt.h>
#endif
#if defined(ARCH_X86_64)
#include <asm/prctl.h>
#endif
#if defined(ARCH_ARM_EABI)
#define user_fpregs_struct user_fpregs
#endif
#if defined(ARCH_ARM64)
#define user_fpregs_struct user_fpsimd_struct
#endif
static const char *stringify_ptrace(
#ifdef __GLIBC__
    enum __ptrace_request
#else
    int
#endif
        request) {
#define CASE_STR(a)                                                            \
  case a:                                                                      \
    return #a;                                                                 \
    break;
  switch ((int)request) {
    CASE_STR(PTRACE_TRACEME)
    CASE_STR(PTRACE_PEEKTEXT)
    CASE_STR(PTRACE_PEEKDATA)
    CASE_STR(PTRACE_PEEKUSER)
    CASE_STR(PTRACE_POKETEXT)
    CASE_STR(PTRACE_POKEDATA) CASE_STR(PTRACE_POKEUSER) CASE_STR(PTRACE_CONT)
        CASE_STR(PTRACE_KILL) CASE_STR(PTRACE_SINGLESTEP) CASE_STR(
            PTRACE_GETREGS) CASE_STR(PTRACE_SETREGS) CASE_STR(PTRACE_GETFPREGS)
            CASE_STR(PTRACE_SETFPREGS) CASE_STR(PTRACE_ATTACH) CASE_STR(
                PTRACE_DETACH) CASE_STR(PTRACE_GETFPXREGS)
                CASE_STR(PTRACE_SETFPXREGS) CASE_STR(PTRACE_SYSCALL) CASE_STR(
                    PTRACE_SETOPTIONS) CASE_STR(PTRACE_GETEVENTMSG)
                    CASE_STR(PTRACE_GETSIGINFO) CASE_STR(PTRACE_SETSIGINFO)
                        CASE_STR(PTRACE_GETREGSET) CASE_STR(PTRACE_SETREGSET)
                            CASE_STR(PTRACE_SEIZE) CASE_STR(PTRACE_INTERRUPT)
                                CASE_STR(PTRACE_LISTEN) CASE_STR(
                                    PTRACE_SET_SYSCALL)
                                    CASE_STR(PTRACE_GET_THREAD_AREA) CASE_STR(
                                        PTRACE_SET_THREAD_AREA)
                                        CASE_STR(PTRACE_GETVFPREGS) CASE_STR(
                                            PTRACE_SINGLEBLOCK)
                                            CASE_STR(PTRACE_ARCH_PRCTL) default
        : return "PTRACE_???";
  }
}
int translate_ptrace_enter(Tracee *tracee) {
  set_sysnum(tracee, PR_void);
  return 0;
}
void attach_to_ptracer(Tracee *ptracee, Tracee *ptracer) {
  memset(&(PTRACEE), 0, sizeof(PTRACEE));
  PTRACEE.ptracer = ptracer;
  PTRACER.nb_ptracees++;
}
void detach_from_ptracer(Tracee *ptracee) {
  Tracee *ptracer = PTRACEE.ptracer;
  PTRACEE.ptracer = NULL;
  assert(PTRACER.nb_ptracees > 0);
  PTRACER.nb_ptracees--;
}
int translate_ptrace_exit(Tracee *tracee) {
  struct {
    word_t request;
    word_t pid;
    word_t address;
    word_t data;
  } regs;
  regs.request = peek_reg(tracee, ORIGINAL, SYSARG_1);
  regs.pid = peek_reg(tracee, ORIGINAL, SYSARG_2);
  regs.address = peek_reg(tracee, ORIGINAL, SYSARG_3);
  regs.data = peek_reg(tracee, ORIGINAL, SYSARG_4);
  word_t result;
  Tracee *ptracee, *ptracer;
  int forced_signal = -1;
  int signal;
  int status;
  if (regs.request == PTRACE_TRACEME) {
    ptracer = tracee->parent;
    ptracee = tracee;
    if (PTRACEE.ptracer != NULL || ptracee == ptracer)
      return -EPERM;
    attach_to_ptracer(ptracee, ptracer);
    if (PTRACER.waits_in == WAITS_IN_KERNEL) {
      status = kill(ptracer->pid, SIGSTOP);
      if (status < 0)
        note(tracee, WARNING, INTERNAL, "can't wake ptracer %d", ptracer->pid);
      else {
        ptracer->sigstop = SIGSTOP_IGNORED;
        PTRACER.waits_in = WAITS_IN_PROOT;
      }
    }
    if (tracee->seccomp == ENABLED)
      tracee->seccomp = DISABLING;
    return 0;
  }
  if (regs.request == PTRACE_ATTACH) {
    ptracer = tracee;
    ptracee = get_tracee(ptracer, regs.pid, false);
    if (ptracee == NULL)
      return -ESRCH;
    if (PTRACEE.ptracer != NULL || ptracee == ptracer)
      return -EPERM;
    attach_to_ptracer(ptracee, ptracer);
    kill(regs.pid, SIGSTOP);
    return 0;
  }
  ptracer = tracee;
  ptracee = get_stopped_ptracee(ptracer, regs.pid, false, __WALL);
  if (ptracee == NULL) {
    static bool warned = false;
    ptracee = get_tracee(tracee, regs.pid, false);
    if (ptracee != NULL && ptracee->exe == NULL && !warned) {
      warned = true;
      note(ptracer, WARNING, INTERNAL,
           "ptrace request to an unexpected ptracee");
    }
    return -ESRCH;
  }
  if (PTRACEE.is_zombie || PTRACEE.ptracer != ptracer || regs.pid == (word_t)-1)
    return -ESRCH;
  switch (regs.request) {
  case PTRACE_SYSCALL:
    PTRACEE.ignore_syscalls = false;
    forced_signal = (int)regs.data;
    status = 0;
    break;
  case PTRACE_CONT:
    PTRACEE.ignore_syscalls = true;
    forced_signal = (int)regs.data;
    status = 0;
    break;
  case PTRACE_SINGLESTEP:
    ptracee->restart_how = PTRACE_SINGLESTEP;
    forced_signal = (int)regs.data;
    status = 0;
    break;
  case PTRACE_SINGLEBLOCK:
    ptracee->restart_how = PTRACE_SINGLEBLOCK;
    forced_signal = (int)regs.data;
    status = 0;
    break;
  case PTRACE_DETACH:
    detach_from_ptracer(ptracee);
    status = 0;
    break;
  case PTRACE_KILL:
    status = ptrace(regs.request, regs.pid, NULL, NULL);
    break;
  case PTRACE_SETOPTIONS:
    PTRACEE.options = regs.data;
    return 0;
  case PTRACE_GETEVENTMSG:
    status = ptrace(regs.request, regs.pid, NULL, &result);
    if (status < 0)
      return -errno;
    poke_word(ptracer, regs.data, result);
    if (errno != 0)
      return -errno;
    return 0;
  case PTRACE_PEEKUSER:
  case PTRACE_PEEKTEXT:
  case PTRACE_PEEKDATA:
    errno = 0;
    result = (word_t)ptrace(regs.request, regs.pid, regs.address, NULL);
    if (errno != 0)
      return -errno;
    poke_word(ptracer, regs.data, result);
    if (errno != 0)
      return -errno;
    return 0;
  case PTRACE_POKEUSER:
    status = ptrace(regs.request, regs.pid, regs.address, regs.data);
    if (status < 0)
      return -errno;
    return 0;
  case PTRACE_POKETEXT:
  case PTRACE_POKEDATA:
    status = ptrace(regs.request, regs.pid, regs.address, regs.data);
    if (status < 0)
      return -errno;
    return 0;
  case PTRACE_GETSIGINFO: {
    siginfo_t siginfo;
    status = ptrace(regs.request, regs.pid, NULL, &siginfo);
    if (status < 0)
      return -errno;
    status = write_data(ptracer, regs.data, &siginfo, sizeof(siginfo));
    if (status < 0)
      return status;
    return 0;
  }
  case PTRACE_SETSIGINFO: {
    siginfo_t siginfo;
    status = read_data(ptracer, &siginfo, regs.data, sizeof(siginfo));
    if (status < 0)
      return status;
    status = ptrace(regs.request, regs.pid, NULL, &siginfo);
    if (status < 0)
      return -errno;
    return 0;
  }
  case PTRACE_GETREGS: {
    struct user_regs_struct buffer;
    status = ptrace(regs.request, regs.pid, NULL, &buffer);
    if (status < 0)
      return -errno;
    status = write_data(ptracer, regs.data, &buffer, sizeof(buffer));
    if (status < 0)
      return status;
    return 0;
  }
  case PTRACE_SETREGS: {
    struct user_regs_struct buffer;
    status = read_data(ptracer, &buffer, regs.data, sizeof(buffer));
    if (status < 0)
      return status;
    status = ptrace(regs.request, regs.pid, NULL, &buffer);
    if (status < 0)
      return -errno;
    return 0;
  }
  case PTRACE_GETFPREGS: {
    struct user_fpregs_struct buffer;
    status = ptrace(regs.request, regs.pid, NULL, &buffer);
    if (status < 0)
      return -errno;
    status = write_data(ptracer, regs.data, &buffer, sizeof(buffer));
    if (status < 0)
      return status;
    return 0;
  }
  case PTRACE_SETFPREGS: {
    struct user_fpregs_struct buffer;
    status = read_data(ptracer, &buffer, regs.data, sizeof(buffer));
    if (status < 0)
      return status;
    status = ptrace(regs.request, regs.pid, NULL, &buffer);
    if (status < 0)
      return -errno;
    return 0;
  }
#if defined(ARCH_X86_64) || defined(ARCH_X86)
  case PTRACE_GET_THREAD_AREA: {
    struct user_desc user_desc;
    status = ptrace(regs.request, regs.pid, regs.address, &user_desc);
    if (status < 0)
      return -errno;
    status = write_data(ptracer, regs.data, &user_desc, sizeof(user_desc));
    if (status < 0)
      return status;
    return 0;
  }
  case PTRACE_SET_THREAD_AREA: {
    struct user_desc user_desc;
    status = read_data(ptracer, &user_desc, regs.data, sizeof(user_desc));
    if (status < 0)
      return status;
    status = ptrace(regs.request, regs.pid, regs.address, &user_desc);
    if (status < 0)
      return -errno;
    return 0;
  }
#endif
  case PTRACE_GETREGSET: {
    struct iovec local_iovec;
    word_t remote_iovec_base;
    word_t remote_iovec_len;
    remote_iovec_base = peek_word(ptracer, regs.data);
    if (errno != 0)
      return -errno;
    remote_iovec_len = peek_word(ptracer, regs.data + sizeof_word(ptracer));
    if (errno != 0)
      return -errno;
    assert(sizeof(local_iovec.iov_len) == sizeof(word_t));
    local_iovec.iov_len = remote_iovec_len;
    local_iovec.iov_base = talloc_zero_size(ptracer->ctx, remote_iovec_len);
    if (local_iovec.iov_base == NULL)
      return -ENOMEM;
    status = ptrace(PTRACE_GETREGSET, regs.pid, regs.address, &local_iovec);
    if (status < 0)
      return status;
    remote_iovec_len = local_iovec.iov_len =
        MIN(remote_iovec_len, local_iovec.iov_len);
    status = writev_data(ptracer, remote_iovec_base, &local_iovec, 1);
    if (status < 0)
      return status;
    poke_word(ptracer, regs.data + sizeof_word(ptracer), remote_iovec_len);
    if (errno != 0)
      return -errno;
    return 0;
  }
  case PTRACE_SETREGSET: {
    struct iovec local_iovec;
    word_t remote_iovec_base;
    word_t remote_iovec_len;
    remote_iovec_base = peek_word(ptracer, regs.data);
    if (errno != 0)
      return -errno;
    remote_iovec_len = peek_word(ptracer, regs.data + sizeof_word(ptracer));
    if (errno != 0)
      return -errno;
    assert(sizeof(local_iovec.iov_len) == sizeof(word_t));
    local_iovec.iov_len = remote_iovec_len;
    local_iovec.iov_base = talloc_zero_size(ptracer->ctx, remote_iovec_len);
    if (local_iovec.iov_base == NULL)
      return -ENOMEM;
    status = read_data(ptracer, local_iovec.iov_base, remote_iovec_base,
                       local_iovec.iov_len);
    if (status < 0)
      return status;
    status = ptrace(PTRACE_SETREGSET, regs.pid, regs.address, &local_iovec);
    if (status < 0)
      return status;
    return 0;
  }
  case PTRACE_GETVFPREGS:
  case PTRACE_GETFPXREGS:
    return -ENOTSUP;
#if defined(ARCH_X86_64)
  case PTRACE_ARCH_PRCTL:
    switch (regs.data) {
    case ARCH_GET_GS:
    case ARCH_GET_FS:
      status = ptrace(regs.request, regs.pid, &result, regs.data);
      if (status < 0)
        return -errno;
      poke_word(ptracer, regs.address, result);
      if (errno != 0)
        return -errno;
      break;
    case ARCH_SET_GS:
    case ARCH_SET_FS:
      return -ENOTSUP;
    default:
      return -ENOTSUP;
    }
    return 0;
#endif
  case PTRACE_SET_SYSCALL:
    status = ptrace(regs.request, regs.pid, regs.address, regs.data);
    if (status < 0)
      return -errno;
    return 0;
  default:
    return -ENOTSUP;
  }
  signal = PTRACEE.event4.proot.pending
               ? handle_tracee_event(ptracee, PTRACEE.event4.proot.value)
               : PTRACEE.event4.proot.value;
  if (forced_signal != -1)
    signal = forced_signal;
  (void)restart_tracee(ptracee, signal);
  return status;
}