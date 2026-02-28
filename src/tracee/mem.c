#include <sys/ptrace.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/user.h>
#include <errno.h>
#include <assert.h>
#include <sys/wait.h>
#include <string.h>
#include <stdint.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/mman.h>

#include "tracee/mem.h"
#include "tracee/abi.h"
#include "syscall/heap.h"
#include "arch.h"
#include "build.h"
#include "cli/note.h"

#ifdef HAS_POKEDATA_WORKAROUND
#include "tracee/reg.h"
#include "syscall/sysnum.h"
extern const ssize_t offset_to_pokedata_workaround;
void launcher_pokedata_workaround();
#if defined(__aarch64__)
__asm(
    ".globl launcher_pokedata_workaround\n"
    "launcher_pokedata_workaround:\n"
    "str x1, [x2]\n"
    ".word 0xf7f0a000\n"
);
#endif
#endif

static inline word_t load_word(const void *address)
{
#ifdef NO_MISALIGNED_ACCESS
    if (((word_t)address & (sizeof(word_t) - 1)) == 0)
        return *(word_t *)address;
    else {
        word_t value;
        memcpy(&value, address, sizeof(word_t));
        return value;
    }
#else
    return *(word_t *)address;
#endif
}

static inline void store_word(void *address, word_t value)
{
#ifdef NO_MISALIGNED_ACCESS
    if (((word_t)address & (sizeof(word_t) - 1)) == 0)
        *((word_t *)address) = value;
    else
        memcpy(address, &value, sizeof(word_t));
#else
    *((word_t *)address) = value;
#endif
}

static int ptrace_pokedata_or_via_stub(Tracee *tracee, word_t addr, word_t word)
{
    int status = -1;
#if HAS_POKEDATA_WORKAROUND
    static bool pokedata_workaround_needed, pokedata_workaround_checked;
    if (!pokedata_workaround_needed)
    {
#endif
        status = ptrace(PTRACE_POKEDATA, tracee->pid, addr, word);
#if HAS_POKEDATA_WORKAROUND
    }
    if (!pokedata_workaround_checked) {
        pokedata_workaround_needed = (status != 0);
        pokedata_workaround_checked = true;
        if (pokedata_workaround_needed) {
            VERBOSE(tracee, 1, "Detected broken PTRACE_POKEDATA - enabling workaround");
        }
    }
    if (pokedata_workaround_needed && tracee->is_aarch32) {
        note(tracee, ERROR, INTERNAL, "POKEDATA workaround is not supported on AArch32");
        status = -1;
        errno = EIO;
    } else if (pokedata_workaround_needed) {
        struct user_regs_struct orig_regs = tracee->_regs[CURRENT];
        bool restore_original_regs = tracee->restore_original_regs;
        sigset_t orig_sigset;
        sigset_t modified_sigset;
        ptrace(PTRACE_GETSIGMASK, tracee->pid, sizeof(sigset_t), &orig_sigset);
        sigfillset(&modified_sigset);
        sigdelset(&modified_sigset, SIGILL);
        sigdelset(&modified_sigset, SIGTRAP);
        sigdelset(&modified_sigset, SIGBUS);
        sigdelset(&modified_sigset, SIGSEGV);
        sigdelset(&modified_sigset, SIGSYS);
        int sigmask_result = ptrace(PTRACE_SETSIGMASK, tracee->pid, sizeof(sigset_t), &modified_sigset);
        word_t pokedata_workaround_stub_addr = tracee->pokedata_workaround_stub_addr;
        poke_reg(tracee, INSTR_POINTER, pokedata_workaround_stub_addr);
        poke_reg(tracee, SYSARG_2, word);
        poke_reg(tracee, SYSARG_3, addr);
        set_sysnum(tracee, PR_void);
        tracee->_regs_were_changed = true;
        tracee->restore_original_regs = false;
        push_specific_regs(tracee, true);
        print_current_regs(tracee, 5, "pokedata workaround" );
        int wstatus = 0;
        bool redeliver_sigstop = false;
        do
        {
            ptrace(PTRACE_CONT, tracee->pid, 0, 0);
            waitpid(tracee->pid, &wstatus, 0);
            if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGSTOP)
            {
                redeliver_sigstop = true;
            }
        } while (WIFSTOPPED(wstatus) && (WSTOPSIG(wstatus) == SIGSYS || WSTOPSIG(wstatus) == SIGSTOP));
        if (redeliver_sigstop)
        {
            kill(tracee->pid, SIGSTOP);
        }
        if (tracee->verbose >= 3)
        {
            note(tracee, INFO, INTERNAL, "pokedata wstatus=%x stub=%lx addr=%lx word=%lx sigmask_result=%d",
                    wstatus, pokedata_workaround_stub_addr, addr, word, sigmask_result);
        }
        bool success = (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGILL);
        ptrace(PTRACE_SETSIGMASK, tracee->pid, sizeof(sigset_t), &orig_sigset);
        tracee->_regs[CURRENT] = orig_regs;
        tracee->_regs_were_changed = true;
        tracee->pokedata_workaround_cancelled_syscall = true;
        tracee->restore_original_regs = restore_original_regs;
        if (success)
        {
            status = 0;
        }
        else
        {
            note(tracee, ERROR, INTERNAL, "POKEDATA workaround stub got signal %d", WSTOPSIG(wstatus));
            status = -1;
            errno = EFAULT;
        }
    }
#endif
    return status;
}

void mem_prepare_after_execve(Tracee *tracee)
{
#if HAS_POKEDATA_WORKAROUND
    tracee->pokedata_workaround_stub_addr = peek_reg(tracee, CURRENT, INSTR_POINTER) + offset_to_pokedata_workaround;
#endif
}

void mem_prepare_before_first_execve(Tracee *tracee)
{
#if HAS_POKEDATA_WORKAROUND
    tracee->pokedata_workaround_stub_addr = (word_t)&launcher_pokedata_workaround;
#endif
}

int write_data(Tracee *tracee, word_t dest_tracee, const void *src_tracer, word_t size)
{
    word_t *src  = (word_t *)src_tracer;
    word_t *dest = (word_t *)dest_tracee;
    long    status;
    word_t word, i, j;
    word_t nb_trailing_bytes;
    word_t nb_full_words;
    uint8_t *last_dest_word;
    uint8_t *last_src_word;

#if defined(HAVE_PROCESS_VM)
    struct iovec local;
    struct iovec remote;
    local.iov_base = src;
    local.iov_len  = size;
    remote.iov_base = dest;
    remote.iov_len  = size;
    status = process_vm_writev(tracee->pid, &local, 1, &remote, 1, 0);
    if ((size_t) status == size)
        return 0;
#endif

    nb_trailing_bytes = size % sizeof(word_t);
    nb_full_words     = (size - nb_trailing_bytes) / sizeof(word_t);
    errno = 0;
    for (i = 0; i < nb_full_words; i++) {
        status = ptrace_pokedata_or_via_stub(tracee, (word_t)(dest + i), load_word(&src[i]));
        if (status < 0) {
            note(tracee, WARNING, SYSTEM, "ptrace(POKEDATA)");
            return -EFAULT;
        }
    }
    if (nb_trailing_bytes == 0)
        return 0;
    errno = 0;
    word = ptrace(PTRACE_PEEKDATA, tracee->pid, dest + i, NULL);
    if (errno != 0) {
        note(tracee, WARNING, SYSTEM, "ptrace(PEEKDATA)");
        return -EFAULT;
    }
    last_dest_word = (uint8_t *)&word;
    last_src_word  = (uint8_t *)&src[i];
    for (j = 0; j < nb_trailing_bytes; j++)
        last_dest_word[j] = last_src_word[j];
    status = ptrace_pokedata_or_via_stub(tracee, (word_t)(dest + i), word);
    if (status < 0) {
        note(tracee, WARNING, SYSTEM, "ptrace(POKEDATA)");
        return -EFAULT;
    }
    return 0;
}

int writev_data(Tracee *tracee, word_t dest_tracee, const struct iovec *src_tracer, int src_tracer_count)
{
    size_t size;
    int status;
    int i;

#if defined(HAVE_PROCESS_VM)
    struct iovec remote;
    for (i = 0, size = 0; i < src_tracer_count; i++)
        size += src_tracer[i].iov_len;
    remote.iov_base = (word_t *)dest_tracee;
    remote.iov_len  = size;
    status = process_vm_writev(tracee->pid, src_tracer, src_tracer_count, &remote, 1, 0);
    if ((size_t) status == size)
        return 0;
#endif

    for (i = 0, size = 0; i < src_tracer_count; i++) {
        status = write_data(tracee, dest_tracee + size,
                src_tracer[i].iov_base, src_tracer[i].iov_len);
        if (status < 0)
            return status;
        size += src_tracer[i].iov_len;
    }
    return 0;
}

int read_data(const Tracee *tracee, void *dest_tracer, word_t src_tracee, word_t size)
{
    word_t *src  = (word_t *)src_tracee;
    word_t *dest = (word_t *)dest_tracer;
    word_t nb_trailing_bytes;
    word_t nb_full_words;
    word_t word, i, j;
    uint8_t *last_src_word;
    uint8_t *last_dest_word;

#if defined(HAVE_PROCESS_VM)
    long status;
    struct iovec local;
    struct iovec remote;
    local.iov_base = dest;
    local.iov_len  = size;
    remote.iov_base = src;
    remote.iov_len  = size;
    status = process_vm_readv(tracee->pid, &local, 1, &remote, 1, 0);
    if ((size_t) status == size)
        return 0;
#endif

    nb_trailing_bytes = size % sizeof(word_t);
    nb_full_words     = (size - nb_trailing_bytes) / sizeof(word_t);
    errno = 0;
    for (i = 0; i < nb_full_words; i++) {
        word = ptrace(PTRACE_PEEKDATA, tracee->pid, src + i, NULL);
        if (errno != 0) {
            note(tracee, WARNING, SYSTEM, "ptrace(PEEKDATA)");
            return -EFAULT;
        }
        store_word(&dest[i], word);
    }
    if (nb_trailing_bytes == 0)
        return 0;
    word = ptrace(PTRACE_PEEKDATA, tracee->pid, src + i, NULL);
    if (errno != 0) {
        note(tracee, WARNING, SYSTEM, "ptrace(PEEKDATA)");
        return -EFAULT;
    }
    last_dest_word = (uint8_t *)&dest[i];
    last_src_word  = (uint8_t *)&word;
    for (j = 0; j < nb_trailing_bytes; j++)
        last_dest_word[j] = last_src_word[j];
    return 0;
}

int read_string(const Tracee *tracee, char *dest_tracer, word_t src_tracee, word_t max_size)
{
    word_t *src  = (word_t *)src_tracee;
    word_t *dest = (word_t *)dest_tracer;
    word_t nb_trailing_bytes;
    word_t nb_full_words;
    word_t word, i, j;
    uint8_t *src_word;
    uint8_t *dest_word;

#if defined(HAVE_PROCESS_VM)
    long status;
    size_t size;
    size_t offset;
    struct iovec local;
    struct iovec remote;
    static size_t chunk_size = 0;
    static uintptr_t chunk_mask;
    if (chunk_size == 0) {
        chunk_size = sysconf(_SC_PAGE_SIZE);
        chunk_size = (chunk_size > 0 && chunk_size < 1024 ? chunk_size : 1024);
        chunk_mask = ~(chunk_size - 1);
    }
    offset = 0;
    do {
        uintptr_t current_chunk = (src_tracee + offset) & chunk_mask;
        uintptr_t next_chunk    = current_chunk + chunk_size;
        size = next_chunk - (src_tracee + offset);
        size = (size < max_size - offset ? size : max_size - offset);
        local.iov_base = (uint8_t *)dest + offset;
        local.iov_len  = size;
        remote.iov_base = (uint8_t *)src + offset;
        remote.iov_len  = size;
        status = process_vm_readv(tracee->pid, &local, 1, &remote, 1, 0);
        if ((size_t) status != size)
            goto fallback;
        status = strnlen(local.iov_base, size);
        if ((size_t) status < size) {
            size = offset + status + 1;
            assert(size <= max_size);
            return size;
        }
        offset += size;
    } while (offset < max_size);
    assert(offset == max_size);
fallback:
#endif

    nb_trailing_bytes = max_size % sizeof(word_t);
    nb_full_words     = (max_size - nb_trailing_bytes) / sizeof(word_t);
    errno = 0;
    for (i = 0; i < nb_full_words; i++) {
        word = ptrace(PTRACE_PEEKDATA, tracee->pid, src + i, NULL);
        if (errno != 0)
            return -EFAULT;
        store_word(&dest[i], word);
        src_word = (uint8_t *)&word;
        for (j = 0; j < sizeof(word_t); j++)
            if (src_word[j] == '\0')
                return i * sizeof(word_t) + j + 1;
    }
    word = ptrace(PTRACE_PEEKDATA, tracee->pid, src + i, NULL);
    if (errno != 0)
        return -EFAULT;
    dest_word = (uint8_t *)&dest[i];
    src_word  = (uint8_t *)&word;
    for (j = 0; j < nb_trailing_bytes; j++) {
        dest_word[j] = src_word[j];
        if (src_word[j] == '\0')
            break;
    }
    return i * sizeof(word_t) + j + 1;
}

word_t peek_word(const Tracee *tracee, word_t address)
{
    word_t result = 0;
#if defined(HAVE_PROCESS_VM)
    int status;
    struct iovec local;
    struct iovec remote;
    local.iov_base = &result;
    local.iov_len  = sizeof_word(tracee);
    remote.iov_base = (void *)address;
    remote.iov_len  = sizeof_word(tracee);
    errno = 0;
    status = process_vm_readv(tracee->pid, &local, 1, &remote, 1, 0);
    if (status > 0)
        return result;
#endif
    errno = 0;
    result = (word_t) ptrace(PTRACE_PEEKDATA, tracee->pid, address, NULL);
    if (errno == EIO)
        errno = EFAULT;
    if (is_32on64_mode(tracee))
        result &= 0xFFFFFFFF;
    return result;
}

void poke_word(const Tracee *tracee, word_t address, word_t value)
{
    word_t tmp;
#if defined(HAVE_PROCESS_VM)
    int status;
    struct iovec local;
    struct iovec remote;
    local.iov_base = &value;
    local.iov_len  = sizeof_word(tracee);
    remote.iov_base = (void *)address;
    remote.iov_len  = sizeof_word(tracee);
    errno = 0;
    status = process_vm_writev(tracee->pid, &local, 1, &remote, 1, 0);
    if (status > 0)
        return;
#endif
    if (is_32on64_mode(tracee)) {
        errno = 0;
        tmp = (word_t) ptrace(PTRACE_PEEKDATA, tracee->pid, address, NULL);
        if (errno != 0)
            return;
        value |= (tmp & 0xFFFFFFFF00000000ULL);
    }
    errno = 0;
    (void) ptrace(PTRACE_POKEDATA, tracee->pid, address, value);
    if (errno == EIO)
        errno = EFAULT;
    return;
}

word_t alloc_mem(Tracee *tracee, ssize_t size)
{
    word_t stack_pointer;
    assert(IS_IN_SYSENTER(tracee));
    stack_pointer = peek_reg(tracee, CURRENT, STACK_POINTER);
    if (stack_pointer == peek_reg(tracee, ORIGINAL, STACK_POINTER))
        size += RED_ZONE_SIZE;
    if (   (size > 0 && stack_pointer <= (word_t) size)
        || (size < 0 && stack_pointer >= ULONG_MAX + size)) {
        note(tracee, WARNING, INTERNAL, "integer under/overflow detected in %s",
            __FUNCTION__);
        return 0;
    }
    stack_pointer -= size;
    poke_reg(tracee, STACK_POINTER, stack_pointer);
    return stack_pointer;
}

int clear_mem(Tracee *tracee, word_t address, size_t size)
{
    int status;
    void *zeros;
    zeros = mmap(NULL, size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (zeros == MAP_FAILED)
        return -errno;
    status = write_data(tracee, address, zeros, size);
    munmap(zeros, size);
    return status;
}