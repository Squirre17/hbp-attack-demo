#include "common.h"

u32 uffd;
void uffd_register(u64 fault_page, u64 fault_page_len){

    struct uffdio_api ua;     // io operation api
    struct uffdio_register ur;// io register

    // find /usr/include -name unistd_64.h 2>/dev/null
    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    ok("uffd: %d", uffd);

    ua.api = UFFD_API;
    ua.features = 0;
    if(ioctl(uffd, UFFDIO_API, &ua) == -1) 
        panic("ioctl");

    ur.range.start = fault_page;
    ur.range.len   = fault_page_len;
    ur.mode 	   = UFFDIO_REGISTER_MODE_MISSING;

    if(ioctl(uffd, UFFDIO_REGISTER, &ur) == -1)
        panic("ioctl");

    pthread_t thr;
    // notice pthread_create return NULL if execute normally
    if(pthread_create(&thr, NULL, UFFD_handler ,NULL))
        panic("pthread_create");

    ok("regitser done");
}

#define UFFD_TODO 0xdeadbeef

void *UFFD_handler(void *nil){

    act("UFFD handler start");
    struct uffd_msg msg;

    while (1)
    {
        struct pollfd pollfd;
        int nready = 0;
        pollfd.fd		= uffd;
        pollfd.events	= POLLIN ;
        nready = poll(&pollfd, 1, -1);// block here waiting for page fault signal arrive
        if(nready != 1)
            panic("poll");
        
        {
            // [+] user code here
        }

        if(read(uffd, &msg, sizeof(msg)) != sizeof(msg))
            panic("read");
        assert(msg.event == UFFD_EVENT_PAGEFAULT);

        struct uffdio_copy uc;
        uc.src 	= (u64)UFFD_TODO;
        uc.dst 	= (u64)UFFD_TODO;
        uc.len 	= UFFD_TODO;
        uc.mode = 0;
        ioctl(uffd, UFFDIO_COPY, &uc);
        
        ok("ioctl done");
    }
    return NULL;
}