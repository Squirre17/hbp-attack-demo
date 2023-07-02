#define FUSE_USE_VERSION 29
#include <fuse.h>
#include "common.h"

static const char *fuse_content = "Hello, World!\n";

static int getattr_callback(const char *path, struct stat *stbuf) {

    act("getattr_callback start");
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/file") == 0) {
        stbuf->st_mode = S_IFREG | 0777;
        stbuf->st_nlink = 1;
        stbuf->st_size = strlen(fuse_content);
        return 0;
    }
    return -ENOENT;
}

static int open_callback(const char *path, struct fuse_file_info *fi) {
    ok("open_callback start");
    return 0;
}


/* deal with read file content request */
static int read_callback(const char *path,
                         char *file_buf, size_t size, off_t offset,
                         struct fuse_file_info *fi) {
    act("read_callback start");

    if (strcmp(path, "/file") == 0) {
        {
            // [+] exploit code location
        }
    }

    return -ENOENT;
}

static struct fuse_operations fops = {
    .getattr = getattr_callback,
    .open    = open_callback,
    .read    = read_callback,
};

u32 fuse_setup_done = 0;
cpu_set_t mtcpu;           /* main thread cpu */
const char *mountpoint = "/tmp/fuse";

void *fuse_thread(void *arg) {

    act("fuse_thread start");
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    struct fuse_chan *chan;
    struct fuse *fuse;

    if (mkdir(mountpoint, 0777))// NOTE: this position can't use access to check whether exist maybe something relate to page access?
        panic("mkdir(%s)", mountpoint);

    if (!(chan = fuse_mount(mountpoint, &args)))
        panic("fuse_mount");

    if (!(fuse = fuse_new(chan, &args, &fops, sizeof(fops), NULL))) {
        fuse_unmount(mountpoint, chan);
        panic("fuse_new");
    }

    /* use same cpu with main thread */
    if (sched_setaffinity(0, sizeof(cpu_set_t), &mtcpu))
        panic("sched_setaffinity");

    fuse_set_signal_handlers(fuse_get_session(fuse));
    fuse_setup_done = 1;
    fuse_loop_mt(fuse);

    fuse_unmount(mountpoint, chan);
    return NULL;
}

int fuse_fd = -1;
void* mmap_fuse_file() {

    if (fuse_fd != -1) close(fuse_fd);
    fuse_fd = open("/tmp/fuse/file", O_RDWR);
    if (fuse_fd == -1) panic("/tmp/fuse/file");

    void *page;
    page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                MAP_PRIVATE, fuse_fd, 0);
    if (page == MAP_FAILED) panic("mmap");
    return page;
}