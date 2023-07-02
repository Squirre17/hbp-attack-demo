#ifndef __COMMON_H__
#define __COMMON_H__

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <linux/userfaultfd.h>

#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <errno.h>
#include <poll.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t   i8;
typedef int16_t  i16;
typedef int32_t  i32;
typedef int64_t  i64;



#define cBLK "\x1b[0;30m"  /* black  */    
#define cRED "\x1b[0;31m"  /* red    */   
#define cGRE "\x1b[0;32m"  /* green  */   
#define cORA "\x1b[0;33m"  /* orange */   
#define cBLU "\x1b[0;34m"  /* blue   */   
#define cPUR "\x1b[0;35m"  /* purple */   
#define cCYA "\x1b[0;36m"  /* cyan   */   
#define cWHI "\x1b[0;37m"  /* white  */   

#define cBLKp "\x1b[1;90m"  /* black  plus */ 
#define cREDp "\x1b[1;91m"  /* red    plus */ 
#define cGREp "\x1b[1;92m"  /* green  plus */ 
#define cORAp "\x1b[1;93m"  /* orange plus */ 
#define cBLUp "\x1b[1;94m"  /* blue   plus */ 
#define cPURp "\x1b[1;95m"  /* purple plus */ 
#define cCYAp "\x1b[1;96m"  /* cyan   plus */ 
#define cWHIp "\x1b[1;97m"  /* white  plus */ 
#define cRST  "\x1b[0m"      /* reset       */


/* wrap of printf */

#define say(x...)     printf(x) 
#define sayl(x...)    { printf(x); puts(""); }

/* Show a prefixed warning. */

#define warn(x...) do {                        \
    say(cORA "[!] " cWHIp "WARNING: " cRST x); \
    say(cRST "\n");                            \
  } while (0)

/* Show a prefixed "doing something" message. */

#define act(x...) do {                        \
    say(cBLU "[*] " cRST x);                  \
    say(cRST "\n");                           \
  } while (0)

/* Show a prefixed "success" message. */

#define ok(x...) do {                         \
    say(cGRE "[+] " cRST x);                  \
    say(cRST "\n");                           \
  } while (0)

/* Show a prefixed "debug" message. */

#define dbg(x...) do {                        \
    say(cPUR "[x] " cRST);                    \
    say("%s(), %s:%u : ",                     \
        __FUNCTION__, __FILE__, __LINE__ );   \
    sayl(x);                                  \
  } while (0)

/* Show a prefixed fatal error message . */

#define err(x...) do {                        \
    say(cRED "\n[-] " cRST);                  \
    say("%s(), %s:%u : ",                     \
        __FUNCTION__, __FILE__, __LINE__ );   \
    sayl(x);                                  \
  } while (0)
/* Die with a verbose non-OS fatal error message. */

#define fatal(x...) do { \
    say(cRED "\n[-] PROGRAM abort : " cWHI x);                \
    say(cRED "\n         Location : " cRST "%s(), %s:%u\n\n", \
         __FUNCTION__, __FILE__, __LINE__);                   \
    exit(1); \
  } while (0)

/* Die by calling abort() to provide a core dump. */

#define abort(x...) do { \
    say(cREDp "\n[-] PROGRAM abort : " cWHI x);                \
    say(cREDp "\n    Stop location : " cRST "%s(), %s:%u\n\n", \
         __FUNCTION__, __FILE__, __LINE__);                    \
    abort(); \
  } while (0)

/* Die with a verbose OS fatal error message. */

#define panic(x...) do {                                            \
    fflush(stdout);                                                 \
    say(cREDp "\n[-]  SYSTEM ERROR : " cWHI x);                     \
    say(cREDp "\n    Stop location : " cRST "%s(), %s:%u\n",        \
         __FUNCTION__, __FILE__, __LINE__);                         \
    say(cREDp "       OS message : " cRST "%s\n", strerror(errno)); \
    exit(1);                                                        \
  } while (0)

/* Die with FAULT() or PFAULT() depending on the value of res (used to
   interpret different failure modes for read(), write(), etc). */

#define rpfatal(res, x...) do {           \
    if (res < 0) panic(x); else fatal(x); \
  } while (0)

/* Error-checking versions of read() and write() that call rpfatal() as
   appropriate. */

#define ck_write(fd, buf, len, fname) do {                       \
    u32 _len = (len);                                            \
    i32 _res = write(fd, buf, _len);                             \
    if (_res != _len) rpfatal(_res, "Short write to %s", fname); \
  } while (0)

#define ck_read(fd, buf, len, fname) do {                         \
    u32 _len = (len);                                             \
    i32 _res = read(fd, buf, _len);                               \
    if (_res != _len) rpfatal(_res, "Short read from %s", fname); \
  } while (0)

/* powerful assert equal */
#define assert_eq(varl, varr) do {                               \
    if(varl != varr) {                                           \
        say(cREDp "\n[-] Assert failed :" cRST " %lx == %lx\n"   \
            ,(u64)varl, (u64)varr                                \
        );                                                       \
        assert(varl == varr);                                    \
    }                                                            \
  } while (0)

/* powerful assert not equal */
#define assert_neq(varl, varr) do {                              \
    if(varl == varr) {                                           \
        say(cREDp "\n[-] Assert failed :" cRST " %lx == %lx\n"   \
            ,(u64)varl, (u64)varr                                \
        );                                                       \
        assert(varl != varr);                                    \
    }                                                            \
  } while (0)


#define unimplemented() do {                                     \
    sayl(cREDp "\n[-] Unimplamented part : " cRST "%s(), %s:%u", \
            __FUNCTION__, __FILE__, __LINE__);                   \
    exit(1);                                                     \
  } while(0);

#define unreachable() do {                                         \
    sayl(cREDp "\n[-] Unreachable location : " cRST "%s(), %s:%u", \
            __FUNCTION__, __FILE__, __LINE__);                     \
    exit(1);                                                       \
  } while(0);

#define range2(__v, __n, __m, __blk) ({    \
    for(int __v = __n; __v < __m; __v++) { \
        {__blk}                            \
    }                                      \
})

#define range(__v, __m, __blk) range2(__v, 0, __m, __blk)

#endif