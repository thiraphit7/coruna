@import Darwin;
@import MachO;
@import UIKit;
#include <mach-o/ldsyms.h> /* _mh_dylib_header */

// Function pointers
extern pthread_t pthread_main_thread_np(void);
extern void _pthread_set_self(pthread_t p);
void              (*_abort)(void);
int               (*_close)(int);
void *            (*_dlsym)(void *, const char *);
thread_t          (*_mach_thread_self)(void);
int               (*_open)(const char *, int, ...);
void              (*__pthread_set_self)(pthread_t p);
pthread_t         (*_pthread_main_thread_np)(void);
int               (*_strncmp)(const char *s1, const char *s2, size_t n);
kern_return_t     (*_thread_terminate)(mach_port_t);
int               (*_write)(int, const void *, size_t);

int shellcode_init(void * (*_dlsym)(void* handle, const char* symbol), const char *next_stage_dylib_path);

static uintptr_t _get_text_vmaddr(const struct mach_header_64 *mh) {
    struct load_command *lc = (void*)((uintptr_t)mh + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < mh->ncmds; i++, lc = (void*)((uint8_t*)lc + lc->cmdsize)) {
        if (lc->cmd != LC_SEGMENT_64) continue;
        struct segment_command_64 *seg = (void*)lc;
        if (_strncmp(seg->segname, "__TEXT", 6) == 0)
            return seg->vmaddr;
    }
    return 0;
}
static size_t macho_size_from_header(const struct mach_header_64 *mh) {
    uintptr_t base       = (uintptr_t)mh;
    uintptr_t text_vm    = _get_text_vmaddr(mh);
    uintptr_t slide      = base - text_vm;  // ASLR slide

    struct load_command *lc = (void*)(base + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < mh->ncmds; i++, lc = (void*)((uint8_t*)lc + lc->cmdsize)) {
        if (lc->cmd != LC_SEGMENT_64) continue;
        struct segment_command_64 *seg = (void*)lc;
        if (_strncmp(seg->segname, "__LINKEDIT", 10) != 0) continue;

        // vmaddr + slide = actual mapped address of __LINKEDIT
        // end = that + vmsize
        return (seg->vmaddr + slide + seg->vmsize) - base;
    }

    return 0;
}

const char *save_myself(void) {
    const char *path = "/tmp/SpringBoardTweak.dylib";
    const struct mach_header_64 *header = (struct mach_header_64 *)&_mh_dylib_header;
    size_t size = macho_size_from_header(header);
    int fd = _open(path, O_RDWR | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) _abort();
    
    if (_write(fd, header, size) != size) {
        _abort();
    }
    _close(fd);
    return path;
}

#if __arm64e__
__attribute__((noinline)) void *pacia(void* ptr, uint64_t ctx) {
    __asm__("xpaci %[value]\n" : [value] "+r"(ptr));
    __asm__("pacia %0, %1" : "+r"(ptr) : "r"(ctx));
    return ptr;
}
#endif

// Entry point when loaded by Coruna
int last(void) {
#if __arm64e__
    _dlsym = pacia(dlsym, 0);
    __pthread_set_self = pacia(_pthread_set_self, 0);
    _pthread_main_thread_np = pacia(pthread_main_thread_np, 0);
#else
    _dlsym = dlsym;
    __pthread_set_self = _pthread_set_self;
    _pthread_main_thread_np = pthread_main_thread_np;
#endif
    __pthread_set_self(_pthread_main_thread_np());
    
    _abort = _dlsym(RTLD_DEFAULT, "abort");
    _close = _dlsym(RTLD_DEFAULT, "close");
    _mach_thread_self = _dlsym(RTLD_DEFAULT, "mach_thread_self");
    _open = _dlsym(RTLD_DEFAULT, "open");
    _strncmp = _dlsym(RTLD_DEFAULT, "strncmp");
    _thread_terminate = _dlsym(RTLD_DEFAULT, "thread_terminate");
    _write = _dlsym(RTLD_DEFAULT, "write");
    
    // setup dyld validation bypass
    const char *path = save_myself();
    shellcode_init(_dlsym, path);
    
    // should not return
    _thread_terminate(_mach_thread_self());
    return 0;
}
int end(void) {
    // should never be called
    return 0;
}
