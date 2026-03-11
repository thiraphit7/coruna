#include <objc/runtime.h>
#include <objc/message.h>
#include <sys/stat.h>
#include <unistd.h>

BOOL returnYES(id self, SEL _cmd, void *arg0) {
    return YES;
}

__attribute__((constructor)) static void init() {
    //(void*)method_getImplementation((id)class_getInstanceMethod((Class)objc_getClass("MIInstallableBundle"), @selector(performVerificationWithError:)))
    Method originalMethod = class_getInstanceMethod((Class)objc_getClass("MIInstallableBundle"), @selector(performVerificationWithError:));
    method_setImplementation(originalMethod, (IMP)returnYES);
}
