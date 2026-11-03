/* Guest-only bootstrap-port experiment, before exec resets userspace caches. */
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>
int main(int argc, char **argv) {
    char model[64] = {0}; size_t size = sizeof(model);
    if (sysctlbyname("hw.model", model, &size, NULL, 0) || strcmp(model, "VirtualMac2,1")) return 77;
    if (argc < 3) return 64;
    mach_port_t port = MACH_PORT_NULL;
    if (!strcmp(argv[1], "dead")) {
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port)) return 65;
        if (mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND)) return 66;
        if (mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1)) return 67;
    } else if (strcmp(argv[1], "null")) return 64;
    kern_return_t kr = task_set_bootstrap_port(mach_task_self(), port);
    if (kr) { fprintf(stderr,"set_bootstrap=%d\n",kr); return 68; }
    execv(argv[2], argv + 2); perror("execv"); return 69;
}
