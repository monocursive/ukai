#include <bootstrap.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <xpc/xpc.h>

typedef int (*interface_routine_t)(void *, uint64_t, xpc_object_t,
                                   xpc_object_t *, uint64_t);
typedef xpc_object_t (*create_from_port_t)(mach_port_t, uint64_t);

int main(int argc, char **argv) {
    int mode = argc > 1 ? argv[1][0] : 'l'; /* l = lookup, p = pipe */
    printf("port=%u\n", (unsigned)bootstrap_port);
    if (mode == 'l') {
        mach_port_t sp = MACH_PORT_NULL;
        kern_return_t kr =
            bootstrap_look_up(bootstrap_port, "com.apple.system.logger", &sp);
        printf("lookup kr=%d\n", kr);
        if (sp != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), sp);
        return kr == KERN_SUCCESS ? 0 : 1;
    }
    create_from_port_t create =
        (create_from_port_t)dlsym(RTLD_DEFAULT, "xpc_pipe_create_from_port");
    interface_routine_t routine = (interface_routine_t)dlsym(
        RTLD_DEFAULT, "_xpc_pipe_interface_routine");
    if (!create || !routine) {
        printf("dlsym failed\n");
        return 1;
    }
    xpc_object_t pipe = create(bootstrap_port, 4);
    printf("pipe=%d\n", pipe != NULL);
    if (!pipe) return 1;
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(dict, "type", 8);
    xpc_dictionary_set_uint64(dict, "handle", (uint64_t)getuid());
    xpc_dictionary_set_string(dict, "name", "com.ukai.k90.direct-probe");
    xpc_object_t reply = NULL;
    int rc = routine(pipe, 0x2be, dict, &reply, 0);
    printf("interface rc=%d reply=%d", rc, reply != NULL);
    if (reply) {
        printf(" error=%lld", xpc_dictionary_get_int64(reply, "error"));
        xpc_release(reply);
    }
    printf("\n");
    xpc_release(dict);
    /* A reply — even an error reply — means launchd answered: the client
     * reached the control plane. */
    return reply != NULL ? 0 : 1;
}
