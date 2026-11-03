/* Guest-only protocol control: no launchctl execution. Test-owned jobs only. */
#include <errno.h>
#include <launch.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>

int main(int argc, char **argv) {
    char model[64] = {0}; size_t size = sizeof(model);
    if (sysctlbyname("hw.model", model, &size, NULL, 0) || strcmp(model, "VirtualMac2,1")) return 77;
    if (argc != 2 || strncmp(argv[1], "com.ukai.protocol.", 18)) return 64;
    launch_data_t request = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
    launch_data_dict_insert(request, launch_data_new_string(argv[1]), LAUNCH_KEY_STARTJOB);
    errno = 0;
    launch_data_t reply = launch_msg(request);
    if (!reply) { printf("no_reply errno=%d\n", errno); return 1; }
    int error = launch_data_get_type(reply) == LAUNCH_DATA_ERRNO ? launch_data_get_errno(reply) : -1;
    printf("type=%d error=%d\n", launch_data_get_type(reply), error);
    launch_data_free(reply); launch_data_free(request);
    return error ? 1 : 0;
}
