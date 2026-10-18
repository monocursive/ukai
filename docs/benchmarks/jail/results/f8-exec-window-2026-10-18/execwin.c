// Probe: what /proc/PID/exe and /proc/PID/environ read while a posix_spawn'd
// child is inside execve. Mirrors the F8 test's helper: spawn `sleep 60` with
// LD_AUDIT set, wait until /proc/PID/exe stops naming this image (or cannot be
// read), then read /proc/PID/environ once, as the pin would.
//
// Per round it records:
//   gate_unreadable  the wait ended because readlink(/proc/PID/exe) failed
//   first_empty      the first environ read after the wait was empty
//   first_missing    the first environ read after the wait lacked LD_AUDIT=
//   ever_window      polling after the wait ever saw exe=new and environ empty
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static char buf[1 << 22];

static ssize_t slurp(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t total = 0, n;
    while ((n = read(fd, buf + total, sizeof buf - total)) > 0) total += n;
    close(fd);
    return n < 0 ? -1 : total;
}

int main(int argc, char **argv) {
    int rounds = argc > 1 ? atoi(argv[1]) : 1000;
    char self[4096];
    ssize_t sl = readlink("/proc/self/exe", self, sizeof self - 1);
    if (sl < 0) return 1;
    self[sl] = 0;
    char *child_argv[] = {"sleep", "60", NULL};
    char *child_env[] = {"PATH=/usr/bin:/bin", "LD_AUDIT=/workspace/evil.so", NULL};
    int gate_unreadable = 0, first_empty = 0, first_missing = 0, ever_window = 0;
    for (int r = 0; r < rounds; r++) {
        pid_t pid;
        if (posix_spawnp(&pid, "sleep", NULL, NULL, child_argv, child_env) != 0) {
            perror("posix_spawnp");
            return 1;
        }
        char exe[64], env[64], link[4096];
        snprintf(exe, sizeof exe, "/proc/%d/exe", pid);
        snprintf(env, sizeof env, "/proc/%d/environ", pid);
        // The test's wait: while the link reads as this image.
        for (;;) {
            ssize_t ll = readlink(exe, link, sizeof link - 1);
            if (ll < 0) { gate_unreadable++; break; }
            link[ll] = 0;
            if (strcmp(link, self) != 0) break;
        }
        // The pin's read, once.
        ssize_t el = slurp(env);
        if (el == 0) first_empty++;
        if (el < 0 || !memmem(buf, el, "LD_AUDIT=", 9)) first_missing++;
        // Keep polling until the environment appears, noting an empty read.
        int window = el == 0;
        for (int i = 0; i < 1000000; i++) {
            el = slurp(env);
            if (el == 0) window = 1;
            if (el > 0 && memmem(buf, el, "LD_AUDIT=", 9)) break;
        }
        ever_window += window;
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
    printf("rounds=%d gate_unreadable=%d first_empty=%d first_missing=%d ever_window=%d\n",
           rounds, gate_unreadable, first_empty, first_missing, ever_window);
    return 0;
}
