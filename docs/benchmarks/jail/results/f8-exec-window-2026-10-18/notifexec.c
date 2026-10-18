// Probe: the ordering the vault's production pin relies on. A target's thread
// T1 is parked in a seccomp user notification on connect() while its main
// thread execve()s `sleep` with LD_AUDIT set. The supervisor, as the mediator
// does, reads /proc/TGID/exe and /proc/TGID/environ and then asks
// SECCOMP_IOCTL_NOTIF_ID_VALID, over and over across the exec.
//
// Claim under test: whenever the notification is still valid after the reads,
// both reads came from the pre-exec image (exe = this probe, environ carries
// PROBE_OLD=1). Any valid notification after a read of the new image (exe =
// sleep, or an environment without PROBE_OLD=1, empty included) is counted
// as a violation.
//
// Run with PROBE_OLD=1 in the environment.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
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

static int has(const char *env, ssize_t len, const char *entry) {
    size_t el = strlen(entry);
    for (ssize_t i = 0; i < len;) {
        size_t l = strnlen(env + i, len - i);
        if (l == el && memcmp(env + i, entry, el) == 0) return 1;
        i += l + 1;
    }
    return 0;
}

static void send_fd(int sock, int fd) {
    char c = 0;
    struct iovec iov = {&c, 1};
    char ctl[CMSG_SPACE(sizeof(int))];
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctl;
    msg.msg_controllen = sizeof ctl;
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &fd, sizeof(int));
    if (sendmsg(sock, &msg, 0) != 1) _exit(90);
}

static int recv_fd(int sock) {
    char c;
    struct iovec iov = {&c, 1};
    char ctl[CMSG_SPACE(sizeof(int))];
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctl;
    msg.msg_controllen = sizeof ctl;
    if (recvmsg(sock, &msg, 0) != 1) return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(CMSG_FIRSTHDR(&msg)), sizeof(int));
    return fd;
}

static int sock_fd;
static void *connector(void *arg) {
    (void)arg;
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(9), .sin_addr = {htonl(0x7f000001)}};
    connect(sock_fd, (struct sockaddr *)&to, sizeof to);
    return NULL;
}

int main(int argc, char **argv) {
    int rounds = argc > 1 ? atoi(argv[1]) : 500;
    char self[4096];
    ssize_t sl = readlink("/proc/self/exe", self, sizeof self - 1);
    self[sl] = 0;
    srand(getpid());
    long reads = 0, violations = 0, caught = 0, window_reads = 0, new_full_reads = 0, rounds_done = 0, no_notif = 0;
    for (int r = 0; r < rounds; r++) {
        int sv[2];
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv);
        unsigned delay = rand() % 400;  // microseconds before the exec
        pid_t pid = fork();
        if (pid == 0) {
            close(sv[0]);
            struct sock_filter f[] = {
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            };
            struct sock_fprog prog = {sizeof f / sizeof f[0], f};
            if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) _exit(91);
            int lfd = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
            if (lfd < 0) _exit(92);
            send_fd(sv[1], lfd);
            close(lfd);
            close(sv[1]);
            sock_fd = socket(AF_INET, SOCK_STREAM, 0);
            pthread_t t;
            pthread_create(&t, NULL, connector, NULL);
            usleep(delay);
            char *cargv[] = {"sleep", "60", NULL};
            char *cenv[] = {"PATH=/usr/bin:/bin", "LD_AUDIT=/workspace/evil.so", NULL};
            execve("/usr/bin/sleep", cargv, cenv);
            _exit(93);
        }
        close(sv[1]);
        int lfd = recv_fd(sv[0]);
        close(sv[0]);
        if (lfd < 0) { fprintf(stderr, "no listener\n"); return 1; }
        struct pollfd p = {lfd, POLLIN, 0};
        if (poll(&p, 1, 500) != 1 || !(p.revents & POLLIN)) {
            no_notif++;
            goto next;
        }
        struct seccomp_notif n;
        memset(&n, 0, sizeof n);
        if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_RECV, &n) != 0) { no_notif++; goto next; }
        char exe[64], env[64], link[4096];
        snprintf(exe, sizeof exe, "/proc/%d/exe", pid);
        snprintf(env, sizeof env, "/proc/%d/environ", pid);
        struct timespec start, now;
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (;;) {
            // The mediator's order: executable, environment, then re-validate.
            ssize_t ll = readlink(exe, link, sizeof link - 1);
            if (ll >= 0) link[ll] = 0; else link[0] = 0;
            ssize_t el = slurp(env);
            __u64 id = n.id;
            int valid = ioctl(lfd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0;
            reads++;
            int old_exe = strcmp(link, self) == 0;
            int old_env = el > 0 && has(buf, el, "PROBE_OLD=1");
            if (el == 0) window_reads++;
            if (el > 0 && has(buf, el, "LD_AUDIT=/workspace/evil.so")) new_full_reads++;
            if (valid && !(old_exe && old_env)) {
                violations++;
                fprintf(stderr, "VIOLATION round=%d exe=%s env_len=%zd\n", r, link, el);
            }
            if (!valid && !(old_exe && old_env)) caught++;
            if (!valid) break;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec - start.tv_sec > 2) { fprintf(stderr, "round %d: notification never withdrawn\n", r); break; }
        }
        // Keep reading a little past the withdrawal so the window is seen.
        for (int i = 0; i < 200; i++) {
            ssize_t el = slurp(env);
            if (el == 0) window_reads++;
            if (el > 0 && has(buf, el, "LD_AUDIT=/workspace/evil.so")) { new_full_reads++; break; }
        }
        rounds_done++;
    next:
        close(lfd);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
    printf("rounds=%ld no_notification=%ld reads=%ld violations=%ld caught_new_image_then_invalid=%ld empty_environ_reads=%ld new_image_reads=%ld\n",
           rounds_done, no_notif, reads, violations, caught, window_reads, new_full_reads);
    return violations != 0;
}
