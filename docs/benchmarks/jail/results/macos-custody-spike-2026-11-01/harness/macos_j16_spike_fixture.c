/* Bounded adversarial workload, disposable development VM only. */
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct unique_info { uint8_t uuid[16]; uint64_t uniqueid, parent_uniqueid;
    int32_t pidversion, original_parent_pidversion; uint64_t reserved[2]; };
static int out;
static const char *self, *path;
static time_t expires;
static void expiry(int sig) { (void)sig; _exit(90); }
static void identity(const char *role) {
    time_t remaining = expires - time(NULL);
    if (remaining <= 0) _exit(90);
    signal(SIGALRM, expiry); alarm((unsigned)remaining);
    struct unique_info u = {0};
    int n = proc_pidinfo(getpid(), 17, 0, &u, sizeof(u));
    audit_token_t t; mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&t, &count)) _exit(3);
    char b[1024];
    int len = snprintf(b, sizeof(b), "{\"role\":\"%s\",\"pid\":%d,\"unique_bytes\":%d,\"uniqueid\":%llu,\"audit_token\":[%u,%u,%u,%u,%u,%u,%u,%u]}\n",
        role, getpid(), n, (unsigned long long)u.uniqueid,
        t.val[0],t.val[1],t.val[2],t.val[3],t.val[4],t.val[5],t.val[6],t.val[7]);
    if (write(out,b,(size_t)len)!=len) _exit(4);
}
static void wait_forever(void) { for (;;) pause(); }
static void *forker(void *arg) {
    int storm = (int)(intptr_t)arg;
    for (int i=0;i<(storm?1000:160);i++) {
        pid_t p=fork();
        if (!p) { identity("parallel-child"); if(storm) execl("/usr/bin/true","true",NULL); wait_forever(); }
        if (p<0) { char b[100]; int n=snprintf(b,sizeof(b),"{\"fork_errno\":%d}\n",errno); (void)write(out,b,(size_t)n); break; }
        if(storm) waitpid(p,NULL,0);
    }
    return NULL;
}
int main(int argc,char **argv) {
    /* hw.* is in the exact product profile's sysctl allowlist. The Python
     * harness independently verifies kern.hv_vmm_present before launch;
     * querying that key here would be denied after sandbox entry. */
    char model[64]={0}; size_t model_size=sizeof(model);
    if(sysctlbyname("hw.model",model,&model_size,NULL,0)||strcmp(model,"VirtualMac2,1")) return 77;
    if(argc<3) return 64;
    self=argv[0]; path=argv[2];
    out=open(path,O_CREAT|O_WRONLY|O_APPEND,0600); if(out<0) return 2;
    const char *mode=argv[1];
    expires=argc>3&&!strcmp(mode,"exec")?(time_t)strtoll(argv[3],NULL,10):time(NULL)+300;
    signal(SIGTERM,SIG_IGN);
    identity("root");
    struct rlimit lim; getrlimit(RLIMIT_NPROC,&lim);
    dprintf(out,"{\"nproc_soft\":%llu,\"nproc_hard\":%llu}\n",(unsigned long long)lim.rlim_cur,(unsigned long long)lim.rlim_max);
    if(!strcmp(mode,"command")) { if(argc<4) return 64; execv(argv[3], &argv[3]); return 5; }
    if(!strcmp(mode,"parallel")||!strcmp(mode,"storm")) {
        pthread_t threads[8]; int storm=!strcmp(mode,"storm");
        for(int i=0;i<8;i++) pthread_create(&threads[i],NULL,forker,(void*)(intptr_t)storm);
        dprintf(out,"{\"ready\":true}\n");
        for(int i=0;i<8;i++) pthread_join(threads[i],NULL);
    } else if(!strcmp(mode,"chain")) {
        for(int i=0;i<200;i++) { pid_t p=fork(); if(p) break; identity("chain-child"); }
        dprintf(out,"{\"ready\":true}\n");
    } else if(!strcmp(mode,"exec")) {
        dprintf(out,"{\"ready\":true}\n"); close(out); usleep(1000);
        char deadline[32]; snprintf(deadline,sizeof(deadline),"%lld",(long long)expires);
        execl(self,self,"exec",path,deadline,NULL); return 5;
    } else if(!strcmp(mode,"orphan")) {
        pid_t p=fork();
        if(!p) { setsid(); identity("orphan-parent"); pid_t c=fork();
            if(!c) { identity("orphan-stopped"); signal(SIGHUP,SIG_IGN); raise(SIGSTOP); wait_forever(); }
            usleep(100000); _exit(0); }
        dprintf(out,"{\"ready\":true}\n");
    } else if(!strcmp(mode,"continue")||!strcmp(mode,"signal")) {
        pid_t parent=getpid();
        for(int i=0;i<24;i++) if(fork()==0) { identity("resumer");
            for(;;) { kill(parent,SIGCONT); kill(0,SIGCONT); if(!strcmp(mode,"continue")) usleep(1000); } }
        dprintf(out,"{\"ready\":true}\n");
    } else return 64;
    wait_forever(); return 0;
}
