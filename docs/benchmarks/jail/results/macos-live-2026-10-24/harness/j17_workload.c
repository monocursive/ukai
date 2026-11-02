/* Real filesystem operations; never modifies product code to inject loss. */
#include <copyfile.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/clonefile.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

static void record(const char *op, int rc) {
    int e = errno;
    printf("{\"operation\":\"%s\",\"rc\":%d,\"errno\":%d}\n", op, rc, rc < 0 ? e : 0);
    fflush(stdout);
}
static void *flood(void *arg) {
    char path[80]; int n = (int)(long)arg;
    for (int i=0;i<10000;i++) {
        snprintf(path,sizeof(path),"flood-%d-%d",n,i % 32);
        int fd=open(path,O_WRONLY|O_CREAT|O_TRUNC,0600);
        if(fd>=0) { (void)write(fd,"x",1); close(fd); unlink(path); }
    }
    return NULL;
}
int main(int argc,char **argv) {
    if(argc!=2) return 64;
    if(!strcmp(argv[1],"longpath")) {
        for(int i=0;i<9;i++) {
            char name[151]; memset(name,'a'+i,150);name[150]=0;
            int rc=mkdir(name,0700); record("mkdir",rc); if(rc<0)return 2;
            rc=chdir(name);record("chdir",rc);if(rc<0)return 2;
            int fd=open("file",O_CREAT|O_WRONLY,0600);record("create",fd);
            if(fd>=0){write(fd,"x",1);close(fd);}
        }
        sleep(2); return 0;
    }
    if(!strcmp(argv[1],"flood")) {
        pthread_t threads[8];
        for(long i=0;i<8;i++) if(pthread_create(&threads[i],NULL,flood,(void*)i))return 3;
        for(int i=0;i<8;i++) pthread_join(threads[i],NULL);
        sleep(2);return 0;
    }
    int fd=open("original",O_CREAT|O_WRONLY|O_TRUNC,0600);record("create",fd);if(fd<0)return 2;
    record("write",(int)write(fd,"content",7));record("close",close(fd));
    record("rename",rename("original","renamed"));
    record("link",link("renamed","linked"));
    record("chmod",chmod("linked",0640));
    record("truncate",truncate("linked",3));
    record("setxattr",setxattr("linked","com.ukai.validation","x",1,0,0));
    record("removexattr",removexattr("linked","com.ukai.validation",0));
    record("utimes",utimes("linked",NULL));
    record("chown",chown("linked",getuid(),getgid()));
    record("chflags",chflags("linked",UF_NODUMP));
    record("clonefile",clonefile("linked","cloned",0));
    record("copyfile",copyfile("linked","copied",NULL,COPYFILE_ALL));
    record("unlink",unlink("linked"));
    pid_t p=fork();if(!p){execl("/usr/bin/true","true",NULL);_exit(127);}int s;waitpid(p,&s,0);
    record("child_exit",WIFEXITED(s)?WEXITSTATUS(s):-1);
    return 0;
}
