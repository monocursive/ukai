/* Live-custodian additions to macos_defense_matrix.rs's syscall probe.
 * Run only in the disposable VM. The token control uses the caller's shared
 * audit-session credentials with the measured destination PID/version. */
#include <CoreServices/CoreServices.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
extern int pid_suspend(pid_t);
extern int pid_resume(pid_t);
extern int memorystatus_control(uint32_t,int32_t,uint32_t,void*,size_t);
extern int proc_rlimit_control(pid_t,int,void*);
static int deputy(pid_t pid, const char *path, int sig) {
    errno=0; int rc=kill(pid,sig), e=errno;
    int fd=open(path,O_WRONLY|O_CREAT|O_APPEND,0600);
    if(fd>=0){dprintf(fd,"pid=%d target=%d rc=%d errno=%d\n",getpid(),pid,rc,e);close(fd);}
    return rc==0?0:1;
}
int main(int argc,char **argv) {
    if(argc==1) {
        char path[4096]; uint32_t n=sizeof(path); if(_NSGetExecutablePath(path,&n)) return 64;
        char *last=strrchr(path,'/'); if(!last) return 64; strcpy(last+1,"target.txt");
        FILE *f=fopen(path,"r"); int pid;char marker[4096];
        if(!f||fscanf(f,"%d %4095s",&pid,marker)!=2) return 65;
        fclose(f);return deputy(pid,marker,0);
    }
    const char *mode=argv[1]; pid_t pid=argc>2?atoi(argv[2]):0; int r=-1;errno=0;
    if(!strcmp(mode,"deputy")) return argc>3?deputy(pid,argv[3],0):64;
    if(!strcmp(mode,"deputy_cont")) return argc>3?deputy(pid,argv[3],SIGCONT):64;
    if(!strcmp(mode,"sigqueue")){void *symbol=dlsym(RTLD_DEFAULT,"sigqueue");printf("available=%d\n",symbol!=NULL);return symbol?0:77;}
    if(!strcmp(mode,"lsopen")) {CFURLRef url=CFURLCreateFromFileSystemRepresentation(NULL,(const UInt8*)argv[2],strlen(argv[2]),true); OSStatus s=LSOpenCFURLRef(url,NULL);CFRelease(url);printf("osstatus=%d\n",(int)s);return s==noErr?0:1;}
    if(argc<3||pid<=1) return 64;
    if(!strcmp(mode,"kill")) r=kill(pid,SIGCONT);
    else if(!strcmp(mode,"killpg")){pid_t pg=getpgid(pid);if(pg>1)r=killpg(pg,0);}
    else if(!strcmp(mode,"kill_minus1")) r=kill(-1,0);
    else if(!strcmp(mode,"proc_terminate")){int sig=0;r=proc_terminate(pid,&sig);printf("termination_signal=%d ",sig);}
    else if(!strcmp(mode,"audit_signal")){audit_token_t t;mach_msg_type_number_t n=TASK_AUDIT_TOKEN_COUNT;
        if(task_info(mach_task_self(),TASK_AUDIT_TOKEN,(task_info_t)&t,&n))return 65;
        t.val[5]=(uint32_t)pid;t.val[7]=(uint32_t)strtoul(argv[3],NULL,10);r=proc_signal_with_audittoken(&t,SIGCONT);}
    else if(!strcmp(mode,"pid_suspend")){r=pid_suspend(pid);int e=errno;if(r==0)pid_resume(pid);errno=e;}
    else if(!strcmp(mode,"pid_resume"))r=pid_resume(pid);
    else if(!strcmp(mode,"ptrace")){r=ptrace(PT_ATTACH,pid,0,0);int e=errno;if(r==0){usleep(10000);ptrace(PT_DETACH,pid,(caddr_t)1,0);kill(pid,SIGCONT);}errno=e;}
    else if(!strcmp(mode,"task_for_pid")||!strcmp(mode,"task_name_for_pid")){
        mach_port_t task=MACH_PORT_NULL;kern_return_t kr=!strcmp(mode,"task_for_pid")?task_for_pid(mach_task_self(),pid,&task):task_name_for_pid(mach_task_self(),pid,&task);
        printf("kr=%d\n",kr);if(task!=MACH_PORT_NULL)mach_port_deallocate(mach_task_self(),task);return kr==KERN_SUCCESS?0:1;}
    else if(!strcmp(mode,"memorystatus"))r=memorystatus_control(0,pid,0,NULL,0);
    else if(!strcmp(mode,"setpriority")){errno=0;int value=getpriority(PRIO_PROCESS,pid);if(errno==0)r=setpriority(PRIO_PROCESS,pid,value);}
    else if(!strcmp(mode,"rlimit_control")){struct rlimit lim={64,64};r=proc_rlimit_control(pid,RLIMIT_NOFILE,&lim);}
    else return 64;
    printf("ret=%d errno=%d\n",r,errno);return r==0?0:1;
}
