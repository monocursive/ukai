
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mach/mach.h>
extern int pid_suspend(pid_t pid);
extern int pid_resume(pid_t pid);
extern kern_return_t bootstrap_look_up(mach_port_t bp, char *name, mach_port_t *sp);
extern int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);
extern int proc_rlimit_control(pid_t pid, int op, void *arg);
static pid_t kid(void){ pid_t p=fork(); if(p==0){ for(;;) pause(); _exit(0);} return p; }
static int done(pid_t p, int ok){ kill(p,SIGKILL); waitpid(p,NULL,0); return ok?0:1; }
int main(int argc, char**argv){
  if(argc<2){fprintf(stderr,"usage: probe CMD [ARG]\n");return 2;}
  const char*c=argv[1];
  errno=0;
  if(!strcmp(c,"self_kill")){pid_t p=kid();int r=kill(p,SIGTERM);int e=errno;if(r==0){waitpid(p,NULL,0);return 0;}kill(p,SIGKILL);waitpid(p,NULL,0);printf("ret=%d errno=%d",r,e);return 1;}
  /* macOS has no sigqueue(3): the §4.7 sigqueue route is vacuous here. */
  if(!strcmp(c,"self_task_for_pid")){pid_t p=kid();mach_port_t t=MACH_PORT_NULL;kern_return_t k=task_for_pid(mach_task_self(),p,&t);int e=errno;printf("kr=%d errno=%d",k,e);return done(p,k==KERN_SUCCESS);}
  if(!strcmp(c,"self_task_name_for_pid")){pid_t p=kid();mach_port_t t=MACH_PORT_NULL;kern_return_t k=task_name_for_pid(mach_task_self(),p,&t);printf("kr=%d errno=%d",k,errno);return done(p,k==KERN_SUCCESS);}
  if(!strcmp(c,"self_ptrace")){pid_t p=kid();long r=ptrace(PT_ATTACH,p,0,0);int e=errno;int d=-1;if(r==0){d=ptrace(PT_DETACH,p,(caddr_t)1,0);}printf("attach=%ld errno=%d detach=%d",r,e,d);return done(p,r==0&&d==0);}
  if(!strcmp(c,"self_pid_suspend_resume")){pid_t p=kid();int a=pid_suspend(p);int ae=errno;int b=a==0?pid_resume(p):-1;printf("suspend=%d errno=%d resume=%d",a,ae,b);return done(p,a==0&&b==0);}
  if(!strcmp(c,"self_memorystatus")){pid_t p=kid();int r=memorystatus_control(0,(int32_t)p,0,NULL,0);printf("ret=%d errno=%d",r,errno);return done(p,r==0);}
  if(!strcmp(c,"self_rlimit_control")){pid_t p=kid();struct rlimit rl={64,64};int r=proc_rlimit_control(p,RLIMIT_NOFILE,&rl);printf("ret=%d errno=%d",r,errno);return done(p,r==0);}
  if(!strcmp(c,"kill_minus1_probe")){int r=kill(-1,0);printf("ret=%d errno=%d",r,errno);return r==0?0:1;}
  if(!strcmp(c,"task_for_pid")){mach_port_t t=MACH_PORT_NULL;kern_return_t k=task_for_pid(mach_task_self(),atoi(argv[2]),&t);printf("kr=%d errno=%d",k,errno);return k==KERN_SUCCESS?0:1;}
  if(!strcmp(c,"task_name_for_pid")){mach_port_t t=MACH_PORT_NULL;kern_return_t k=task_name_for_pid(mach_task_self(),atoi(argv[2]),&t);printf("kr=%d errno=%d",k,errno);return k==KERN_SUCCESS?0:1;}
  if(!strcmp(c,"bootstrap")){mach_port_t bp=MACH_PORT_NULL,p2=MACH_PORT_NULL;task_get_bootstrap_port(mach_task_self(),&bp);kern_return_t k=bootstrap_look_up(bp,(char*)argv[2],&p2);printf("kr=%d",k);return k==KERN_SUCCESS?0:1;}
  if(!strcmp(c,"unix_connect")){int s=socket(AF_UNIX,SOCK_STREAM,0);struct sockaddr_un a;memset(&a,0,sizeof a);a.sun_family=AF_UNIX;strncpy(a.sun_path,argv[2],sizeof a.sun_path-1);int r=connect(s,(struct sockaddr*)&a,sizeof a);printf("ret=%d errno=%d",r,errno);return r==0?0:1;}
  if(!strcmp(c,"tcp_connect")){int s=socket(AF_INET,SOCK_STREAM,0);struct sockaddr_in a;memset(&a,0,sizeof a);a.sin_family=AF_INET;a.sin_port=htons((unsigned short)atoi(argv[3]));a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);int r=connect(s,(struct sockaddr*)&a,sizeof a);printf("ret=%d errno=%d",r,errno);return r==0?0:1;}
  fprintf(stderr,"unknown cmd\n");return 2;
}
