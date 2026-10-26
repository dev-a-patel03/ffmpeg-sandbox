/* dumpable_proof.c: PR_SET_DUMPABLE(0) blocks a same-uid child from
 * reading the parent's /proc/<pid>/environ, needing no capability. The second
 * layer behind nonet for the credential-theft vector. The parent sets itself
 * non-dumpable and forks a same-uid child that tries to read its environ.
 *   ./dumpable_proof dumpable      # child reads environ
 *   ./dumpable_proof nondumpable   # child gets Permission denied */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
static int try_read(pid_t pid){
  char p[64]; snprintf(p,sizeof p,"/proc/%d/environ",(int)pid);
  FILE*f=fopen(p,"r");
  if(!f){ printf("    child: fopen(%s) -> %s\n",p,strerror(errno)); return 1; }
  char buf[256]; size_t n=fread(buf,1,sizeof buf,f);
  printf("    child: read %zu bytes (fread err? %s)\n",n,ferror(f)?strerror(errno):"no");
  fclose(f); return 0;
}
int main(int argc,char**argv){
  setvbuf(stdout,NULL,_IONBF,0);
  int dumpable = (argc>1 && !strcmp(argv[1],"nondumpable")) ? 0 : 1;
  if(!dumpable){ prctl(PR_SET_DUMPABLE,0,0,0,0); printf("  parent PR_SET_DUMPABLE=0 (dumpable now %d)\n",prctl(PR_GET_DUMPABLE)); }
  else printf("  parent dumpable (default %d)\n",prctl(PR_GET_DUMPABLE));
  pid_t me=getpid();
  pid_t c=fork();
  if(c==0){ sleep(1); printf("  [same-uid child uid=%d reading /proc/%d/environ]\n",(int)getuid(),(int)me); try_read(me); fflush(stdout); _exit(0); }
  wait(NULL); return 0;
}
