/* killall.c - kill processes by name or list PIDs */

/* Copyright 1993-1998 Werner Almesberger. See file COPYING for details. */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "comm.h"
#include "signals.h"


#define PROC_BASE "/proc"
#define MAX_NAMES (sizeof(unsigned long)*8)


static int verbose = 0,exact = 0,interactive = 0,quiet = 0,wait_until_dead = 0,
  process_group = 0,pidof;


static int ask(char *name,pid_t pid)
{
    int ch,c;

    do {
        printf("Kill %s(%s%d) ? (y/n) ",name,process_group ? "pgid " : "",pid);
        fflush(stdout);
	do if ((ch = getchar()) == EOF) exit(0);
	while (ch == '\n' || ch == '\t' || ch == ' ');
	do if ((c = getchar()) == EOF) exit(0);
	while (c != '\n');
    }
    while (ch != 'y' && ch != 'n' && ch != 'Y' && ch != 'N');
    return ch == 'y' || ch == 'Y';
}


static int kill_all(int signal,int names,char **namelist)
{
    DIR *dir;
    struct dirent *de;
    FILE *file;
    struct stat st,sts[MAX_NAMES];
    int *name_len;
    char path[PATH_MAX+1],comm[COMM_LEN];
    char command_buf[PATH_MAX+1];
    char *command;
    pid_t *pid_table,pid,self,*pid_killed;
    pid_t *pgids;
    int empty,i,j,okay,length,got_long,error;
    int pids,max_pids,pids_killed;
    unsigned long found;

    if (!(name_len = malloc(sizeof(int)*names))) {
	perror("malloc");
	exit(1);
    }
    for (i = 0; i < names; i++)
	if (!strchr(namelist[i],'/')) {
	    sts[i].st_dev = 0;
	    name_len[i] = strlen(namelist[i]);
	}
	else if (stat(namelist[i],&sts[i]) < 0) {
		perror(namelist[i]);
		exit(1);
	    }
    self = getpid();
    found = 0;
    if (!(dir = opendir(PROC_BASE))) {
	perror(PROC_BASE);
	exit(1);
    }
    max_pids = 256;
    pid_table = malloc(max_pids*sizeof(pid_t));
    if (!pid_table) {
	perror("malloc");
	exit(1);
    }
    pids = 0;
    while (de = readdir(dir)) {
	if (!(pid = atoi(de->d_name)) || pid == self) continue;
	if (pids == max_pids) {
	    if (!(pid_table = realloc(pid_table,2*pids*sizeof(pid_t)))) {
		perror("realloc");
		exit(1);
	    }
	    max_pids *= 2;
	}
	pid_table[pids++] = pid;
    }
    (void) closedir(dir);
    empty = 1;
    pids_killed = 0;
    pid_killed = malloc(max_pids*sizeof(pid_t));
    if (!pid_killed) {
	perror("malloc");
	exit(1);
    }
    if (!process_group) pgids = NULL; /* silence gcc */
    else {
	pgids = malloc(pids*sizeof(pid_t));
	if (!pgids) {
	    perror("malloc");
	    exit(1);
	}
    }
    for (i = 0; i < pids; i++) {
	sprintf(path,PROC_BASE "/%d/stat",pid_table[i]);
	if (!(file = fopen(path,"r"))) continue;
	empty = 0;
	okay = fscanf(file,"%*d (%[^)]",comm) == 1;
	(void) fclose(file);
	if (!okay) continue;
	got_long = 0;
	command = NULL; /* make gcc happy */
	length = strlen(comm);
	if (length == COMM_LEN-1) {
	    sprintf(path,PROC_BASE "/%d/cmdline",pid_table[i]);
	    if (!(file = fopen(path,"r"))) continue;
	    okay = fscanf(file,"%s",command_buf) == 1;
	    (void) fclose(file);
	    if (exact && !okay) {
		if (verbose)
		    fprintf(stderr,"skipping partial match %s(%d)\n",comm,
		      pid_table[i]);
		continue;
	    }
	    got_long = okay;
	    if (okay) {
		command = strrchr(command_buf,'/');
		if (command) command++;
		else command = command_buf;
	    }
	}
	for (j = 0; j < names; j++) {
	    pid_t id;

	    if (!sts[j].st_dev) {
		if (length != COMM_LEN-1 || name_len[j] < COMM_LEN-1) {
		    if (strcmp(namelist[j],comm)) continue;
		}
		else if (got_long ? strcmp(namelist[j],command) :
		      strncmp(namelist[j],comm,COMM_LEN-1)) continue;
	    }
	    else {
		sprintf(path,PROC_BASE "/%d/exe",pid_table[i]);
		if (stat(path,&st) < 0) continue;
		if (sts[j].st_dev != st.st_dev || sts[j].st_ino != st.st_ino)
		    continue;
	    }
	    if (!process_group) id = pid_table[i];
	    else {
		int j;

		id = getpgid(pid_table[i]);
		pgids[i] = id;
		if (id < 0) {
		    fprintf(stderr,"getpgid(%d): %s\n",pid_table[i],
		      strerror(errno));
		}
		for (j = 0; j < i; j++)
		    if (pgids[j] == id) break;
		if (j < i) continue;
	    }
	    if (interactive && !ask(comm,id)) continue;
	    if (pidof) {
		if (found) putchar(' ');
		printf("%d",id);
		found |= 1 << j;
	    }
	    else if (kill(process_group ? -id : id,signal) >= 0) {
		    if (verbose)
			fprintf(stderr,"Killed %s(%s%d)\n",got_long ? command :
			  comm,process_group ? "pgid " : "",id);
		    found |= 1 << j;
		    pid_killed[pids_killed++] = id;
		}
		else if (errno != ESRCH || interactive)
			fprintf(stderr,"%s(%d): %s\n",got_long ? command :
			  comm,id,strerror(errno));
	}
    }
    if (empty) {
	fprintf(stderr,PROC_BASE " is empty (not mounted ?)\n");
	exit(1);
    }
    if (!quiet && !pidof)
	for (i = 0; i < names; i++)
	    if (!(found & (1 << i)))
		fprintf(stderr,"%s: no process killed\n",namelist[i]);
    if (pidof) putchar('\n');
    error = found == ((1 << (names-1)) | ((1 << (names-1))-1)) ? 0 : 1;
    /*
     * We scan all (supposedly) killed processes every second to detect dead
     * processes as soon as possible in order to limit problems of race with
     * PID re-use.
     */
    while (pids_killed && wait_until_dead) {
	for (i = 0; i < pids_killed;) {
	    if (kill(process_group ? -pid_killed[i] : pid_killed[i],0) < 0 &&
	      errno == ESRCH) {
		pid_killed[i] = pid_killed[--pids_killed];
		continue;
	    }
	    i++;
	}
	sleep(1); /* wait a bit longer */
    }
    return error;
}


static void usage_pidof(void)
{
    fprintf(stderr,"usage: pidof [ -eg ] name ...\n");
    fprintf(stderr,"       pidof -V\n\n");
    fprintf(stderr,"    -e      require exact match for very long names;\n");
    fprintf(stderr,"            skip if the command line is unavailable\n");
    fprintf(stderr,"    -g      show process group ID instead of process ID\n");
    fprintf(stderr,"    -V      display version information\n\n");
}


static void usage_killall(void)
{
    fprintf(stderr,"usage: killall [ -egiqvw ] [ -signal ] name ...\n");
    fprintf(stderr,"       killall -l\n");
    fprintf(stderr,"       killall -V\n\n");
    fprintf(stderr,"    -e      require exact match for very long names;\n");
    fprintf(stderr,"            skip if the command line is unavailable\n");
    fprintf(stderr,"    -g      kill process group instead of process\n");
    fprintf(stderr,"    -i      ask for confirmation before killing\n");
    fprintf(stderr,"    -l      list all known signal names\n");
    fprintf(stderr,"    -q      quiet; don't print complaints\n");
    fprintf(stderr,"    -signal send signal instead of SIGTERM\n");
    fprintf(stderr,"    -v      report if the signal was successfully sent\n");
    fprintf(stderr,"    -V      display version information\n");
    fprintf(stderr,"    -w      wait for processes to die\n\n");
}


static void usage(void)
{
    if (pidof) usage_pidof();
    else usage_killall();
    exit(1);
}


int main(int argc,char **argv)
{
    char *name,*walk;
    int sig_num;

    name = strrchr(*argv,'/');
    if (name) name++;
    else name = *argv;
    pidof = strcmp(name,"killall");
    if (argc == 2 && !strcmp(argv[1],"-l")) {
	if (pidof) usage();
	list_signals();
	return 0;
    }
    if (argc == 2 && !strcmp(argv[1],"-V")) {
	fprintf(stderr,"%s from psmisc version " PSMISC_VERSION "\n",
	  pidof ? "pidof" : "killall");
	return 0;
    }
    sig_num = SIGTERM;
    while (argc > 1 && *argv[1] == '-') {
	argc--;
	argv++;
	if (**argv == '-') {
	    for (walk = *argv+1; *walk && strchr("eigqvw",*walk); walk++) {
		switch (*walk) {
		    case 'e':
			exact = 1;
			break;
		    case 'i':
			if (pidof) usage();
			interactive = 1;
			break;
		    case 'g':
			process_group = 1;
			break;
		    case 'q':
			if (pidof) usage();
			quiet = 1;
			break;
		    case 'v':
			if (pidof) usage();
			verbose = 1;
			break;
		    case 'w':
			if (pidof) usage();
			wait_until_dead = 1;
			break;
		}
	    }
	    if (*walk)
		if (walk != *argv+1 || pidof) usage();
		else sig_num = get_signal(*argv+1,"killall");
	}
    }
    if (argc < 2) usage();
    if (argc > MAX_NAMES+1) {
	fprintf(stderr,"Maximum number of names is %d\n",MAX_NAMES);
	exit(1);
    }
    return kill_all(sig_num,argc-1,argv+1);
}
