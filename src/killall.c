/*
 * killall.c - kill processes by name or list PIDs
 *
 * Copyright (C) 1993-2002 Werner Almesberger
 * Copyright (C) 2002-2007 Craig Small
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <pwd.h>
#include <regex.h>
#include <ctype.h>
#include <assert.h>

#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#endif /*WITH_SELINUX*/

#include "i18n.h"
#include "comm.h"
#include "signals.h"

#define PROC_BASE "/proc"
#define MAX_NAMES (int)(sizeof(unsigned long)*8)

#define TSECOND "sec"
#define TMINUTE "min"
#define THOUR   "hour"
#define TDAY    "day" 
#define TWEEK   "WEEK"
#define TMONTH  "MON" 
#define TYEAR   "YEAR"

#define TMAX_SECOND 31536000
#define TMAX_MINUTE 525600  
#define TMAX_HOUR   8760    
#define TMAX_DAY    365     
#define TMAX_WEEK   48      
#define TMAX_MONTH  12      
#define TMAX_YEAR   1       

#define ER_REGFAIL -1
#define ER_NOMEM   -2
#define ER_UNKWN   -3
#define ER_OOFRA   -4

static int verbose = 0, exact = 0, interactive = 0, reg = 0,
           quiet = 0, wait_until_dead = 0, process_group = 0,
           younger_than = 0, older_than = 0,
           ignore_case = 0, pidof;

static int
ask (char *name, pid_t pid, const int signal)
{
  int res;
  size_t len;
  char *line;

  line = NULL;
  len = 0;

  do {
    if (signal == SIGTERM)
        printf (_("Kill %s(%s%d) ? (y/N) "), name, process_group ? "pgid " : "",
	        pid);
    else
        printf (_("Signal %s(%s%d) ? (y/N) "), name, process_group ? "pgid " : "",
	        pid);

    fflush (stdout);

    if (getline (&line, &len, stdin) < 0)
      return 0;
    /* Check for default */
    if (line[0] == '\n') {
      free(line);
      return 0;
    }
    res = rpmatch(line);
    if (res >= 0) {
      free(line);
      return res;
    }
  } while(1);
  /* Never should get here */
}

static double
uptime()
{
   char * savelocale;
   char buf[2048];
   FILE* file;
   if (!(file=fopen( PROC_BASE "/uptime", "r"))) {
      fprintf(stderr, "error opening uptime file\n");	
      exit(1);
   }
   savelocale = setlocale(LC_NUMERIC, NULL);
   setlocale(LC_NUMERIC,"C");
   fscanf(file, "%s", buf);
   fclose(file);
   setlocale(LC_NUMERIC,savelocale);
   return atof(buf);
}

/* process age from jiffies to seconds via uptime */
static double process_age(const unsigned jf)
{
   double sc_clk_tck = sysconf(_SC_CLK_TCK);
   assert(sc_clk_tck > 0);
   return uptime() - jf / sc_clk_tck;
}

/* returns requested time interval in seconds, 
 negative indicates error has occured  
 */
static time_t 
parse_time_units(const char* age)
{
   regex_t preg;
   if ( 0 == regcomp(&preg, "^[0-9]{1,8}[a-zA-Z]{1,8}$", REG_NOSUB | REG_EXTENDED)) {
      int ret = regexec(&preg, age, (size_t)0, NULL, 0);
      regfree(&preg);
      if ( 0 != ret )
	return ER_REGFAIL;
   }

   time_t res;
   char * savelocale;
   savelocale = setlocale(LC_ALL, NULL);
   setlocale(LC_NUMERIC,"C");

   unsigned int i;
   for (i=0; i<strlen(age); i++) {
      if ( isdigit( (int)age[i] ) )
	continue;
      else
	break;
   }

   char *numb, *unit;
   if ( NULL == (numb = calloc(sizeof(char), i +1)))
     return ER_NOMEM;
   if ( NULL == (unit = calloc(sizeof(char), strlen(age) -i +1))) {
      free(numb);
      return ER_NOMEM;
   };
   
   strncpy(numb, &age[0], i +1);
   strncpy(unit, &age[i], strlen(age) - i +1);
   time_t numbll = atoll(numb);

   if      ( (strlen(unit) == strlen(TSECOND)) && (0 == strncmp(TSECOND, unit, strlen(TSECOND)))) 
     res = numbll <= TMAX_SECOND ? numbll : ER_OOFRA;

   else if ( (strlen(unit) == strlen(TMINUTE)) && (0 == strncmp(TMINUTE, unit, strlen(TMINUTE))))
     res = numbll <= TMAX_MINUTE ? numbll * 60 : ER_OOFRA;

   else if ( (strlen(unit) == strlen(THOUR))   && (0 == strncmp(THOUR, unit, strlen(THOUR)))) 
     res = numbll <=TMAX_HOUR    ? numbll * 60 * 60 : ER_OOFRA;

   else if ( (strlen(unit) == strlen(TDAY) )   && (0 == strncmp(TDAY, unit, strlen(TDAY))))
     res = numbll <= TMAX_DAY    ? numbll * 60 * 60 * 24 : ER_OOFRA;

   else if ( (strlen(unit) == strlen(TWEEK) )  && (0 == strncmp(TWEEK, unit, strlen(TWEEK))))
     res = numbll <= TMAX_WEEK   ? numbll * 60 * 60 * 24 * 7 : ER_OOFRA;

   else if ( (strlen(unit) == strlen(TMONTH) ) && (0 == strncmp(TMONTH, unit, strlen(TMONTH))))
     res = numbll <= TMAX_MONTH  ? numbll * 60 * 60 * 24 * 7 * 4 : ER_OOFRA;

   else if ( (strlen(unit) == strlen(TYEAR) )  && (0 == strncmp(TYEAR, unit, strlen(TYEAR))))
     res = numbll <= TMAX_YEAR   ? numbll * 60 * 60 * 24 * 7 * 4 * 12 : ER_OOFRA;
   else
     res = ER_UNKWN;

   free(numb);
   free(unit);   
   setlocale(LC_ALL,savelocale);
   
   return res;
}

static int
match_process_uid(pid_t pid, uid_t uid)
{
	char buf[128];
	uid_t puid;
	FILE *f;
	int re = -1;
	
	snprintf (buf, sizeof buf, PROC_BASE "/%d/status", pid);
	if (!(f = fopen (buf, "r")))
		return 0;
	
	while (fgets(buf, sizeof buf, f))
	{
		if (sscanf (buf, "Uid:\t%d", &puid))
		{
			re = uid==puid;
			break;
		}
	}
	fclose(f);
	if (re==-1)
	{
		fprintf(stderr, _("Cannot get UID from process status\n"));
		exit(1);
	}
	return re;
}

static regex_t *
build_regexp_list(int names, char **namelist)
{
	int i;
	regex_t *reglist;
	int flag = REG_EXTENDED|REG_NOSUB;
	
	if (!(reglist = malloc (sizeof (regex_t) * names)))
	{
		perror ("malloc");
		exit (1);
	}

	if (ignore_case)
		flag |= REG_ICASE;
	
	for (i = 0; i < names; i++)
	{
		if (regcomp(&reglist[i], namelist[i], flag) != 0) 
		{
			fprintf(stderr, _("Bad regular expression: %s\n"), namelist[i]);
			exit (1);
		}
	}
	return reglist;
}

#ifdef WITH_SELINUX
static int
kill_all(int signal, int names, char **namelist, struct passwd *pwent, 
					regex_t *scontext )
#else  /*WITH_SELINUX*/
static int
kill_all (int signal, int names, char **namelist, struct passwd *pwent)
#endif /*WITH_SELINUX*/
{
  DIR *dir;
  struct dirent *de;
  FILE *file;
  struct stat st, sts[MAX_NAMES];
  int *name_len = NULL;
  char *path, comm[COMM_LEN];
  char *command_buf;
  char *command;
  pid_t *pid_table, pid, self, *pid_killed;
  pid_t *pgids;
  int i, j, okay, length, got_long, error;
  int pids, max_pids, pids_killed;
  unsigned long found;
  regex_t *reglist = NULL;;
#ifdef WITH_SELINUX
  security_context_t lcontext=NULL;
#endif /*WITH_SELINUX*/

  if (names && reg) 
      reglist = build_regexp_list(names, namelist);
  else if (names)
   {
      if (!(name_len = malloc (sizeof (int) * names)))
        {
          perror ("malloc");
          exit (1);
        }
      for (i = 0; i < names; i++) 
        {
          if (!strchr (namelist[i], '/'))
            {
	      sts[i].st_dev = 0;
	      name_len[i] = strlen (namelist[i]);
            }
          else if (stat (namelist[i], &sts[i]) < 0)
            {
	      perror (namelist[i]);
	      exit (1);
            }
        }
    } 
  self = getpid ();
  found = 0;
  if (!(dir = opendir (PROC_BASE)))
    {
      perror (PROC_BASE);
      exit (1);
    }
  max_pids = 256;
  pid_table = malloc (max_pids * sizeof (pid_t));
  if (!pid_table)
    {
      perror ("malloc");
      exit (1);
    }
  pids = 0;
  while ( (de = readdir (dir)) != NULL)
    {
      if (!(pid = (pid_t) atoi (de->d_name)) || pid == self)
	continue;
      if (pids == max_pids)
	{
	  if (!(pid_table = realloc (pid_table, 2 * pids * sizeof (pid_t))))
	    {
	      perror ("realloc");
	      exit (1);
	    }
	  max_pids *= 2;
	}
      pid_table[pids++] = pid;
    }
  (void) closedir (dir);
  pids_killed = 0;
  pid_killed = malloc (max_pids * sizeof (pid_t));
  if (!pid_killed)
    {
      perror ("malloc");
      exit (1);
    }
  if (!process_group)
    pgids = NULL;		/* silence gcc */
  else
    {
      pgids = malloc (pids * sizeof (pid_t));
      if (!pgids)
	{
	  perror ("malloc");
	  exit (1);
	}
    }
  for (i = 0; i < pids; i++)
    {
      pid_t id;
      int found_name = -1;
      double process_age_sec = 0;
      /* match by UID */
      if (pwent && match_process_uid(pid_table[i], pwent->pw_uid)==0)
	continue;
#ifdef WITH_SELINUX
      /* match by SELinux context */
      if (scontext) 
        {
          if (getpidcon(pid_table[i], &lcontext) < 0)
            continue;
	  if (regexec(scontext, lcontext, 0, NULL, 0) != 0) {
            freecon(lcontext);
            continue;
          }
          freecon(lcontext);
        }
#endif /*WITH_SELINUX*/
      /* load process name */
      if (asprintf (&path, PROC_BASE "/%d/stat", pid_table[i]) < 0)
	continue;
      if (!(file = fopen (path, "r"))) 
	{
	  free (path);
	  continue;
	}
      free (path);
      okay = fscanf (file, "%*d (%15[^)]", comm) == 1;
      if (!okay) {
	fclose(file);
	continue;
      }
      if ( younger_than || older_than ) {
	 rewind(file);
	 unsigned int proc_stt_jf = 0;
	 okay = fscanf(file, "%*d %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %ull", 
		       &proc_stt_jf) == 1;
	 if (!okay) {
	    fclose(file);
	    continue;
	 }
	 process_age_sec = process_age(proc_stt_jf);
	 assert(process_age_sec > 0);
      }
      (void) fclose (file);
       
      got_long = 0;
      command = NULL;		/* make gcc happy */
      length = strlen (comm);
      if (length == COMM_LEN - 1)
	{
	  if (asprintf (&path, PROC_BASE "/%d/cmdline", pid_table[i]) < 0)
	    continue;
	  if (!(file = fopen (path, "r"))) {
	    free (path);
	    continue;
	  }
	  free (path);
          while (1) {
            /* look for actual command so we skip over initial "sh" if any */
            char *p;
	    int cmd_size = 128;
	    command_buf = (char *)malloc (cmd_size);
	    if (!command_buf)
	      exit (1);

            /* 'cmdline' has arguments separated by nulls */
            for (p=command_buf; ; p++) {
              int c;
	      if (p == (command_buf + cmd_size)) 
		{
		  int cur_size = cmd_size;
		  cmd_size *= 2;
		  command_buf = (char *)realloc(command_buf, cmd_size);
		  if (!command_buf)
		    exit (1);
		  p = command_buf + cur_size;
		}
              c = fgetc(file);
              if (c == EOF || c == '\0') {
                *p = '\0';
                break;
              } else {
                *p = c;
              }
            }
            if (strlen(command_buf) == 0) {
              okay = 0;
              break;
            }
            p = strrchr(command_buf,'/');
            p = p ? p+1 : command_buf;
            if (strncmp(p, comm, COMM_LEN-1) == 0) {
              okay = 1;
              command = p;
              break;
            }
          }
          (void) fclose(file);
	  if (exact && !okay)
	    {
	      if (verbose)
		fprintf (stderr, _("skipping partial match %s(%d)\n"), comm,
			 pid_table[i]);
	      continue;
	    }
	  got_long = okay;
	}
      /* mach by process name */
      for (j = 0; j < names; j++)
	{
	  if (reg)
	    {
	      if (regexec (&reglist[j], got_long ? command : comm, 0, NULL, 0) != 0)
		      continue;
	    }
	  else /* non-regex */
	    {
	      if ( younger_than && process_age_sec && (process_age_sec > younger_than ) )
		 continue;
	      if ( older_than   && process_age_sec && (process_age_sec < older_than ) )
		 continue;
	       
 	      if (!sts[j].st_dev)
	        {
	          if (length != COMM_LEN - 1 || name_len[j] < COMM_LEN - 1)
	  	    {
		      if (ignore_case == 1)
		        {
		          if (strcasecmp (namelist[j], comm))
		             continue;
		        }
		      else
		        {
		          if (strcmp(namelist[j], comm))
		             continue;
		        }
		    }
	          else
	            {
	              if (ignore_case == 1)
	                {
	                  if (got_long ? strcasecmp (namelist[j], command) :
	                                 strncasecmp (namelist[j], comm, COMM_LEN - 1))
	                     continue;
	                }
	              else
	                {
	                  if (got_long ? strcmp (namelist[j], command) :
	                                 strncmp (namelist[j], comm, COMM_LEN - 1))
	                     continue;
	                }
	            }
	        }
	      else
	        {
		  int ok = 1;

	          if (asprintf (&path, PROC_BASE "/%d/exe", pid_table[i]) < 0)
		    continue;

	          if (stat (path, &st) < 0) 
		      ok = 0;

		  else if (sts[j].st_dev != st.st_dev ||
			   sts[j].st_ino != st.st_ino)
		    {
		      /* maybe the binary has been modified and std[j].st_ino
		       * is not reliable anymore. We need to compare paths.
		       */
		      char linkbuf[PATH_MAX];

		      if (readlink(path, linkbuf, sizeof(linkbuf)) <= 0 ||
					  strcmp(namelist[j], linkbuf))
			ok = 0;
		    }

		  free(path);
		  if (!ok)
		    continue;
	        }
	    } /* non-regex */
	  found_name = j;
	  break;
	}  
        
        if (names && found_name==-1)
	  continue;  /* match by process name faild */
	
        /* check for process group */
	if (!process_group)
	  id = pid_table[i];
	else
	  {
	    int j;

	    id = getpgid (pid_table[i]);
	    pgids[i] = id;
	    if (id < 0)
	      {
	        fprintf (stderr, "getpgid(%d): %s\n", pid_table[i],
		   strerror (errno));
	      }
	    for (j = 0; j < i; j++)
	      if (pgids[j] == id)
	        break;
	    if (j < i)
	      continue;
	  }	
	if (interactive && !ask (comm, id, signal))
	  continue;
	if (pidof)
	  {
	    if (found)
	       putchar (' ');
	    printf ("%d", id);
	    found |= 1 << (found_name >= 0 ? found_name : 0);
	  }
	else if (kill (process_group ? -id : id, signal) >= 0)
	  {
	    if (verbose)
	      fprintf (stderr, _("Killed %s(%s%d) with signal %d\n"), got_long ? command :
			 comm, process_group ? "pgid " : "", id, signal);
	    if (found_name >= 0)
		    /* mark item of namelist */
		    found |= 1 << found_name;
	    pid_killed[pids_killed++] = id;
	  }
	else if (errno != ESRCH || interactive)
	  fprintf (stderr, "%s(%d): %s\n", got_long ? command :
	    	comm, id, strerror (errno));
    }
  if (!quiet && !pidof)
    for (i = 0; i < names; i++)
      if (!(found & (1 << i)))
	fprintf (stderr, _("%s: no process found\n"), namelist[i]);
  if (pidof)
    putchar ('\n');
  if (names)
    /* killall returns a zero return code if at least one process has 
     * been killed for each listed command. */
    error = found == ((1 << (names - 1)) | ((1 << (names - 1)) - 1)) ? 0 : 1;
  else
    /* in nameless mode killall returns a zero return code if at least 
     * one process has killed */
    error = pids_killed ? 0 : 1;
  /*
   * We scan all (supposedly) killed processes every second to detect dead
   * processes as soon as possible in order to limit problems of race with
   * PID re-use.
   */
  while (pids_killed && wait_until_dead)
    {
      for (i = 0; i < pids_killed;)
	{
	  if (kill (process_group ? -pid_killed[i] : pid_killed[i], 0) < 0 &&
	      errno == ESRCH)
	    {
	      pid_killed[i] = pid_killed[--pids_killed];
	      continue;
	    }
	  i++;
	}
      sleep (1);		/* wait a bit longer */
    }
  return error;
}


static void
usage_pidof (void)
{
  fprintf (stderr, _(
    "Usage: pidof [ -eg ] NAME...\n"
    "       pidof -V\n\n"
    "    -e      require exact match for very long names;\n"
    "            skip if the command line is unavailable\n"
    "    -g      show process group ID instead of process ID\n"
    "    -V      display version information\n\n"));
}


static void
usage_killall (void)
{
#ifdef WITH_SELINUX
   fprintf(stderr, _(
     "Usage: killall [-Z CONTEXT] [-u USER] [ -eIgiqrvw ] [ -SIGNAL ] NAME...\n"));
#else  /*WITH_SELINUX*/
  fprintf(stderr, _(
    "Usage: killall [OPTION]... [--] NAME...\n"));
#endif /*WITH_SELINUX*/
  fprintf(stderr, _(
    "       killall -l, --list\n"
    "       killall -V, --version\n\n"
    "  -e,--exact          require exact match for very long names\n"
    "  -I,--ignore-case    case insensitive process name match\n"
    "  -g,--process-group  kill process group instead of process\n"
    "  -y,--younger-than   kill processes younger than Nsec,min,hour,day,WEEK,MON,YEAR\n"
    "  -o,--older-than     kill processes older than Nsec,min,hour,day,WEEK,MON,YEAR\n"		    
    "  -i,--interactive    ask for confirmation before killing\n"
    "  -l,--list           list all known signal names\n"
    "  -q,--quiet          don't print complaints\n"
    "  -r,--regexp         interpret NAME as an extended regular expression\n"
    "  -s,--signal SIGNAL  send this signal instead of SIGTERM\n"
    "  -u,--user USER      kill only process(es) running as USER\n"
    "  -v,--verbose        report if the signal was successfully sent\n"
    "  -V,--version        display version information\n"
    "  -w,--wait           wait for processes to die\n"));
#ifdef WITH_SELINUX
  fprintf(stderr, _(
    "  -Z,--context REGEXP kill only process(es) having context\n"
    "                      (must precede other arguments)\n"));
#endif /*WITH_SELINUX*/
  fputc('\n', stderr);
}


static void
usage (void)
{
  if (pidof)
    usage_pidof ();
  else
    usage_killall ();
  exit (1);
}

void print_version()
{
  fprintf(stderr, "%s (PSmisc) %s\n", pidof ? "pidof" : "killall", VERSION);
  fprintf(stderr, _(
    "Copyright (C) 1993-2005 Werner Almesberger and Craig Small\n\n"));
  fprintf(stderr, _(
    "PSmisc comes with ABSOLUTELY NO WARRANTY.\n"
    "This is free software, and you are welcome to redistribute it under\n"
    "the terms of the GNU General Public License.\n"
    "For more information about these matters, see the files named COPYING.\n"));
}

int
main (int argc, char **argv)
{
  char *name;
  int sig_num;
  int optc;
  int myoptind;
  struct passwd *pwent = NULL;
  struct stat isproc;
  char yt[16];
  char ot[16];

  //int optsig = 0;

  struct option options[] = {
    {"exact", 0, NULL, 'e'},
    {"ignore-case", 0, NULL, 'I'},
    {"process-group", 0, NULL, 'g'},
    {"younger-than", 1, NULL, 'y'},
    {"older-than", 1, NULL, 'o'},
    {"interactive", 0, NULL, 'i'},
    {"list-signals", 0, NULL, 'l'},
    {"quiet", 0, NULL, 'q'},
    {"regexp", 0, NULL, 'r'},
    {"signal", 1, NULL, 's'},
    {"user", 1, NULL, 'u'},
    {"verbose", 0, NULL, 'v'},
    {"wait", 0, NULL, 'w'},
#ifdef WITH_SELINUX
    {"context", 1, NULL, 'Z'},
#endif /*WITH_SELINUX*/
    {"version", 0, NULL, 'V'},
    {0,0,0,0 }};

  /* Setup the i18n */
#ifdef ENABLE_NLS
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif
#ifdef WITH_SELINUX
  security_context_t scontext = NULL;
  regex_t scontext_reg;

  if ( argc < 2 ) usage(); /* do the obvious thing... */
#endif /*WITH_SELINUX*/

  name = strrchr (*argv, '/');
  if (name)
    name++;
  else
    name = *argv;
  pidof = strcmp (name, "killall");
  sig_num = SIGTERM;


  opterr = 0;
#ifdef WITH_SELINUX
  while ( (optc = getopt_long_only(argc,argv,"egy:o:ilqrs:u:vwZ:VI",options,NULL)) != -1) {
#else
  while ( (optc = getopt_long_only(argc,argv,"egy:o:ilqrs:u:vwVI",options,NULL)) != -1) {
#endif
    switch (optc) {
      case 'e':
        exact = 1;
        break;
      case 'g':
        process_group = 1;
        break;
      case 'y':
       if (pidof)
	 usage();
       strncpy(yt, optarg, 16);
       if ( 0 >= (younger_than = parse_time_units(yt) ) )
	    usage();
       break;
      case 'o':
       if (pidof)
	 usage();       
       strncpy(ot, optarg, 16);
       if ( 0 >= (older_than = parse_time_units(ot) ) )
	    usage();
       break;
      case 'i':
        if (pidof)
          usage();
        interactive = 1;
        break;
      case 'l':
        if (pidof)
          usage();
        list_signals();
        return 0;
        break;
      case 'q':
        if (pidof)
          usage();
        quiet = 1;
        break;
      case 'r':
	if (pidof)
	  usage();
	reg = 1;
	break;
      case 's':
	sig_num = get_signal (optarg, "killall");
        break;
      case 'u':
	if (pidof)
	  usage();
        if (!(pwent = getpwnam(optarg)))
	  {
            fprintf (stderr, _("Cannot find user %s\n"), optarg);
            exit (1);
          }
        break;
      case 'v':
        if (pidof)
          usage();
        verbose = 1;
        break;
      case 'w':
        if (pidof)
          usage();
        wait_until_dead = 1;
        break;
      case 'I':
        ignore_case = 1;
        break;
      case 'V':
        print_version();
        return 0;
        break;
#ifdef WITH_SELINUX
      case 'Z': 
        if (is_selinux_enabled()>0) {
	  scontext=optarg;
          if (regcomp(&scontext_reg, scontext, REG_EXTENDED|REG_NOSUB) != 0) {
            fprintf(stderr, _("Bad regular expression: %s\n"), scontext);
            exit (1);
	  }
        } else 
           fprintf(stderr, "Warning: -Z (--context) ignored. Requires an SELinux enabled kernel\n");
        break;
#endif /*WITH_SELINUX*/
      case '?':
        /* Signal names are in uppercase, so check to see if the argv
         * is upper case */
        if (argv[optind-1][1] >= 'A' && argv[optind-1][1] <= 'Z') {
	      sig_num = get_signal (argv[optind-1]+1, "killall");
        } else {
          /* Might also be a -## signal too */
          if (argv[optind-1][1] >= '0' && argv[optind-1][1] <= '9') {
            sig_num = atoi(argv[optind-1]+1);
          } else {
            usage();
          }
        }
        break;
    }
  }
  myoptind = optind;
#ifdef WITH_SELINUX
  if ((argc - myoptind < 1) && pwent==NULL && scontext==NULL) 
#else
  if ((argc - myoptind < 1) && pwent==NULL)	  
#endif
    usage();

  if (argc - myoptind > MAX_NAMES + 1)
    {
      fprintf (stderr, _("Maximum number of names is %d\n"), MAX_NAMES);
      exit (1);
    }
  if (stat("/proc/self/stat", &isproc)==-1)
    {
      fprintf (stderr, _("%s is empty (not mounted ?)\n"), PROC_BASE);
      exit (1);
    }
  argv = argv + myoptind;
  /*printf("sending signal %d to procs\n", sig_num);*/
#ifdef WITH_SELINUX
  return kill_all(sig_num,argc - myoptind, argv, pwent, 
		  		scontext ? &scontext_reg : NULL);
#else  /*WITH_SELINUX*/
  return kill_all(sig_num,argc - myoptind, argv, pwent);
#endif /*WITH_SELINUX*/
}
