/* killall.c - kill processes by name or list PIDs */

/* Copyright 1993-1998 Werner Almesberger. See file COPYING for details. */

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

#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#endif /*WITH_SELINUX*/

#include "i18n.h"
#include "comm.h"
#include "signals.h"


#define PROC_BASE "/proc"
#define MAX_NAMES (int)(sizeof(unsigned long)*8)


static int verbose = 0, exact = 0, interactive = 0,
           quiet = 0, wait_until_dead = 0, process_group = 0,
           ignore_case = 0, pidof;

static int
ask (char *name, pid_t pid)
{
  int res;
  size_t len;
  char *line;

  line = NULL;
  len = 0;

  do {
    printf (_("Kill %s(%s%d) ? (y/N) "), name, process_group ? "pgid " : "",
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

#ifdef WITH_SELINUX
static int
kill_all(int signal, int names, char **namelist, security_context_t scontext )
#else  /*WITH_SELINUX*/
static int
kill_all (int signal, int names, char **namelist)
#endif /*WITH_SELINUX*/
{
  DIR *dir;
  struct dirent *de;
  FILE *file;
  struct stat st, sts[MAX_NAMES];
  int *name_len;
  char *path, comm[COMM_LEN];
  char *command_buf;
  char *command;
  pid_t *pid_table, pid, self, *pid_killed;
  pid_t *pgids;
  int empty, i, j, okay, length, got_long, error;
  int pids, max_pids, pids_killed;
  unsigned long found;
#ifdef WITH_SELINUX
  security_context_t lcontext=NULL;

  if ( names == 0 || ! namelist ) exit( 1 ); /* do the obvious thing...*/
#endif /*WITH_SELINUX*/

  if (!(name_len = malloc (sizeof (int) * names)))
    {
      perror ("malloc");
      exit (1);
    }
  for (i = 0; i < names; i++) {
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
  empty = 1;
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
      if (asprintf (&path, PROC_BASE "/%d/stat", pid_table[i]) < 0)
	continue;
      if (!(file = fopen (path, "r"))) 
	{
	  free (path);
	  continue;
	}
      free (path);
      empty = 0;
      okay = fscanf (file, "%*d (%[^)]", comm) == 1;
      (void) fclose (file);
      if (!okay)
	continue;
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
      for (j = 0; j < names; j++)
	{
	  pid_t id;

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
	      else if (got_long ? strcmp (namelist[j], command) :
		       strncmp (namelist[j], comm, COMM_LEN - 1))
		continue;
#ifdef WITH_SELINUX
              if ( scontext != NULL ) {
                if ( getpidcon(pid_table[i], &lcontext) < 0 )
                  continue;
                if (strcmp(lcontext,scontext)!=0) {
		  freecon(lcontext);
                  continue;
		}
		freecon(lcontext);
              }
#endif /*WITH_SELINUX*/
	    }
	  else
	    {
	      if (asprintf (&path, PROC_BASE "/%d/exe", pid_table[i]) < 0)
		continue;

	      if (stat (path, &st) < 0) {
		    free (path);
		    continue;
	      }
	      free (path);
#ifdef WITH_SELINUX
              if ( scontext != NULL ) {
                if ( getpidcon(pid_table[i], &lcontext) < 0 )
                  continue;
                if (strcmp(lcontext,scontext)!=0) {
		  freecon(lcontext);
                  continue;
		}
		freecon(lcontext);
              }
#endif /*WITH_SELINUX*/
	      if (sts[j].st_dev != st.st_dev || sts[j].st_ino != st.st_ino)
		continue;
	    }
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
	  if (interactive && !ask (comm, id))
	    continue;
	  if (pidof)
	    {
	      if (found)
		putchar (' ');
	      printf ("%d", id);
	      found |= 1 << j;
	    }
	  else if (kill (process_group ? -id : id, signal) >= 0)
	    {
	      if (verbose)
		fprintf (stderr, _("Killed %s(%s%d) with signal %d\n"), got_long ? command :
			 comm, process_group ? "pgid " : "", id, signal);
	      found |= 1 << j;
	      pid_killed[pids_killed++] = id;
	    }
	  else if (errno != ESRCH || interactive)
	    fprintf (stderr, "%s(%d): %s\n", got_long ? command :
		     comm, id, strerror (errno));
	}
    }
  if (empty)
    {
      fprintf (stderr, _("%s is empty (not mounted ?)\n"), PROC_BASE);
      exit (1);
    }
  if (!quiet && !pidof)
    for (i = 0; i < names; i++)
      if (!(found & (1 << i)))
	fprintf (stderr, _("%s: no process killed\n"), namelist[i]);
  if (pidof)
    putchar ('\n');
  error = found == ((1 << (names - 1)) | ((1 << (names - 1)) - 1)) ? 0 : 1;
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
  fprintf(stderr, _(
    "Usage: killall [OPTIONS]... [--] NAME...\n"
    "       killall -l, --list\n"
    "       killall -V, --version\n\n"
    "  -e,--exact          require exact match for very long names\n"
    "  -I,--ignore-case    case insensitive process name match\n"
    "  -g,--process-group  kill process group instead of process\n"
    "  -i,--interactive    ask for confirmation before killing\n"
    "  -l,--list           list all known signal names\n"
    "  -q,--quiet          don't print complaints\n"
    "  -s,--signal SIGNAL  send this signal instead of SIGTERM\n"
    "  -v,--verbose        report if the signal was successfully sent\n"
    "  -V,--version        display version information\n"
    "  -w,--wait           wait for processes to die\n\n"));
#ifdef WITH_SELINUX
  fprintf(stderr, _(
    "  -Z,--context CONTEXT kill only process(es) having context\n"
    "                      (must precede other arguments)"));
#endif /*WITH_SELINUX*/
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
    "Copyright (C) 1993-2002 Werner Almesberger and Craig Small\n\n"));
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
  //int optsig = 0;

  struct option options[] = {
    {"exact", 0, NULL, 'e'},
    {"ignore-case", 0, NULL, 'I'},
    {"process-group", 0, NULL, 'g'},
    {"interactive", 0, NULL, 'i'},
    {"list-signals", 0, NULL, 'l'},
    {"quiet", 0, NULL, 'q'},
    {"signal", 1, NULL, 's'},
    {"verbose", 0, NULL, 'v'},
    {"wait", 0, NULL, 'w'},
#ifdef WITH_SELINUX
    {"context", 1, NULL, 'Z'},
#endif /*WITH_SELINUX*/
    {"version", 0, NULL, 'V'},
    {0,0,0,0 }};

#ifdef WITH_SELINUX
  security_context_t scontext = NULL;

  if ( argc < 2 ) usage(); /* do the obvious thing... */
#endif /*WITH_SELINUX*/

  name = strrchr (*argv, '/');
  if (name)
    name++;
  else
    name = *argv;
  pidof = strcmp (name, "killall");
  sig_num = SIGTERM;

  /* Setup the i18n */
#ifdef ENABLE_NLS
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  opterr = 0;
#ifdef WITH_SELINUX
  while ( (optc = getopt_long_only(argc,argv,"egilqs:vwZ:VI",options,NULL)) != EOF) {
#else
  while ( (optc = getopt_long_only(argc,argv,"egilqs:vwVI",options,NULL)) != EOF) {
#endif
    switch (optc) {
      case 'e':
        exact = 1;
        break;
      case 'g':
        process_group = 1;
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
      case 's':
	sig_num = get_signal (optarg, "killall");
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
        if (is_selinux_enabled()>0) 
           scontext=optarg;
        else 
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
  if (argc - myoptind < 1) 
    usage();

  if (argc - myoptind > MAX_NAMES + 1)
    {
      fprintf (stderr, _("Maximum number of names is %d\n"), MAX_NAMES);
      exit (1);
    }
  argv = argv + myoptind;
  /*printf("sending signal %d to procs\n", sig_num);*/
#ifdef WITH_SELINUX
  return kill_all(sig_num,argc - myoptind, argv, scontext);
#else  /*WITH_SELINUX*/
  return kill_all(sig_num,argc - myoptind, argv );
#endif /*WITH_SELINUX*/
}
