/* fuser.c - identify processes using files */

/* Copyright 1993-1999 Werner Almesberger. See file COPYING for details. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <pwd.h>
#include <signal.h>
#include <limits.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef __linux__
#include <linux/kdev_t.h>	/* for MKDEV */
#include <linux/major.h>	/* for LOOP_MAJOR */
#endif
#ifdef ENABLE_NLS
#include <libintl.h>
#include <locale.h>
#define _(String) gettext (String)
#else
#define _(String) (String)
#endif

#include "comm.h"
#include "loop.h"         /* for loop_info */
#include "signals.h"


#define PROC_BASE  "/proc"
#define UID_UNKNOWN -1
#define NAME_FIELD 20		/* space reserved for file name */

#define MAX_LINE 256		/* longest line we may ever find in /proc */


#ifndef LOOP_MAJOR		/* don't count on the headers too much ... */
#define LOOP_MAJOR 7
#endif

#ifndef MAJOR
#define MAJOR(arg) 6           /* something that doesn't = LOOP_MAJOR */
#endif

#ifndef MKDEV
#define MKDEV(arg1, arg2) mknod("/dev/Isuck", arg1, arg2) /* this is wrong */
#endif


#define REF_FILE   1		/* an open file */
#define REF_ROOT   2		/* current root */
#define REF_CWD    4		/* current directory */
#define REF_EXE    8		/* executable */
#define REF_MMAP  16		/* mmap'ed file or library */

#define FLAG_KILL  1		/* kill process */
#define FLAG_UID   2		/* show uid */
#define FLAG_VERB  4		/* show verbose output */
#define FLAG_DEV   8		/* show all processes using this device */
#define FLAG_ASK  16		/* ask before killing a process */


typedef struct _net_cache
{
  struct sockaddr_storage rmt_addr;
  int lcl_port;
  int rmt_port;
  ino_t ino;
  struct _net_cache *next;
}
NET_CACHE;

typedef struct _unix_cache
{
  dev_t fs_dev;
  ino_t fs_ino;
  ino_t net_ino;
  struct _unix_cache *next;
}
UNIX_CACHE;

typedef struct
{
  const char *name;
  NET_CACHE *cache;
  int once;
}
SPACE_DSC;

typedef enum
{ it_proc, it_mount, it_loop, it_swap }
ITEM_TYPE;

typedef struct item_dsc
{
  ITEM_TYPE type;
  union
  {
    struct
    {
      pid_t pid;
      int uid;			/* must also accept UID_UNKNOWN */
      int ref_set;
    }
    proc;
    struct
    {
      const char *path;
    }
    misc;
  }
  u;
  struct item_dsc *next;
}
ITEM_DSC;

typedef struct file_dsc
{
  const char *name;		/* NULL if previous entry has name */
  dev_t dev;
  ino_t ino;
  int flags, sig_num;
  SPACE_DSC *name_space;	/* or NULL if no indication */
  ITEM_DSC *items;
  struct file_dsc *named, *next;
}
FILE_DSC;

static SPACE_DSC name_spaces[] = {
  {"file", NULL, 0},		/* must be first */
  {"tcp", NULL, 0},
  {"udp", NULL, 0},
  {NULL, NULL, 0}
};


static FILE_DSC *files = NULL;
static FILE_DSC *last_named = NULL;
static UNIX_CACHE *unix_cache = NULL;
static pid_t self;
static int all = 0, found_item = 0;
static dev_t net_dev;
static int ipv4only = 0, ipv6only = 0;


static void
parse_net_file (SPACE_DSC * dsc,char *filename, NET_CACHE **lastptr,int version )
{
  FILE *file;
  NET_CACHE *new, *last;
  char line[MAX_LINE + 1];
  char rmt_addr[128];
  char addr6[128];
  unsigned long tmp_ino;

  if (!(file = fopen (filename, "r")))
    {
      perror (filename);
      exit (1);
    }
  last = *lastptr;
  (void) fgets (line, MAX_LINE, file);
  while (fgets (line, MAX_LINE, file))
    {
      new = malloc (sizeof (NET_CACHE));
      if (!new)
	{
	  perror ("malloc");
	  exit (1);
	}
    if (sscanf (line, 
        "%*d: %*x:%x %64[0-9A-Fa-f]:%x %*x %*x:%*x %*x:%*x %*x %*d %*d %lu",
        &new->lcl_port, rmt_addr, &new->rmt_port, &tmp_ino) != 4)
	{
	  free (new);
	  continue;
	}
      new->ino = tmp_ino;
      if (strlen(rmt_addr) > 8) {
        sscanf(rmt_addr, "%08X%08X%08X%08X",
            &((struct sockaddr_in6 *)&new->rmt_addr)->sin6_addr.s6_addr32[0],
            &((struct sockaddr_in6 *)&new->rmt_addr)->sin6_addr.s6_addr32[1],
            &((struct sockaddr_in6 *)&new->rmt_addr)->sin6_addr.s6_addr32[2],
            &((struct sockaddr_in6 *)&new->rmt_addr)->sin6_addr.s6_addr32[3]);
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&new->rmt_addr)->sin6_addr, addr6, sizeof(addr6));
      } else {
        sscanf(rmt_addr, "%X",
            &((struct sockaddr_in *) &new->rmt_addr)->sin_addr.s_addr);
            ((struct sockaddr *) &new->rmt_addr)->sa_family = AF_INET;
      }
      if (!new->ino)
	{
	  free (new);
	  continue;
	}
      new->next = NULL;
      if (last)
	last->next = new;
      else
	dsc->cache = new;
      last = new;
    }
  (void) fclose (file);
  *lastptr = last;

}

static void
fill_net_cache (SPACE_DSC * dsc)
{
  NET_CACHE *last;
  struct stat statbuf;
  char *buffer = malloc (strlen (PROC_BASE) + strlen (dsc->name) + 8);
  if (!buffer)
    return;

  if (dsc->once)
    return;
  dsc->once = 1;
  last = NULL;

  /* Check to see if we have both namespace files, if we don't then silently
   * not use them if not flags are specified and complain if the flags
   * were specified.
   */
  
  if (!ipv6only) {
    sprintf (buffer, PROC_BASE "/net/%s", dsc->name);
    if (stat(buffer, &statbuf) != 0) {
      if (ipv4only) 
        fprintf(stderr, _("-4 flag used but proc file %s is not readable\n"), buffer);
    } else {
      parse_net_file (dsc, buffer, &last,4 );
    }
  }
  if (!ipv4only) {
    sprintf (buffer, PROC_BASE "/net/%s6", dsc->name);
    if (stat(buffer, &statbuf) != 0) {
      if (ipv6only) 
        fprintf(stderr, _("-6 flag used but proc file %s is not readable\n"), buffer);
    } else {
      parse_net_file (dsc, buffer, &last,6 );
    }
  }
}


static void
fill_unix_cache (void)
{
  static int once;
  FILE *file;
  UNIX_CACHE *new, *last;
  struct stat st;
  char *path = NULL, line[MAX_LINE + 1];
  int ino;

  if (once)
    return;
  once = 1;
  if (!(file = fopen (PROC_BASE "/net/unix", "r")))
    {
      perror (PROC_BASE "/net/unix");
      exit (1);
    }
  last = NULL;
  (void) fgets (line, MAX_LINE, file);
  while (fgets (line, MAX_LINE, file))
    {
      if (sscanf (line, "%*x: %*x %*x %*x %*x %*x %d %as", &ino, &path) != 2)
	continue;
      if (stat (path, &st) < 0) {
	free (path);
	continue;
      }
      free (path);

      new = malloc (sizeof (UNIX_CACHE));
      new->fs_dev = st.st_dev;
      new->fs_ino = st.st_ino;
      new->net_ino = ino;
      new->next = NULL;
      if (last)
	last->next = new;
      else
	unix_cache = new;
      last = new;
    }
  (void) fclose (file);

}


static unsigned long
try_to_find_unix_dev (ino_t inode)
{
  UNIX_CACHE *walk;

  for (walk = unix_cache; walk; walk = walk->next)
    if (walk->net_ino == inode)
      return walk->fs_dev;
  return 0;
}


static void
add_file (const char *path, dev_t device, ino_t inode,
	  pid_t pid, int ref)
{
  struct stat st;
  FILE_DSC *file, *next;
  ITEM_DSC **item, *this;
  dev_t mount_dev;

  if (device)
    mount_dev = device;
  else
    mount_dev = try_to_find_unix_dev (inode);
  for (file = files; file; file = next)
    {
      next = file->next;
      if (file->flags & FLAG_DEV ? mount_dev && mount_dev == file->dev :
	  device == file->dev && inode == file->ino)
	{
	  if (!file->name)
	    file = file->named;
	  for (item = &file->items; *item; item = &(*item)->next)
	    if ((*item)->type == it_proc && (*item)->u.proc.pid >= pid)
	      break;
	  if (*item && (*item)->u.proc.pid == pid)
	    this = *item;
	  else
	    {
	      if (!(this = malloc (sizeof (ITEM_DSC))))
		{
		  perror ("malloc");
		  exit (1);
		}
	      this->type = it_proc;
	      this->u.proc.pid = pid;
	      this->u.proc.uid = UID_UNKNOWN;
	      this->u.proc.ref_set = 0;
	      this->next = *item;
	      *item = this;
	      found_item = 1;
	    }
	  this->u.proc.ref_set |= ref;
	  if ((file->flags & (FLAG_UID | FLAG_VERB)) && this->u.proc.uid ==
	      UID_UNKNOWN && lstat (path, &st) >= 0)
	    this->u.proc.uid = st.st_uid;
	}
    }
}


static void
add_other (ITEM_TYPE type, dev_t mount_dev,
	   dev_t device, ino_t inode, const char *path)
{
  FILE_DSC *file, *next;
  ITEM_DSC **item, *this;

  for (file = files; file; file = next)
    {
      next = file->next;
      if (file->flags & FLAG_DEV ? mount_dev == file->dev :
	  device == file->dev && inode == file->ino)
	{
	  if (!file->name)
	    file = file->named;
	  for (item = &file->items; *item; item = &(*item)->next);
	  /* there's no easy way to suppress duplicates, so we don't */
	  if (!(this = malloc (sizeof (ITEM_DSC))))
	    {
	      perror ("malloc");
	      exit (1);
	    }
	  this->type = type;
	  if (!(this->u.misc.path = strdup (path)))
	    {
	      perror ("strdup");
	      exit (1);
	    }
	  this->next = *item;
	  *item = this;
	  found_item = 1;
	}
    }
}


static void
check_link (const char *path, pid_t pid, int type)
{
  struct stat st;

  if (stat (path, &st) >= 0)
    add_file (path, st.st_dev, st.st_ino, pid, type);
}


static void
check_map (const char *rel, pid_t pid, int type)
{
  FILE *file;
  char line[MAX_LINE + 1];
  int major, minor;
  ino_t inode;
  unsigned long long tmp_inode;

  if (!(file = fopen (rel, "r")))
    return;
  while (fgets (line, MAX_LINE, file))
    {
      if (sscanf (line, "%*s %*s %*s %x:%x %lld", &major, &minor, &tmp_inode) != 3)
	continue;
      if (major || minor || tmp_inode) {
        inode = (ino_t)(tmp_inode);
	    add_file (rel, MKDEV (major, minor), inode, pid, type);
      }
    }
  fclose (file);
}


static void
check_dir (const char *rel, pid_t pid, int type)
{
  DIR *dir;
  struct dirent *de;
  char *path;

  if (!(dir = opendir (rel)))
    return;
  while ((de = readdir (dir)) != NULL)
    if (strcmp (de->d_name, ".") && strcmp (de->d_name, ".."))
      {
	asprintf (&path, "%s/%s", rel, de->d_name);
	check_link (path, pid, type);
	free (path);
      }
  (void) closedir (dir);
}


static void
scan_fd (void)
{
  DIR *dir;
  struct dirent *de;
  char *path;
  pid_t pid;
  int empty;

  if (!(dir = opendir (PROC_BASE)))
    {
      perror (PROC_BASE);
      exit (1);
    }
  empty = 1;
  while ((de = readdir (dir)) != NULL)
    if ((pid = (pid_t)atoi (de->d_name)) != 0)
      {
	empty = 0;
	if (asprintf (&path, "%s/%d", PROC_BASE, pid) < 0)
	  continue;
	if (chdir (path) >= 0)
	  {
	    check_link ("root", pid, REF_ROOT);
	    check_link ("cwd", pid, REF_CWD);
	    check_link ("exe", pid, REF_EXE);
	    check_dir ("lib", pid, REF_MMAP);
	    check_dir ("mmap", pid, REF_MMAP);
	    check_map ("maps", pid, REF_MMAP);
	    check_dir ("fd", pid, REF_FILE);
	  }
	free (path);
      }
  (void) closedir (dir);
  if (empty)
    {
      fprintf (stderr, _("%s is empty (not mounted ?)\n"),PROC_BASE);
      exit (1);
    }
}


static void
scan_mounts (void)
{
  FILE *file;
  struct stat st_dev, st_parent, st_mounted;
  char line[MAX_LINE + 1], *path = NULL, *mounted = NULL;
  char *end;

  if (!(file = fopen (PROC_BASE "/mounts", "r")))
    return;			/* old kernel */
  while (fgets (line, MAX_LINE, file))
    {
      if (sscanf (line, "%as %as", &path, &mounted) != 2)
	continue;
      /* new kernel :-) */
      if (stat (path, &st_dev) < 0) {
	free (path);            /* might be NFS or such */
	free (mounted);
	continue;		
      }
      if (S_ISBLK (st_dev.st_mode) && MAJOR (st_dev.st_rdev) == LOOP_MAJOR)
	{
          struct loop_info loopinfo;
          int fd;

          if ((fd = open(path, O_RDWR)) > 0) {
            if (ioctl(fd, LOOP_GET_STATUS, &loopinfo) >= 0) {
              add_other(it_loop,loopinfo.lo_device,loopinfo.lo_device,loopinfo.lo_inode,path);
            }
            (void) close(fd);
                }
	}
      if (stat (mounted, &st_mounted) < 0)
	{
	  perror (mounted);
	  free (path);
	  free (mounted);
	  continue;
	}
      if (asprintf (&end, "%s/..", mounted) < 0)
	{
	  free (path);
	  free (mounted);
	  continue;
	}

      if (stat (end, &st_parent) >= 0)
	{
	  add_other (it_mount, st_parent.st_dev, st_mounted.st_dev,
		     st_mounted.st_ino, mounted);
	}
      free (end);
      free (path);
      free (mounted);
    }
  (void) fclose (file);
}


static void
scan_swaps (void)
{
  FILE *file;
  struct stat st;
  char line[MAX_LINE + 1], *path, type[MAX_LINE + 1];

  if (!(file = fopen (PROC_BASE "/swaps", "r")))
    return;			/* old kernel */
  (void) fgets (line, MAX_LINE, file);
  while (fgets (line, MAX_LINE, file))
    {
      if (sscanf (line, "%as %s", &path, type) != 2)
	continue;		/* new kernel :-) */
      if (strcmp (type, "file")) {
	free (path);
	continue;
      }
      if (stat (path, &st) >= 0)
	add_other (it_swap, st.st_dev, st.st_dev, st.st_ino, path);
      free (path);
    }
  (void) fclose (file);
}


static int
ask (pid_t pid)
{
  int res;
  size_t len;
  char *line;

  line = NULL;
  len = 0;

  fflush (stdout);
  do {
    fprintf (stderr, _("Kill process %d ? (y/N) "), pid);
    fflush (stderr);

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
  return 0;
}

static void
kill_item (const FILE_DSC * file, const ITEM_DSC * item)
{
  char tmp[10];

  switch (item->type)
    {
    case it_proc:
      if (item->u.proc.pid == self)
	return;
      if ((file->flags & FLAG_ASK) && !ask (item->u.proc.pid))
	return;
      if (kill (item->u.proc.pid, file->sig_num) >= 0)
	break;
      sprintf (tmp, _("kill %d"), item->u.proc.pid);
      perror (tmp);
      break;
    case it_mount:
      fprintf (stderr, _("No automatic removal. Please use  umount %s\n"),
	       item->u.misc.path);
      break;
    case it_loop:
      fprintf (stderr, _("No automatic removal. Please use  umount %s\n"),
	       item->u.misc.path);
      break;
    case it_swap:
      fprintf (stderr, _("No automatic removal. Please use  swapoff %s\n"),
	       file->name);
      break;
    }
}


static void
show_files_or_kill (void)
{
  const FILE_DSC *file;
  const ITEM_DSC *item;
  FILE *f;
  const struct passwd *pw;
  const char *user, *scan;
  char tmp[10], *path, comm[COMM_LEN + 1];
  int length, header, first, dummy, last_namelen = 0;
  header = 1;
  for (file = files; file; file = file->next)
    if (file->name && (file->items || all))
      {
	if (header && (file->flags & FLAG_VERB))
	  {
	    fprintf (stderr, _("\n%*s USER        PID ACCESS COMMAND\n"), NAME_FIELD, "");
	    header = 0;
	  }
	length = 0;
	for (scan = file->name; scan && *scan; scan++)
	  if (*scan == '\\')
	    length += fprintf (stderr, "\\\\");
	  else if (*scan > ' ' && *scan <= '~')
	    {
	      putc(*scan,stderr);
	      length++;
	    }
	  else
	    length += fprintf (stderr, "\\%03o", *scan);
	if (file->name_space)
	  length += fprintf (stderr, "/%s", file->name_space->name);

	if (length > 0)
	  last_namelen=length;
	else
	  fprintf(stderr, "\n%*.*s",last_namelen,last_namelen," ");

	if (!(file->flags & FLAG_VERB))
	  {
	    putc (':',stderr);
	    length++;
	  }

	first = 1;
	for (item = file->items; item; item = item->next)
	  {
	    if (!(file->flags & FLAG_VERB))
	      {
		if (item->type != it_proc)
		  continue;
        if ((first==1) && (item->u.proc.ref_set & (REF_FILE|REF_ROOT|REF_CWD|REF_EXE|REF_MMAP))) {
    while (length < NAME_FIELD)
    {
      putc(' ',stderr);
      length++;
    }
        }
		printf ("%6d", item->u.proc.pid);
        fflush(stdout);
		/* if (item->u.proc.ref_set & REF_FILE)*/
		if (item->u.proc.ref_set & REF_ROOT)
		  putc ('r', stderr);
		if (item->u.proc.ref_set & REF_CWD)
		  putc ('c', stderr);
		if (item->u.proc.ref_set & REF_EXE)
		  putc ('e', stderr);
		else if (item->u.proc.ref_set & REF_MMAP)
		  putc ('m', stderr);
		if ((file->flags & FLAG_UID) && item->u.proc.uid !=
		    UID_UNKNOWN)
                {
		  if ((pw = getpwuid (item->u.proc.uid)) != NULL) {
		    fprintf (stderr, "(%s)", pw->pw_name);
                  } else {
		    fprintf (stderr, "(%d)", item->u.proc.uid);
                  }
                }
		first = 0;
	      }
	    else
	      {
		const char *name;
		int uid;

		switch (item->type)
		  {
		  case it_proc:
		    asprintf (&path, PROC_BASE "/%d/stat", item->u.proc.pid);
		    strcpy (comm, "???");
		    if ((f = fopen (path, "r")) != NULL)
		      {
			(void) fscanf (f, "%d (%[^)]", &dummy, comm);
			(void) fclose (f);
		      }
		    free (path);
		    name = comm;
		    uid = item->u.proc.uid;
		    break;
		  case it_mount:
		  case it_loop:
		  case it_swap:
		    name = item->u.misc.path;
		    uid = 0;
		    break;
		  default:
		    fprintf (stderr, _("Internal error (type %d)\n"),
			     item->type);
		    exit (1);
		  }
		if (uid == UID_UNKNOWN)
		  user = "???";
		else if ((pw = getpwuid (uid)) != NULL)
		  user = pw->pw_name;
		else
		  {
		    sprintf (tmp, "%d", uid);
		    user = tmp;
		  }
		if (!first)
		  fprintf (stderr, "%*s", NAME_FIELD, "");
		else if (length > NAME_FIELD)
		  fprintf (stderr, "\n%*s", NAME_FIELD, "");
        else
          while (length < NAME_FIELD)
          {
            putc(' ', stderr);
            length++;
          }
		fprintf (stderr, " %-8s ", user);
		switch (item->type)
		  {
		  case it_proc:
		    printf ("%6d", item->u.proc.pid);
            fflush(stdout);
            fprintf (stderr, " %c%c%c%c%c  ",
			    item->u.proc.ref_set & REF_FILE ? 'f' : '.',
			    item->u.proc.ref_set & REF_ROOT ? 'r' : '.',
			    item->u.proc.ref_set & REF_CWD ? 'c' : '.',
			    item->u.proc.ref_set & REF_EXE ? 'e' : '.',
			    (item->u.proc.ref_set & REF_MMAP) &&
			    !(item->u.proc.ref_set & REF_EXE) ? 'm' : '.');
		    break;
		  case it_mount:
		    fprintf (stderr, _("kernel mount  "));
		    break;
		  case it_loop:
		    fprintf (stderr, _("kernel loop   "));
		    break;
		  case it_swap:
		    fprintf (stderr, _("kernel swap   "));
		    break;
		  }
		if (name)
                {
		  for (scan = name; *scan; scan++)
		    if (*scan == '\\')
		      fprintf (stderr, "\\\\");
		    else if (*scan > ' ' && *scan <= '~')
		      putc (*scan,stderr);
		    else
		      fprintf (stderr, "\\%03o", (unsigned char) *scan);
                }
		putc ('\n',stderr);
	      }
	    first = 0;
	  }
	if (!(file->flags & FLAG_VERB) || first)
	  putc('\n',stderr);
	if (file->flags & FLAG_KILL)
	  for (item = file->items; item; item = item->next)
	    kill_item (file, item);
      }
}


static void
kill_files (void)
{
  const FILE_DSC *file;
  const ITEM_DSC *item;

  for (file = files; file; file = file->next)
    if (file->flags & FLAG_KILL)
      for (item = file->items; item; item = item->next)
	kill_item (file, item);
}


static void
enter_item (const char *name, int flags, int sig_number, dev_t dev,
	    ino_t ino, SPACE_DSC * name_space)
{
  static FILE_DSC *last = NULL;
  FILE_DSC *new;

  if (!(new = malloc (sizeof (FILE_DSC))))
    {
      perror ("malloc");
      exit (1);
    }
  if (last_named && !strcmp (last_named->name, name) &&
      last_named->name_space == name_space)
    new->name = NULL;
  else if (!(new->name = strdup (name)))
    {
      perror ("strdup");
      exit (1);
    }
  new->flags = flags;
  new->sig_num = sig_number;
  new->items = NULL;
  new->next = NULL;
  new->dev = dev;
  new->ino = ino;
  new->name_space = name_space;
  if (last)
    last->next = new;
  else
    files = new;
  last = new;
  new->named = last_named;
  if (new->name)
    last_named = new;
}


static int
parse_inet (const char *spec, const char *name_space, int *lcl_port,
	    struct sockaddr_storage *rmt_addr, int *rmt_port)
{
  char *s, *here, *next, *end;
  int port, field, address_match;

  if (!(s = strdup (spec)))
    {
      perror ("strdup");
      exit (1);
    }
  *lcl_port = *rmt_port = -1;
  memset(rmt_addr, 0, sizeof(struct sockaddr_storage));
  field = 0;
  address_match = 0;
  for (here = s; here; here = next ? next + 1 : NULL)
    {
      next = strchr (here, ',');
      if (next)
	*next = 0;
      switch (field)
	{
	case 0:
	  /* fall through */
	case 2:
	  if (!*here)
	    break;
	  port = strtoul (here, &end, 0);
	  if (*end)
	    {
	      struct servent *se;

	      if (!(se = getservbyname (here, name_space)))
		return 0;
	      port = ntohs (se->s_port);
	    }
	  if (field)
	    *rmt_port = port;
	  else
	    *lcl_port = port;
	  break;
	case 1:
	  if (!*here)
	    break;
          if (!ipv4only) {

            if (inet_pton(AF_INET6, here, &((struct sockaddr_in6*)rmt_addr)->sin6_addr) > 0) {
              address_match = 1;
              rmt_addr->ss_family = AF_INET6;
             }
          }
          if (!ipv6only && !address_match) {
            if (inet_pton(AF_INET, here, &((struct sockaddr_in*)rmt_addr)->sin_addr) > 0) {
              address_match = 1;
              rmt_addr->ss_family = AF_INET6;
            }
          }
            
	  break;
	default:
	  return 0;
	}
      field++;
    }
  return 1;
}

static void find_net_dev(void)
{
  int fd = socket(PF_INET, SOCK_DGRAM,0);
  struct stat buf;
  if (fd >= 0 && fstat(fd, &buf) == 0) {
    net_dev = buf.st_dev;
    close(fd);
    return;
  }
  if (fd >= 0)
    close(fd);
  fprintf(stderr,_("can't find sockets' device number"));
}



static void
usage (void)
{
  fprintf (stderr, _(
    "usage: fuser [ -a | -s | -c ] [ -n space ] [ -signal ] [ -kimuv ] name ...\n"
    "             [ - ] [ -n space ] [ -signal ] [ -kimuv ] name ...\n"
    "       fuser -l\n"
    "       fuser -V\n\n"
    "    -a        display unused files too\n"
    "    -c        mounted FS\n"
    "    -f        silently ignored (for POSIX compatibility)\n"
    "    -k        kill processes accessing that file\n"
    "    -i        ask before killing (ignored without -k)\n"
    "    -l        list signal names\n"
    "    -m        mounted FS\n"
    "    -n space  search in the specified name space (file, udp, or tcp)\n"
    "    -s        silent operation\n"
    "    -signal   send signal instead of SIGKILL\n"
    "    -u        display user ids\n"
    "    -v        verbose output\n"
    "    -V        display version information\n"
    "    -4        search IPv4 sockets only\n"
    "    -6        search IPv6 sockets only\n"
    "    -         reset options\n\n"
    "  udp/tcp names: [local_port][,[rmt_host][,[rmt_port]]]\n\n"));
  exit (1);
}

void print_version()
{
  fprintf(stderr, _("fuser (psmisc) %s\n"), VERSION);
  fprintf(stderr, _(
    "Copyright (C) 1993-2002 Werner Almesberger and Craig Small\n\n"
    "PSmisc comes with ABSOLUTELY NO WARRANTY.\n"
    "This is free software, and you are welcome to redistribute it under the terms\n"
    "of the GNU General Public License.\n"
    "For more information about these matters, see the files named COPYING.\n"));
}



int
main (int argc, char **argv)
{
  SPACE_DSC *name_space;
  int flags, silent, do_kill, sig_number, no_files;

  flags = silent = do_kill = 0;
  sig_number = SIGKILL;
  name_space = name_spaces;
  no_files = 1;

  /* Setup the i18n */
#ifdef ENABLE_NLS
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  if (argc < 2)
    usage ();
  if (argc == 2 && !strcmp (argv[1], "-l"))
    {
      list_signals ();
      return 0;
    }
  find_net_dev();
  while (--argc)
    {
      argv++;
      if (**argv == '-')
	if (!argv[0][1])
	  {
	    flags = 0;
	    sig_number = SIGKILL;
	  }
	else
	  while (*++*argv)
	    {
	      int end;

	      end = 0;
	      switch (**argv)
		{
		case 'a':
		  all = 1;
		  break;
        case 'f':
          break;
		case 'k':
		  flags |= FLAG_KILL;
		  do_kill = 1;
		  break;
		case 'i':
		  flags |= FLAG_ASK;
		  break;
		case 'm':
		case 'c':
		  flags |= FLAG_DEV;
		  break;
		case 'n':
		  if (!--argc)
		    usage ();
		  argv++;
		  for (name_space = name_spaces; name_space->name;
		       name_space++)
		    if (!strcmp (*argv, name_space->name))
		      break;
		  if (!name_space->name)
		    usage ();
		  end = 1;
		  break;
		case 's':
		  silent = 1;
		  break;
		case 'u':
		  flags |= FLAG_UID;
		  break;
		case 'v':
		  flags |= FLAG_VERB;
		  break;
		case 'V':
		  print_version();
		  return 0;
                case '4':
                    if (ipv6only) 
                      usage();
                    ipv4only = 1;
                    break;
                case '6':
                    if (ipv4only)
                      usage();
                    ipv6only = 1;
                    break;
		default:
		  if (isupper (**argv) || isdigit (**argv))
		    {
		      sig_number = get_signal (*argv, "fuser");
		      argv[0][1] = 0;
		      break;
		    }
		  usage ();
		}
	      if (end)
		break;
	    }
      else
	{
	  SPACE_DSC *this_name_space;
	  struct stat st;
	  char *here;

	  no_files = 0;
	  last_named = NULL;
	  this_name_space = name_space;
	  if (name_space != name_spaces || stat (*argv, &st) < 0)
	    {
	      here = strchr (*argv, '/');
	      if (here && here != *argv)
		{
		  for (this_name_space = name_spaces; this_name_space->name;
		       this_name_space++)
		    if (!strcmp (here + 1, this_name_space->name))
		      {
			*here = 0;
			break;
		      }
		  if (!this_name_space->name)
		    this_name_space = name_spaces;
		}
	    }
	  if (this_name_space == name_spaces)
	    {
	      if (stat (*argv, &st) < 0)
		{
		  perror (*argv);
		  continue;
		}
	      if (flags & FLAG_DEV)
              {
		if (S_ISBLK (st.st_mode))
		  st.st_dev = st.st_rdev;
		else if (S_ISDIR (st.st_mode))
		  {
		    if (stat (*argv, &st) < 0)
		      {
			perror (*argv);
			continue;
		      }
		  }
              }
	      if (S_ISSOCK (st.st_mode) || (flags & FLAG_DEV))
		fill_unix_cache ();
	      if (!S_ISSOCK (st.st_mode) || (flags & FLAG_DEV))
		enter_item (*argv, flags, sig_number, st.st_dev, st.st_ino,
			    NULL);
	      else
		{
		  UNIX_CACHE *walk;

		  for (walk = unix_cache; walk; walk = walk->next)
		    if (walk->fs_dev == st.st_dev && walk->fs_ino ==
			st.st_ino)
		      enter_item (*argv, flags, sig_number, net_dev,
                        walk->net_ino, NULL);
		}
	    }
	  else
	    {
	      NET_CACHE *walk;
	      struct sockaddr_storage rmt_addr;
	      int lcl_port, rmt_port;

	      if (flags & FLAG_DEV)
		{
		  fprintf (stderr, _("ignoring -m in name space \"%s\"\n"),
			   this_name_space->name);
		  flags &= ~FLAG_DEV;
		}
	      fill_net_cache (this_name_space);
	      if (!parse_inet (*argv, this_name_space->name, &lcl_port,
			       &rmt_addr, &rmt_port))
		{
		  fprintf (stderr, _("%s/%s: invalid specification\n"), *argv,
			   this_name_space->name);
		  continue;
		}
	      for (walk = this_name_space->cache; walk; walk = walk->next)
		if ((lcl_port == -1 || walk->lcl_port == lcl_port) &&
		    (rmt_addr.ss_family == 0 || ( memcmp(
                     &((struct sockaddr_in6*)&walk->rmt_addr)->sin6_addr,
                     &((struct sockaddr_in6*)&rmt_addr)->sin6_addr,
                     sizeof(struct in6_addr)) == 0) ) &&
		    (rmt_port == -1 || walk->rmt_port == rmt_port))
		  enter_item (*argv, flags, sig_number, net_dev, walk->ino,
			      this_name_space);
	    }
	}
    }
  if (no_files || (all && silent))
    usage ();
  scan_fd ();
  scan_mounts ();
  scan_swaps ();
  if (do_kill && seteuid (getuid ()) < 0)
    {
      perror ("seteuid");
      return 1;
    }
  self = getpid ();
  if (silent)
    kill_files ();
  else
    show_files_or_kill ();
  return found_item ? 0 : 1;
}
