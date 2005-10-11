/*
 * fuser.c - identify processes using files
 *
 * Based on fuser.c Copyright (C) 1993-2005 Werner Almesberger and Craig Small
 *
 * Completely re-written
 * Copyright (C) 2005 Craig Small
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pwd.h>
#include <netdb.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>
#include <mntent.h>
#include <signal.h>
#include <getopt.h>

#include "fuser.h"
#include "signals.h"
#include "i18n.h"

#undef DEBUG

#define NAME_FIELD 20		/* space reserved for file name */
/* Function defines */
static void add_matched_proc(struct names *name_list, const pid_t pid, const uid_t uid, const char access);
static void check_dir(const pid_t pid, const char *dirname, struct device_list *dev_head, struct inode_list *ino_head, const uid_t uid, const char access);
static void check_map(const pid_t pid, const char *filename, struct device_list *dev_head, struct inode_list *ino_head, const uid_t uid, const char access);
static struct stat *get_pidstat(const pid_t pid, const char *filename);
static uid_t getpiduid(const pid_t pid);
static void print_matches(struct names *names_head, const opt_type opts, const int sig_number);
static void kill_matched_proc(struct procs *pptr, const opt_type opts, const int sig_number);

static dev_t get_netdev(void);
int parse_mount(struct names *this_name, struct device_list **dev_list);
static void add_device(struct device_list **dev_list, struct names  *this_name, dev_t device);
void scan_mount_devices(const opt_type opts, struct mountdev_list **mount_devices);
#ifdef DEBUG
static void debug_match_lists(struct names *names_head, struct inode_list *ino_head, struct device_list *dev_head);
#endif

static void usage (const char *errormsg)
{
	if (errormsg != NULL)
		fprintf(stderr, "%s\n", errormsg);

  fprintf (stderr, _(
    "Usage: fuser [ -a | -s | -c ] [ -n SPACE ] [ -SIGNAL ] [ -kimuv ] NAME...\n"
    "             [ - ] [ -n SPACE ] [ -SIGNAL ] [ -kimuv ] NAME...\n"
    "       fuser -l\n"
    "       fuser -V\n"
    "Show which processes use the named files, sockets, or filesystems.\n\n"
    "    -a        display unused files too\n"
    "    -c        mounted FS\n"
    "    -f        silently ignored (for POSIX compatibility)\n"
    "    -i        ask before killing (ignored without -k)\n"
    "    -k        kill processes accessing the named file\n"
    "    -l        list available signal names\n"
    "    -m        show all processes using the named filesystems\n"
    "    -n SPACE  search in this name space (file, udp, or tcp)\n"
    "    -s        silent operation\n"
    "    -SIGNAL   send this signal instead of SIGKILL\n"
    "    -u        display user IDs\n"
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
  fprintf(stderr, _("fuser (PSmisc) %s\n"), VERSION);
  fprintf(stderr, _(
    "Copyright (C) 1993-2005 Werner Almesberger and Craig Small\n\n"));
  fprintf(stderr, _(
    "PSmisc comes with ABSOLUTELY NO WARRANTY.\n"
    "This is free software, and you are welcome to redistribute it under\n"
    "the terms of the GNU General Public License.\n"
    "For more information about these matters, see the files named COPYING.\n"));
}

static void scan_procs(struct names *names_head, struct inode_list *ino_head, struct device_list *dev_head)
{
	DIR *topproc_dir;
	struct dirent *topproc_dent;
	char *fd_dirpath, *fd_pathname;
	struct inode_list *ino_tmp;
	struct device_list *dev_tmp;
	pid_t pid, my_pid;
	uid_t uid;
	struct stat *cwd_stat, *exe_stat, *root_stat;

	if ( (fd_dirpath = malloc(MAX_PATHNAME)) == NULL)
		return;
	if ( (fd_pathname = malloc(MAX_PATHNAME)) == NULL)
		return;

	if ( (topproc_dir = opendir("/proc")) == NULL) {
		fprintf(stderr, _("Cannot open /proc directory: %s\n"), strerror(errno));
		exit(1);
	}
	my_pid = getpid();
	while ( (topproc_dent = readdir(topproc_dir)) != NULL) {
		if (topproc_dent->d_name[0] < '0' || topproc_dent->d_name[0] > '9') /* Not a process */
			continue;
		pid = atoi(topproc_dent->d_name);
		/* Dont print myself */
		if (pid == my_pid)
			continue;
		uid = getpiduid(pid);

		root_stat = get_pidstat(pid, "root");
		cwd_stat = get_pidstat(pid, "cwd");
		exe_stat = get_pidstat(pid, "exe");
		/* Scan the devices */
		for (dev_tmp = dev_head ; dev_tmp != NULL ; dev_tmp = dev_tmp->next) {
			if (exe_stat != NULL && exe_stat->st_dev == dev_tmp->device) 
				add_matched_proc(dev_tmp->name, pid, uid, ACCESS_EXE);
			if (root_stat != NULL && root_stat->st_dev == dev_tmp->device) 
				add_matched_proc(dev_tmp->name, pid, uid, ACCESS_ROOT);
			if (cwd_stat != NULL && cwd_stat->st_dev == dev_tmp->device) 
				add_matched_proc(dev_tmp->name, pid, uid, ACCESS_CWD);
		}
		for (ino_tmp = ino_head ; ino_tmp != NULL ; ino_tmp = ino_tmp->next) {
			if (exe_stat != NULL) {
				if (exe_stat->st_dev == ino_tmp->device && exe_stat->st_ino == ino_tmp->inode) {
					add_matched_proc(ino_tmp->name, pid, uid, ACCESS_EXE);
				}
			}
			if (root_stat != NULL) {
				if (root_stat->st_dev == ino_tmp->device && root_stat->st_ino == ino_tmp->inode){
					add_matched_proc(ino_tmp->name, pid, uid, ACCESS_ROOT);
				}

			}
			if (cwd_stat != NULL){
				if (cwd_stat->st_dev == ino_tmp->device && cwd_stat->st_ino == ino_tmp->inode) {
					add_matched_proc(ino_tmp->name, pid, uid, ACCESS_CWD);
				}
			}
		}
		check_dir(pid, "lib", dev_head, ino_head, uid, ACCESS_MMAP);
		check_dir(pid, "mmap", dev_head, ino_head, uid, ACCESS_MMAP);
		check_dir(pid, "fd", dev_head, ino_head, uid, ACCESS_FILE);
		check_map(pid, "maps", dev_head, ino_head, uid, ACCESS_MMAP);

	} /* while topproc_dent */
	closedir(topproc_dir);
}
static void add_inode(struct inode_list **ino_list, struct names  *this_name, dev_t device, ino_t inode)
{
	struct inode_list *ino_tmp, *ino_head;

	ino_head = *ino_list;

	if ( (ino_tmp = malloc(sizeof(struct inode_list))) == NULL)
		return;
	ino_tmp->name = this_name;
	ino_tmp->device = device;
	ino_tmp->inode = inode;
	ino_tmp->next = ino_head;
	*ino_list = ino_tmp;
}

static void add_device(struct device_list **dev_list, struct names  *this_name, dev_t device)
{
	struct device_list *dev_tmp, *dev_head;

	/*printf("Adding device %s %d\n", this_name->filename, device);*/
	dev_head = *dev_list;

	if ( (dev_tmp = malloc(sizeof(struct device_list))) == NULL)
		return;
	dev_tmp->name = this_name;
	dev_tmp->device = device;
	dev_tmp->next = dev_head;
	*dev_list = dev_tmp;
}

static void add_ip_conn(struct ip_connections **ip_list, const char *protocol, struct names *this_name, const int lcl_port, const int rmt_port, unsigned long rmt_address)
{
	struct ip_connections *ip_tmp, *ip_head;

	ip_head = *ip_list;

	if ( (ip_tmp = malloc(sizeof(struct ip_connections))) == NULL)
		return;
	ip_tmp->name = this_name;
	ip_tmp->lcl_port = lcl_port;
	ip_tmp->rmt_port = rmt_port;
	ip_tmp->rmt_address.s_addr = rmt_address;
	ip_tmp->next = ip_head;

	*ip_list = ip_tmp;
}

static void add_ip6_conn(struct ip6_connections **ip_list, const char *protocol, struct names *this_name, const int lcl_port, const int rmt_port, struct in6_addr rmt_address)
{
	struct ip6_connections *ip_tmp, *ip_head;

	ip_head = *ip_list;

	if ( (ip_tmp = malloc(sizeof(struct ip6_connections))) == NULL)
		return;
	ip_tmp->name = this_name;
	ip_tmp->lcl_port = lcl_port;
	ip_tmp->rmt_port = rmt_port;
	memcpy(&(ip_tmp->rmt_port),&(rmt_port),sizeof(struct in6_addr));
	ip_tmp->next = ip_head;

	*ip_list = ip_tmp;
}

static void add_matched_proc(struct names *name_list, const pid_t pid, const uid_t uid, const char access)
{
	struct procs *pptr, *last_proc;
	char *pathname;
	char cmdname[101], *cptr;
	int cmdlen;
	FILE *fp;

	last_proc = NULL;
	for (pptr = name_list->matched_procs; pptr != NULL ; pptr = pptr->next)
	{
		last_proc = pptr;
		if (pptr->pid == pid) {
			pptr->access |= access;
			return;
		}
	}
	/* Not found */
	if ( (pptr = malloc(sizeof (struct procs))) == NULL) {
		fprintf(stderr,_("Cannot allocate memory for matched proc: %s\n"), strerror(errno));
		return;
	}
	pptr->pid = pid;
	pptr->uid = uid;
	pptr->access = access;
	pptr->next = NULL;
	/* set command name */
	pptr->command = NULL;
	if ( (asprintf(&pathname, "/proc/%d/stat", pid) > 0) &&
			( (fp = fopen(pathname, "r")) != NULL) &&
			( fscanf(fp, "%*d (%100[^)]", cmdname) == 1)) 
		if ( (pptr->command = malloc(MAX_CMDNAME+1)) != NULL) {
			cmdlen = 0;
			for (cptr = cmdname; cmdlen < MAX_CMDNAME && *cptr ; cptr++) {
				if (isprint(*cptr))
					pptr->command[cmdlen++] = *cptr;
				else if(cmdlen < (MAX_CMDNAME-4))
					cmdlen += sprintf(&(pptr->command[cmdlen]), "\\%03o", *cptr);
			}
			pptr->command[cmdlen] = '\0';
		}
	if (last_proc == NULL)
		name_list->matched_procs = pptr;
	else
		last_proc->next = pptr;
}

int parse_mount(struct names *this_name, struct device_list **dev_list)
{
	struct stat st;

	if (stat(this_name->filename, &st) != 0) {
		fprintf(stderr, _("Cannot stat mount point %s: %s\n"), 
				this_name->filename,
				strerror(errno));
		exit(1);
	}
	/*printf("Debug: parse_mount() adding %s\n", this_name->filename);*/
	add_device(dev_list, this_name, st.st_dev);
	return 0;
}

int parse_file(struct names *this_name, struct inode_list **ino_list)
{
	struct stat st;

	if (stat(this_name->filename, &st) != 0) {
		fprintf(stderr,_("Cannot stat %s: %s\n"), this_name->filename,
				strerror(errno));
		return -1;
	}
	/*printf("adding file %s %lX %lX\n", this_name->filename,
			(unsigned long)st.st_dev, (unsigned long)st.st_ino);*/
	add_inode(ino_list, this_name, st.st_dev, st.st_ino);
	return 0;
}

int parse_mounts(struct names *this_name, struct mountdev_list *mounts, struct device_list **dev_list, const char opts) 
{
	struct stat st;
	struct mountdev_list *mountptr;
	dev_t match_device;

	if (stat(this_name->filename, &st) != 0) {
		fprintf(stderr,_("Cannot stat %s: %s\n"), this_name->filename,
				strerror(errno));
		return -1;
	}
	if (S_ISBLK(st.st_mode))
		match_device = st.st_rdev;
	else
		match_device = st.st_dev;
	for (mountptr = mounts ; mountptr != NULL ; mountptr = mountptr->next) {
		if (mountptr->device == match_device) {
			/*printf("Debug: adding parse_mounts() adding %s\n", 
					this_name->filename);*/
			add_device(dev_list, this_name, match_device);
		}
	}
	return 0;
}

int parse_inet(struct names *this_name, const int ipv6_only, const int ipv4_only, struct ip_connections **ip_list, struct ip6_connections **ip6_list)
{
	struct addrinfo *res, *resptr;
	struct addrinfo hints;
	int errcode;
	char *lcl_port_str, *rmt_addr_str, *rmt_port_str, *tmpstr, *tmpstr2;
	in_port_t lcl_port;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	char hostspec[100];
	char *protocol;
	int i;
	
	if ( (protocol = strchr(this_name->filename, '/')) == NULL)
		return -1;
	protocol++;
	if (protocol[0] == '\0')
		return -1;
	for (i=0; i < 99 && this_name->filename[i] != '\0' && this_name->filename[i] != '/'; i++)
		hostspec[i] = this_name->filename[i];
	hostspec[i] = '\0';

	lcl_port_str = rmt_addr_str = rmt_port_str = NULL;
	/* Split out the names */
	if ( (tmpstr = strchr(hostspec, ',')) == NULL) {
		/* Single option */
		lcl_port_str = strdup(hostspec);
	} else {
		if (tmpstr == hostspec)
			lcl_port_str = NULL;
		else {
			lcl_port_str = strdup(hostspec);
			*tmpstr = '\0';
		}
		tmpstr++;
		if (*tmpstr != '\0') {
			if ( (tmpstr2 = strchr(tmpstr, ',')) == NULL) {
				/* Only 2 options */
				rmt_addr_str = tmpstr;
			} else {
				if (tmpstr2 == tmpstr)
					rmt_addr_str = NULL;
				else {
					rmt_addr_str = tmpstr;
					*tmpstr2 = '\0';
				}
				tmpstr2++;
				if (*tmpstr2 != '\0')
					rmt_port_str = tmpstr2;
			}
		}
	}
	/*printf("parsed to lp %s rh %s rp %s\n", lcl_port_str, rmt_addr_str, rmt_port_str);*/

	memset(&hints, 0, sizeof(hints));
	if (ipv6_only) {
		hints.ai_family = PF_INET6;
	} else if (ipv4_only) {
			hints.ai_family = PF_INET;
		} else 
			hints.ai_family = PF_UNSPEC;
	if (strcmp(protocol, "tcp") == 0)
		hints.ai_socktype = SOCK_STREAM;
	else
		hints.ai_socktype = SOCK_DGRAM;

	if (lcl_port_str == NULL) {
		lcl_port = 0;
	} else {
		/* Resolve local port first */
		if ( (errcode = getaddrinfo(NULL, lcl_port_str, &hints, &res)) != 0) {
			fprintf(stderr, _("Cannot resolve local port %s: %s\n"),
					lcl_port_str, gai_strerror(errcode));
			return -1;
		}
		if (res == NULL)
			return -1;
		switch(res->ai_family) {
			case AF_INET:
				lcl_port = ((struct sockaddr_in*)(res->ai_addr))->sin_port;
				break;
			case AF_INET6:
				lcl_port = ((struct sockaddr_in6*)(res->ai_addr))->sin6_port;
				break;
			default:
				fprintf(stderr, _("Unknown local port AF %d\n"), res->ai_family);
				freeaddrinfo(res);
				return -1;
		}
		freeaddrinfo(res);
	}
	free(lcl_port_str);
	res = NULL;
	if (rmt_addr_str == NULL && rmt_port_str == NULL) {
		add_ip_conn(ip_list, protocol, this_name, ntohs(lcl_port), 0, INADDR_ANY);
		add_ip6_conn(ip6_list, protocol,this_name, ntohs(lcl_port), 0, in6addr_any);
		return 0;
	} else {
		/* Resolve remote address and port */
		if (getaddrinfo(rmt_addr_str, rmt_port_str, &hints, &res) == 0) {
			for(resptr = res ; resptr != NULL ; resptr = resptr->ai_next ) {
				switch(resptr->ai_family) {
					case AF_INET:
						sin = (struct sockaddr_in*)resptr->ai_addr;
						add_ip_conn(ip_list, protocol, this_name, ntohs(lcl_port), ntohs(sin->sin_port), sin->sin_addr.s_addr);
					break;
				case AF_INET6:
					sin6 = (struct sockaddr_in6*)resptr->ai_addr;
						add_ip6_conn(ip6_list, protocol, this_name, ntohs(lcl_port), ntohs(sin6->sin6_port), sin6->sin6_addr);
					break;
				}
			} /*while */
			return 0;
		}
	}
	return 1;
}




void find_net_sockets(struct inode_list **ino_list, struct ip_connections *conn_list, const char *protocol, dev_t netdev)
{
	FILE *fp;
	char pathname[200], line[BUFSIZ];
	unsigned long loc_port, rmt_port;
	unsigned long rmt_addr, scanned_inode;
	ino_t inode;
	struct ip_connections *conn_tmp;

	if (snprintf(pathname,200, "/proc/net/%s", protocol) < 0) 
		return ;

	if ( (fp = fopen(pathname, "r")) == NULL) {
		fprintf(stderr, _("Cannot open protocol file: %s"), strerror(errno));
		return;
	}
	while (fgets(line, BUFSIZ, fp) != NULL) {
		if (sscanf(line, "%*u: %*x:%lx %08lx:%lx %*x %*x:%*x %*x:%*x %*x %*d %*d %lu",
			&loc_port,
			&rmt_addr,
			&rmt_port,
			&scanned_inode) != 4)
			continue;
		/*printf("Found *:%lu with %s:%lu\n", loc_port, inet_ntoa(*((struct in_addr*)&rmt_addr)), rmt_port);*/
		inode = scanned_inode;
		for(conn_tmp = conn_list ; conn_tmp != NULL ; conn_tmp = conn_tmp->next) {
			/*printf("Comparing with *.%lu %s:%lu ...", 
					conn_tmp->lcl_port,
					inet_ntoa(conn_tmp->rmt_address),
					conn_tmp->rmt_port);*/
			if (conn_tmp->lcl_port == loc_port &&
					conn_tmp->rmt_port == rmt_port &&
					(memcmp(&(conn_tmp->rmt_address), &(rmt_addr),4) ==0)
			   ) {
				/* add inode to list */
				add_inode(ino_list, conn_tmp->name, netdev, inode);
			}
		}
			

	}
	return ;
}

void find_net6_sockets(struct inode_list **ino_list, struct ip6_connections *conn_list, const char *protocol, const dev_t netdev)
{
	FILE *fp;
	char pathname[200], line[BUFSIZ];
	unsigned long loc_port, rmt_port;
	struct in6_addr rmt_addr;
	unsigned int tmp_addr[4];
	char rmt_addr6str[INET6_ADDRSTRLEN];
	struct ip6_connections *head, *tmpptr, *tail;
	struct ip6_connections *conn_tmp;
	unsigned long scanned_inode;
	ino_t inode;

	head = tmpptr = tail = NULL;

	if (snprintf(pathname,200, "/proc/net/%s6", protocol) < 0) 
		return ;

	if ( (fp = fopen(pathname, "r")) == NULL) {
		fprintf(stderr, _("Cannot open protocol file: %s"), strerror(errno));
		return ;
	}
	while (fgets(line, BUFSIZ, fp) != NULL) {
		if (sscanf(line, "%*u: %*x:%lx %08x%08x%08x%08x:%lx %*x %*x:%*x %*x:%*x %*x %*d %*d %lu",
			&loc_port, 
			&(tmp_addr[0]),
			&(tmp_addr[1]),
			&(tmp_addr[2]),
			&(tmp_addr[3]),
			&rmt_port, &scanned_inode) != 7)
			continue;
		inode = scanned_inode;
		rmt_addr.s6_addr32[0] = tmp_addr[0];
		rmt_addr.s6_addr32[1] = tmp_addr[1];
		rmt_addr.s6_addr32[2] = tmp_addr[2];
		rmt_addr.s6_addr32[3] = tmp_addr[3];
		inet_ntop(AF_INET6, &rmt_addr, rmt_addr6str, INET6_ADDRSTRLEN);
		/*printf("Found %ld with %s:%ld\n", loc_port, rmt_addr6str, rmt_port);*/
		for(conn_tmp = conn_list ; conn_tmp != NULL ; conn_tmp = conn_tmp->next) {
			inet_ntop(AF_INET6, &conn_tmp->rmt_address, rmt_addr6str, INET6_ADDRSTRLEN);
		/*	printf("Comparing with *.%lu %s:%lu ...", 
					conn_tmp->lcl_port,
					rmt_addr6str,
					conn_tmp->rmt_port);*/
			if (conn_tmp->lcl_port == loc_port &&
					conn_tmp->rmt_port == rmt_port &&
					(memcmp(&(conn_tmp->rmt_address), &(rmt_addr),16) ==0)
			   ) {
				add_inode(ino_list, conn_tmp->name, netdev, inode);
			}
		}
	}
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"all", 0, 0, 'a'},
		{"mountpoint", 0, 0, 'c'},
		{"help", 0, 0, 'h'},
		{"interactive", 0, 0, 'i'},
		{"kill", 0, 0, 'k'},
		{"list", 0, 0, 'l'},
		{"mounted", 0, 0, 'm'},
		{"name-space", 1, 0, 'n'},
		{"silent", 0, 0, 's'},
		{"show-user", 0, 0, 'u'},
		{"verbose", 0, 0, 'v'},
		{"version", 0, 0, 'V'},
		{0, 0, 0, 0}
	};
	opt_type opts; 
	struct option *opt_ptr;
	int sig_number;
	int ipv4_only, ipv6_only;
	unsigned char default_namespace = NAMESPACE_FILE;
	struct mountdev_list *mount_devices = NULL;
	struct device_list *match_devices = NULL;

	dev_t netdev;
	struct ip_connections *tcp_connection_list = NULL;
	struct ip_connections *udp_connection_list = NULL;
	struct ip6_connections *tcp6_connection_list = NULL;
	struct ip6_connections *udp6_connection_list = NULL;
	struct inode_list *match_inodes = NULL;
	struct names *names_head, *this_name, *names_tail;
	int optc, option;
	char *nsptr;

	ipv4_only = ipv6_only = 0;
	names_head = this_name = names_tail = NULL;
	opts = 0;
	sig_number = SIGKILL;

	netdev = get_netdev();
	scan_mount_devices(opts, &mount_devices);

	/* getopt doesnt like things like -SIGBLAH */
	for(optc = 1; optc < argc; optc++) {
		if (argv[optc][0] == '-') { /* its an option */
			option=argv[optc][1];
			if (argv[optc][1] == '-') { /* its a long option */
				if (argv[optc][2] == '\0') {
					continue;
				}
				/* FIXME longopts */
				continue;
			}
			switch(argv[optc][1]) {
				case '4':
					ipv4_only = 1;
					break;
				case '6':
					ipv6_only = 1;
					break;
				case 'a':
					opts |= OPT_ALLFILES;
					break;
				case 'c':
					opts |= OPT_MOUNTPOINT;
					break;
				case 'f':
					/* ignored */
					break;
				case 'h':
					usage(NULL);
					break;
				case 'i':
					opts |= OPT_INTERACTIVE;
					break;
				case 'k':
					opts |= OPT_KILL;
					break;
				case 'l':
					list_signals();
					break;
				case 'm':
					opts |= OPT_MOUNTS;
					break;
				case 'n':
					optc++;
					if (optc >= argc) {
						usage(_("Namespace option requires an argument."));
					}
					if (strcmp(argv[optc], "tcp") == 0)
						default_namespace = NAMESPACE_TCP;
					else if (strcmp(argv[optc], "udp") == 0)
						default_namespace = NAMESPACE_UDP;
					else if (strcmp(argv[optc], "file") == 0)
						default_namespace = NAMESPACE_FILE;
					else 
						usage(_("Invalid namespace name"));
					break;
				case 's':
					opts |= OPT_SILENT;
					break;
				case 'u':
					opts |= OPT_USER;
					break;
				case 'v':
					opts |= OPT_VERBOSE;
					break;
				case 'V':
					print_version();
					return 0;
				default:
					if ( isupper(argv[optc][1]) || isdigit(argv[optc][1])) {
						sig_number = get_signal(argv[optc]+1,"fuser");
						break;
					}
					fprintf(stderr,"%s: Invalid option %c\n",argv[0] , argv[optc][1]);

					usage(NULL);
					break;
			} /* switch */
			continue;
		}
		/* File specifications */
		if ( (this_name = malloc(sizeof(struct names))) == NULL)
			continue;
		this_name->next = NULL;
		if (names_head == NULL)
			names_head = this_name;
		if (names_tail != NULL)
			names_tail->next = this_name;
		names_tail = this_name;
		/* try to find namespace spec */
		this_name->name_space = default_namespace;
		if ( ((nsptr = strchr(argv[optc], '/')) != NULL )
			&& ( nsptr != argv[optc] )) {
			if (strcmp(nsptr+1, "tcp") == 0) {
				this_name->name_space = NAMESPACE_TCP;
				*nsptr = '\0';
			} else if (strcmp(nsptr+1, "udp") == 0) {
				this_name->name_space = NAMESPACE_UDP;
				*nsptr = '\0';
			} else if (strcmp(nsptr+1, "file") == 0) {
				this_name->name_space = NAMESPACE_FILE;
				*nsptr = '\0';
			}
		}
		this_name->matched_procs = NULL;
		if ((opts & OPT_MOUNTS || opts & OPT_MOUNTPOINT) && this_name->name_space != NAMESPACE_FILE)
			usage(_("You can only use files with mountpoint option"));
		switch(this_name->name_space) {
			case NAMESPACE_TCP:
				asprintf(&(this_name->filename), "%s/tcp", argv[optc]);
				parse_inet(this_name, ipv4_only, ipv6_only, &tcp_connection_list, &tcp6_connection_list);
				break;
			case NAMESPACE_UDP:
				asprintf(&(this_name->filename), "%s/udp", argv[optc]);
				parse_inet(this_name, ipv4_only, ipv6_only, &tcp_connection_list, &tcp6_connection_list);
				break;
			default: /* FILE */
				this_name->filename = strdup(argv[optc]);
					parse_file(this_name, &match_inodes);
				if (opts & OPT_MOUNTPOINT || opts & OPT_MOUNTS)
					parse_mounts(this_name, mount_devices, &match_devices, opts);
				break;
		}

	} /* for optc */
	if (names_head == NULL) {
		usage(_("No process specification given"));
	}
	/* Check conflicting operations */
	if (opts & OPT_MOUNTPOINT) {
		if (opts & OPT_MOUNTS)
			usage(_("You cannot use the mounted and mountpoint flags together"));
	}
	if (opts & OPT_SILENT) 
	{
		opts &= ~OPT_VERBOSE;
		opts &= ~OPT_USER;
		if (opts & OPT_ALLFILES)
			usage(_("all option cannot be used with silent option."));
	}
	if (ipv4_only && ipv6_only)
		usage(_("You cannot search for only IPv4 and only IPv6 sockets at the same time"));
	if (!ipv4_only) {
		if (tcp_connection_list != NULL)
			find_net_sockets(&match_inodes, tcp_connection_list, "tcp",netdev);
		if (udp_connection_list != NULL)
			find_net_sockets(&match_inodes, udp_connection_list, "udp",netdev);
	}
	if (!ipv6_only) {
		if (tcp6_connection_list != NULL)
			find_net6_sockets(&match_inodes, tcp6_connection_list, "tcp",netdev);
		if (udp6_connection_list != NULL)
			find_net6_sockets(&match_inodes,  udp6_connection_list, "udp",netdev);
	}
#ifdef DEBUG
	debug_match_lists(names_head, match_inodes, match_devices);
#endif
	scan_procs(names_head, match_inodes, match_devices);
	print_matches(names_head,opts, sig_number);
	return 0;
}

static void print_matches(struct names *names_head, const opt_type opts, const int sig_number)
{
	struct names *nptr;
	struct procs *pptr;
	char first;
	int len;
	struct passwd *pwent = NULL;
	
	if (opts & OPT_VERBOSE)
		fprintf(stderr, _("\n%*s USER        PID ACCESS COMMAND\n"),
				NAME_FIELD, "");
	for (nptr = names_head; nptr != NULL ; nptr = nptr->next) {
		fprintf(stderr, "%s", nptr->filename);
		first = 1;
		len = strlen(nptr->filename);
		if (!(opts & OPT_VERBOSE)) {
			putc(':', stderr);
			len++;
		}
		for (pptr = nptr->matched_procs; pptr != NULL ; pptr = pptr->next) {
			if (opts & (OPT_VERBOSE|OPT_USER)) {
				if (pwent == NULL || pwent->pw_uid != pptr->uid)
					pwent = getpwuid(pptr->uid);
			}
			if (len > NAME_FIELD && (opts & OPT_VERBOSE)) {
				putc('\n', stderr);
				len=0;
			}
			if ((opts & OPT_VERBOSE) || first) 
				while (len++ < NAME_FIELD)
					putc(' ', stderr);
			if (opts & OPT_VERBOSE) {
				if (pwent == NULL)
					fprintf(stderr, " %-8s ", _("(unknown)"));
				else
					fprintf(stderr, " %-8s ", pwent->pw_name);
			}
			printf("%6d", pptr->pid);
			fflush(stdout);
			if (opts & OPT_VERBOSE) {
				fprintf(stderr, " %c%c%c%c%c ",
						pptr->access & ACCESS_FILE ? (pptr->access & ACCESS_FILEWR ? 'F' : 'f' ) : '.',
						pptr->access & ACCESS_ROOT ? 'r' : '.',
						pptr->access & ACCESS_CWD ? 'c' : '.',
						pptr->access & ACCESS_EXE ? 'e' : '.',
						(pptr->access & ACCESS_MMAP) && !(pptr->access & ACCESS_EXE) ? 'm' : '.');
			} else {
				if (pptr->access & ACCESS_ROOT)
					putc('r', stderr);
				if (pptr->access & ACCESS_CWD)
					putc('c', stderr);
				if (pptr->access & ACCESS_EXE)
					putc('e', stderr);
				else if (pptr->access & ACCESS_MMAP)
					putc('m', stderr);
			}
			if (opts & OPT_USER) {
				if (pwent == NULL)
					fprintf(stderr, " %-8s ", _("(unknown)"));
				else
					fprintf(stderr, "(%s)", pwent->pw_name);
			}
			if (opts & OPT_VERBOSE) {
				if (pptr->command == NULL)
					fprintf(stderr, "???\n");
				else 
					fprintf(stderr, "%s\n", pptr->command);
			}
			len = 0;
			first = 0;
		}
		if (nptr->matched_procs == NULL || !(opts & OPT_VERBOSE))
			putc('\n', stderr);
		if (opts & OPT_KILL)
			kill_matched_proc(nptr->matched_procs,  opts, sig_number);

	} /* next name */

}

static struct stat *get_pidstat(const pid_t pid, const char *filename)
{
	char pathname[256];
	struct stat *st;

	if ( (st = malloc(sizeof(struct stat))) == NULL)
		return NULL;
	snprintf(pathname, 256, "/proc/%d/%s", pid, filename);
	if (stat(pathname, st) != 0) 
		return NULL;
	else
		return st;
}

static void check_dir(const pid_t pid, const char *dirname, struct device_list *dev_head, struct inode_list *ino_head, const uid_t uid, const char access)
{
	char *dirpath, *filepath;
	DIR *dirp;
	struct dirent *direntry;
	struct inode_list *ino_tmp;
	struct device_list *dev_tmp;
	struct stat st, lst;

	if ( (dirpath = malloc(MAX_PATHNAME)) == NULL)
		return;
	if ( (filepath = malloc(MAX_PATHNAME)) == NULL)
		return;

	snprintf(dirpath, MAX_PATHNAME, "/proc/%d/%s", pid, dirname);
	if ( (dirp = opendir(dirpath)) == NULL)
		return;
	while ( (direntry = readdir(dirp)) != NULL) {
		if (direntry->d_name[0] < '0' || direntry->d_name[0] > '9')
			continue;

		snprintf(filepath, MAX_PATHNAME, "/proc/%d/%s/%s",
			pid, dirname, direntry->d_name);
		if (stat(filepath, &st) != 0) {
			fprintf(stderr, _("Cannot stat file %s: %s\n"),filepath, strerror(errno));
		} else {
			for (dev_tmp = dev_head ; dev_tmp != NULL ; dev_tmp = dev_tmp->next) {
				if (st.st_dev == dev_tmp->device) {
					if (access == ACCESS_FILE && (lstat(filepath, &lst)==0) && (lst.st_mode & S_IWUSR)) {
						add_matched_proc(dev_tmp->name, pid,uid, ACCESS_FILEWR|access);
					} else  {
						add_matched_proc(dev_tmp->name, pid,uid, access);
					}
				}
			}
			for (ino_tmp = ino_head ; ino_tmp != NULL ; ino_tmp = ino_tmp->next) {
				if (st.st_dev == ino_tmp->device && st.st_ino == ino_tmp->inode) {
					if (access == ACCESS_FILE && (lstat(filepath, &lst)==0) && (lst.st_mode & S_IWUSR)) {
						add_matched_proc(ino_tmp->name, pid,uid, ACCESS_FILEWR|access);
					} else {
						add_matched_proc(ino_tmp->name, pid,uid, access);
					}
				}
			}
		}
	} /* while fd_dent */
	closedir(dirp);
}

static void check_map(const pid_t pid, const char *filename, struct device_list *dev_head, struct inode_list *ino_head, const uid_t uid, const char access)
{
	char pathname[MAX_PATHNAME];
	char line[BUFSIZ];
	struct inode_list *ino_tmp;
	struct device_list *dev_tmp;
	FILE *fp;
	unsigned long long tmp_inode;
	unsigned int tmp_maj, tmp_min;
	dev_t tmp_device;

	snprintf(pathname, MAX_PATHNAME, "/proc/%d/%s", pid, filename);
	if ( (fp = fopen(pathname, "r")) == NULL)
		return;
	while (fgets(line,BUFSIZ, fp)) {
		if (sscanf(line, "%*s %*s %*s %x:%x %lld", 
					&tmp_maj, &tmp_min, &tmp_inode) == 3) {
			tmp_device = tmp_maj * 256 + tmp_min;
			for(dev_tmp = dev_head ; dev_tmp != NULL ; dev_tmp = dev_tmp->next)
				if (dev_tmp->device == tmp_device)
					add_matched_proc(dev_tmp->name, pid, uid, access);
			for(ino_tmp = ino_head ; ino_tmp != NULL ; ino_tmp = ino_tmp->next)
				if (ino_tmp->device == tmp_device && ino_tmp->inode == tmp_inode)
					add_matched_proc(ino_tmp->name, pid, uid, access);
		}
	}
	fclose(fp);
}

static uid_t getpiduid(const pid_t pid)
{
	char pathname[MAX_PATHNAME];
	struct stat st;

	if (snprintf(pathname, MAX_PATHNAME, "/proc/%d", pid) < 0) 
		return 0;
	if (stat(pathname, &st) != 0)
		return 0;
	return st.st_uid;
}

void add_mount_device(struct mountdev_list **mount_head,const char *fsname, const char *dir, dev_t device)
{
	struct mountdev_list *newmount;
	/*printf("Adding mount Path: %s Dir:%s dev:%0x\n",dir, fsname, device);*/

	if ( (newmount = malloc(sizeof(struct mountdev_list))) == NULL)
		return;
	newmount->fsname = strdup(fsname);
	newmount->dir = strdup(dir);
	newmount->device = device;
	newmount->next = *mount_head;
	*mount_head = newmount;
}

/*
 * scan_mount_devices : Create a list of mount points and devices
 *   This list is used later for matching purposes
 */
void scan_mount_devices(const opt_type opts, struct mountdev_list **mount_devices)
{
	FILE *mntfp;
	struct mntent *mnt_ptr;
	struct stat st;
	
	if ( (mntfp = setmntent("/etc/mtab","r")) == NULL) {
		fprintf(stderr, _("Cannot open /etc/mtab: %s\n"),
				strerror(errno));
		return;
	}
	while ( (mnt_ptr = getmntent(mntfp)) != NULL) {
		if (stat(mnt_ptr->mnt_dir, &st) == 0) {
			add_mount_device(mount_devices, mnt_ptr->mnt_fsname, mnt_ptr->mnt_dir, st.st_dev);
		}
	}
}

static dev_t get_netdev(void)
{
	int skt;
	struct stat st;

	if ( (skt = socket(PF_INET,SOCK_DGRAM,0)) < 0)
		return -1;
	if ( fstat(skt, &st) != 0) 
		return -1;
	return st.st_dev;
}

#ifdef DEBUG
/* often not used, doesnt need translation */
static void debug_match_lists(struct names *names_head, struct inode_list *ino_head, struct device_list *dev_head)
{
	struct names *nptr;
	struct inode_list *iptr;
	struct device_list *dptr;

	fprintf(stderr,"Names:\n");
	for (nptr=names_head; nptr!= NULL; nptr=nptr->next) 
	{
		fprintf(stderr, "\t%s %c\n", nptr->filename, nptr->name_space);
	}
	fprintf(stderr,"\nInodes:\n");
	for (iptr=ino_head; iptr!=NULL; iptr=iptr->next)
	{
		fprintf(stderr, "\tDev:%0lx Inode:%0lx\n",
				(unsigned long)iptr->device, (unsigned long)iptr->inode);
	}
	fprintf(stderr,"\nDevices:\n");
	for (dptr=dev_head; dptr!=NULL; dptr=dptr->next)
	{
		fprintf(stderr, "\tDev:%0lx\n",
				(unsigned long)dptr->device);
	}
}

#endif

/* 0 = no, 1=yes */
static int ask(const pid_t pid)
{
	int res;
	size_t len = 0;
	char *line = NULL;

	fflush(stdout);
	while(1) {
		fprintf(stderr, _("Kill process %d ? (y/N) "), pid);
		fflush(stderr);
		if (getline(&line, &len, stdin) < 0)
			return 0;
		if (line[0] == '\n') {
			free(line);
			return 0;
		}
		res = rpmatch(line);
		if (res >= 0) {
			free(line);
			return res;
		}
	} /* while */
}

static void kill_matched_proc(struct procs *proc_head, const opt_type opts, const int sig_number)
{
	struct procs *pptr;

	for (pptr = proc_head ; pptr != NULL ; pptr = pptr->next ) {
		if ( (opts & OPT_INTERACTIVE) && (ask(pptr->pid) == 0))
			continue;
		kill (pptr->pid, sig_number);
	}
}
