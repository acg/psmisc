/*
 * peekfd.c - Intercept file descriptor read and writes
 *
 * Copyright (C) 2007 Trent Waddington <trent.waddington@gmail.com>
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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/user.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>

#include "i18n.h"

#define MAX_ATTACHED_PIDS 1024
int num_attached_pids = 0;
pid_t attached_pids[MAX_ATTACHED_PIDS];

void detach(void) {
	int i;
	for (i = 0; i < num_attached_pids; i++)	
		ptrace(PTRACE_DETACH, attached_pids[i], 0, 0);
}

void attach(pid_t pid) {
	attached_pids[0] = pid;
	if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
		fprintf(stderr, _("Error attaching to pid %i\n"), pid);
		return;
	}
	num_attached_pids++;
}

void print_version()
{
  fprintf(stderr, _("peekfd (PSmisc) %s\n"), VERSION);
  fprintf(stderr, _(
    "Copyright (C) 2007 Trent Waddington\n\n"));
  fprintf(stderr, _(
    "PSmisc comes with ABSOLUTELY NO WARRANTY.\n"
    "This is free software, and you are welcome to redistribute it under\n"
    "the terms of the GNU General Public License.\n"
    "For more information about these matters, see the files named COPYING.\n"));
}

void usage() {
	fprintf(stderr, _(
      "Usage: peekfd [-8] [-n] [-c] [-d] [-V] [-h] <pid> [<fd> ..]\n"
	  "    -8 output 8 bit clean streams.\n"
	  "    -n don't display read/write from fd headers.\n"
	  "    -c peek at any new child processes too.\n"
	  "    -d remove duplicate read/writes from the output.\n"
	  "    -V prints version info.\n"
	  "    -h prints this help.\n"
	  "\n"
	  "  Press CTRL-C to end output.\n"));
}

int bufdiff(int pid, unsigned char *lastbuf, unsigned int addr, unsigned int len) {
	int i;
	for (i = 0; i < len; i++)
		if (lastbuf[i] != (ptrace(PTRACE_PEEKTEXT, pid, addr + i, 0) & 0xff))
			return 1;
	return 0;
}

int main(int argc, char **argv)
{
	int eight_bit_clean = 0;
	int no_headers = 0;
	int follow_forks = 0;
	int remove_duplicates = 0;
	int optc;
    int target_pid = 0;
    int numfds = 0;
    int *fds = NULL;
    int i;

    struct option options[] = {
      {"eight-bit-clean", 0, NULL, '8'},
      {"no-headers", 0, NULL, 'n'},
      {"follow", 0, NULL, 'f'},
      {"duplicates-removed", 0, NULL, 'd'},
      {"help", 0, NULL, 'h'},
      {"version", 0, NULL, 'V'},
    };

  /* Setup the i18n */
#ifdef ENABLE_NLS
    setlocale(LC_ALL, "");
    bindtextdomain(PACKAGE, LOCALEDIR);
    textdomain(PACKAGE);
#endif

	if (argc < 2) {
		usage();
		return 1;
	}

	while ((optc = getopt_long(argc, argv, "8ncdhV",options, NULL)) != -1) {
		switch(optc) {
			case '8':
				eight_bit_clean = 1;
				break;
			case 'n':
				no_headers = 1;
				break;
			case 'c':
				follow_forks = 1;
				break;
			case 'd':
				remove_duplicates = 1;
				break;
			case 'V':
				print_version();
				return 1;
			case 'h':
			case '?':
				usage();
				return 1;
		}
	}
    /* First arg off the options is the PID to see */
    if (optind >= argc) {
      usage();
      return -1;
    }
    target_pid = atoi(argv[optind++]);

    if (optind < argc) {
      numfds = argc - optind;
      fds = malloc(sizeof(int) * numfds);
	  for (i = 0; i < numfds; i++)
		fds[i] = atoi(argv[optind + 1 + i]);
    }

	attach(target_pid);
	if (num_attached_pids == 0)
		return 1;

	atexit(detach);

	ptrace(PTRACE_SYSCALL, attached_pids[0], 0, 0);

	/*int count = 0;*/
	int lastfd = numfds > 0 ? fds[0] : 0;
	int lastdir = 3;
	unsigned char *lastbuf = NULL;
	int last_buf_size=-1;

	for(;;) {
		int status;
		int pid = wait(&status);
		if (WIFSTOPPED(status)) {
			struct user_regs_struct regs;
			ptrace(PTRACE_GETREGS, pid, 0, &regs);
		
			/*unsigned int b = ptrace(PTRACE_PEEKTEXT, pid, regs.eip, 0);*/
	
			if (follow_forks && (regs.orig_eax == 2 || regs.orig_eax == 120)) {
				if (regs.eax > 0)
					attach(regs.eax);					
			}
			if ((regs.orig_eax == 3 || regs.orig_eax == 4) && (regs.edx == regs.eax)) {
				for (i = 0; i < numfds; i++)
					if (fds[i] == regs.ebx)
						break;
				if (i != numfds || numfds == 0) {
					if (regs.ebx != lastfd || regs.orig_eax != lastdir) {
						lastfd = regs.ebx;
						lastdir = regs.orig_eax;
						if (!no_headers)
							printf("\n%sing fd %i:\n", regs.orig_eax == 3 ? "read" : "writ", lastfd);
					}
					if (!remove_duplicates || lastbuf == NULL
							||  last_buf_size != regs.edx || 
							bufdiff(pid, lastbuf, regs.ecx, regs.edx)) {

						if (remove_duplicates) {
							if (lastbuf)
								free(lastbuf);
							lastbuf = malloc(regs.edx);
							last_buf_size = regs.edx;
						}

						for (i = 0; i < regs.edx; i++) {
							unsigned int a = ptrace(PTRACE_PEEKTEXT, pid, regs.ecx + i, 0);
							if (remove_duplicates)
								lastbuf[i] = a & 0xff;

							if (eight_bit_clean)
								putchar(a & 0xff);
							else {
								if (isprint(a & 0xff) || (a & 0xff) == '\n')
									printf("%c", a & 0xff);
								else if ((a & 0xff) == 0x0d)
									printf("\n");
								else if ((a & 0xff) == 0x7f)
									printf("\b");
								else if (a & 0xff)
									printf(" [%02x] ", a & 0xff);
							}
						}
					}
					fflush(stdout);
				}
			}

			ptrace(PTRACE_SYSCALL, pid, 0, 0);
		}
	}

	return 0;
}
