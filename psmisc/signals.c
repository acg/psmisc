/* signals.c - signal name handling */

/* Copyright 1993-1995 Werner Almesberger. See file COPYING for details. */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "signals.h"


typedef struct {
    int number;
    const char *name;
} SIGNAME;


static SIGNAME signals[] = {
#include "signames.h"
  { 0,NULL }};


void list_signals(void)
{
    SIGNAME *walk;
    int col;

    col = 0;
    for (walk = signals; walk->name; walk++) {
	if (col+strlen(walk->name)+1 > 80) {
	    putchar('\n');
	    col = 0;
	}
	printf("%s%s",col ? " " : "",walk->name);
	col += strlen(walk->name)+1;
    }
    putchar('\n');
}


int get_signal(char *name,const char *cmd)
{
    SIGNAME *walk;

    if (isdigit(*name))
	return atoi(name);
    for (walk = signals; walk->name; walk++)
	if (!strcmp(walk->name,name)) break;
    if (walk->name) return walk->number;
    fprintf(stderr,"%s: unknown signal; %s -l lists signals.\n",name,cmd);
    exit(1);
}
