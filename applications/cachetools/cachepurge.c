/*
** Copyright 2016 Carnegie Mellon University
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**    http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include "Xsocket.h"
#include "xcache.h"
#include "dagaddr.hpp"

#define CACHEDIR "/tmp/content/"

int verbose = 1;

void help(const char *name)
{
	printf("\nusage: %s [-q] \n", name);
	printf("where:\n");
	printf(" -q : quiet mode\n\n");
	exit(0);
}

void say(const char *fmt, ...)
{
	if (verbose) {
		va_list args;

		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
	}
}

void die(int ecode, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
	fprintf(stdout, "aborting\n");
	exit(ecode);
}

int main(int argc, char **argv) {

		if (argc == 2 && strcmp(argv[1], "-q") == 0) {
			verbose = 0;
		} else if (argc != 1) {
			help(argv[0]);
		}

		say("Sorry, I don't do anything yet\n", CACHEDIR);

		return 0;
}