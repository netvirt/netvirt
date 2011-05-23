/*
 * options.c: conf file parser API
 *
 * Copyright (C) 2009 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>

#include "journal.h"
#include "options.h"

enum {
    SUCCESS = 0,
    ERR_SYNTAX,	    /* syntax error */
    ERR_DUPLICATE,  /* duplicate item */
    ERR_ERRNO,	    /* unknown error but errno knows */
    ERR_TYPE,	    /* invalid option type */
    ERR_MAN	    /* mandatory option not present */
};

#define break_line(e, l) do { printf("line %i: ", l); return e; } while (0)

void option_dump(struct options *opts)
{
	int i = 0;
	while (opts[i].tag != NULL) {

		if (opts[i].type & OPT_STR)
			JOURNAL_NOTICE("option]> %s == %s",
				opts[i].tag, *(char **)(opts[i].value) ? *(char **)(opts[i].value) : "(nil)");

		else if (opts[i].type & OPT_INT) {

			if (*(int **)(opts[i].value))
				JOURNAL_NOTICE("option]> %s == %i", opts[i].tag, **(int **)(opts[i].value));
			else
				JOURNAL_NOTICE("option]> %s == (nil)", opts[i].tag);
		}
		else
			JOURNAL_NOTICE("option]> %s == err: invalid type", opts[i].tag);

		i++;
	}
}

/* trim(): remove whitespaces from string
 * @str	    -> a pointer to the string to strip
 * $return  -> the string with no spaces
 */
static char *trim(char *str)
{
	char *a, *z;

	a = str;
	while (*a == ' ') a++;

	z = a + strlen(a);
	while (*--z == ' ' && (z > a));
	*++z = '\0';

	return a;
}

/* is_comment(): verify wether line is a comment or not
 * @str	    -> the string to verify
 * $return  -> 1 if line is a comment, 0 otherwise
 * The line is considered a comment if the following is found
 * to be the first character beside spaces :
 *	# OR ; OR [
 */
static int is_comment(char *str)
{
	char *p;

	p = str;
	while (*p == ' ') p++;
	switch(*p) {
		case '#':
		case '[':
		case ';':
			return 1;
	}

	return 0;
}

/* try_set_value(): find matching tag, then store value
 * @str	    -> the string associated to the tag
 * @tag	    -> the tag name to find in options struct
 * @opts    -> the options struct
 * $return  -> 0 if no error occured, an ERR_ value otherwise
 *
 * This function is used internaly by parse() everytime it
 * finds a `tag = value' pair in the config file.
 */
static int try_set_value(char *str, char *tag, struct options *opts)
{
	int i = 0;
	for (; opts[i].tag != NULL; i++) {

		if (strcmp(opts[i].tag, tag) != 0)
			continue;

		if (*(void **)(opts[i].value) != NULL)
			return ERR_DUPLICATE;

		if (opts[i].type & OPT_STR) {
			*(void **)(opts[i].value) = strdup(str);

			if (*(void **)(opts[i].value) == NULL)
				return ERR_ERRNO;
		}
		else if (opts[i].type & OPT_INT) {
			*(void **)(opts[i].value) = malloc(sizeof(int));

			if (*(void **)(opts[i].value) == NULL)
				return ERR_ERRNO;

				errno = 0;
				**(int **)(opts[i].value) = strtoul(str, NULL, 0);
				/* if an error occurred, errno will have a
				 * non-zero value after the call
				 */
				if (errno != 0)
					return ERR_ERRNO;

		} else {
		    /* the caller MUST specify a valid option type */
		    return ERR_TYPE;
		}
	}

	return 0;
}

/* parse(): parse the file pointer to populate options struct
 * @opts    -> the options struct
 * @fp	    -> a pointer to the file
 * $return  -> 0 if no error occured, an ERR_ value otherwise
 *
 * MAX_LEN is the maximum length allowed for a line.
 *
 * This function retreives each line of the given file, strip off
 * comments and bail out on stuborn syntax error. For each valid
 * line, it asks try_set_value() to store the value inside the
 * options struct.
 */
#define MAX_LEN 256
static int parse(struct options *opts, FILE *fp)
{
	char *p, arg[MAX_LEN];
	int line = 0, ret = 0, err = 0;

	memset(arg, 0, MAX_LEN);

	while (!feof(fp) && (ret = fscanf(fp, "\n%256[^\n]\n", arg)) != 0 && ret < MAX_LEN) {

		line++;

		if (is_comment(arg))
			continue;

		p = strstr(arg, "=");
		if (p == NULL)
			break_line(ERR_SYNTAX, line);

		*p = '\0'; p++;

		p = trim(p);
		if (*p == 0)
			break_line(ERR_SYNTAX, line);

		err = try_set_value(p, trim(arg), opts);
		if (err > 0)
			break_line(err, line);
	}

	if (ret > MAX_LEN) {
		JOURNAL_NOTICE("option]> the line %i is longer than %i :: %s:%i",
				line, MAX_LEN, __FILE__, __LINE__);
		return ERR_ERRNO;
	}

	if (ret == EOF) {
		JOURNAL_NOTICE("option]> unexpected error %s :: %s:%i",
				strerror(errno), __FILE__, __LINE__);
		return ERR_ERRNO;
	}

    return 0;
}

/* sanity_check(): final option type lookup
 * @opts    -> pointer to the options structure
 * $return  -> 1 if option types are satisfied, 0 otherwise
 */
static int sanity_check(const struct options *opts)
{
	int i = 0;
	for (; opts[i].tag != NULL; i++)
		if ((opts[i].type & OPT_MAN) && *(void **)(opts[i].value) == NULL) {
				JOURNAL_NOTICE("option]> '%s' is missing from configuration :: %s:%i",
						opts[i].tag, __FILE__, __LINE__);

				return ERR_MAN;
		    }

	    return SUCCESS;
}

/* option_free(): free allocated memory
 * @opts    -> pointer to the options structure
 * $return  -> nothing
 *
 * Use this function to release memory allocated by strdup() and malloc()
 * in the try_set_value() function when you no longer need them.
 */
void option_free(struct options *opts)
{
	int i = 0;
	for (; opts[i].tag != NULL; i++) {

		free(*(void **)(opts[i].value));
		*(void **)(opts[i].value) = NULL;
	}
}

/* option_parse(): parse a configuration file
 * @opts    -> the options struct
 * @path    -> an absolute pathname to the file
 * $return  -> 1 on success, 0 otherwise
 *
 * This is the exported function to allow caller to parse a configuration
 * file and populate the provided options structure.
 */
int option_parse(struct options *opts, char *path)
{
	FILE *fp;
	int i;

	if ((fp = fopen(path, "r")) == NULL) {
		JOURNAL_NOTICE("%s: %s", path, strerror(errno));
		return 1;
	}

	for (i = 0; opts[i].tag != NULL; i++)
		*(void **)opts[i].value = NULL;

	switch(parse(opts, fp)) {
		case ERR_SYNTAX:
			JOURNAL_NOTICE("option]> syntax error :: %s:%i", __FILE__, __LINE__);
			option_free(opts);
			fclose(fp);
			return ERR_SYNTAX;

		case ERR_DUPLICATE:
			JOURNAL_NOTICE("option]> duplicate :: %s:%i", __FILE__, __LINE__);
			option_free(opts);
			fclose(fp);
			return ERR_DUPLICATE;

		case ERR_ERRNO:
			JOURNAL_NOTICE("option]> unexpected error %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
			option_free(opts);
			fclose(fp);
			return ERR_ERRNO;

		case ERR_TYPE:
			JOURNAL_NOTICE("option]> invalid option type :: %s:%i", __FILE__, __LINE__);
			option_free(opts);
			fclose(fp);
			return ERR_TYPE;
	}

	fclose(fp);
	return sanity_check(opts);
}
