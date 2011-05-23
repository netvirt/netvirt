#ifndef DNDS_OPTIONS_H
#define DNDS_OPTIONS_H

#define OPT_STR 0x01	/* Is a string */
#define OPT_INT 0x02	/* Is an integer */
#define OPT_MAN 0x04	/* Is mandatory */

struct options {
	char *tag;
	void *value;
	unsigned short type;
};

extern int option_parse(struct options *, char *);
extern void option_dump(struct options *);
extern void option_free(struct options *);

#endif /* DNDS_OPTIONS_H */
