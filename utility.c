/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2008 Jason Bittel <jason.bittel@gmail.com>

*/

#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "error.h"

/* Strip leading and trailing spaces from parameter string, modifying
   the string in place and returning a pointer to the (potentially)
   new starting point */
char *str_strip_whitespace(char *str) {
        int len;

#ifdef DEBUG
        ASSERT(str);
        ASSERT(strlen(str) > 0);
#endif

        while (isspace(*str)) str++;
        len = strlen(str);
        while (len && isspace(*(str + len - 1)))
                *(str + (len--) - 1) = '\0';

        return str;
}

/* Convert the paramter string to lowercase */
char *str_tolower(char *str) {
        char *c;

#ifdef DEBUG
        ASSERT(str);
        ASSERT(strlen(str) > 0);
#endif

        for (c = str; *c != '\0'; c++) {
                *c = tolower(*c);
        }

        return str;
}

/* Function originated as strcasecmp() from the GNU C library; modified
   from its original format since s2 will always be lowercase, and to
   take a max comparison length */
int str_compare(const char *str1, const char *str2, int len) {
        unsigned char c1, c2;

#ifdef DEBUG
        ASSERT(str1 != str2);
        ASSERT(len > 0);
#endif

        do {
                c1 = tolower(*str1++);
                c2 = *str2++;
                if ((c1 == '\0') || (c2 == '\0')) break;
        } while ((c1 == c2) && (--len > 0));

        return c1 - c2;
}
