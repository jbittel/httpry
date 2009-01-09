/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2009 Jason Bittel <jason.bittel@gmail.com>

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

/* Compare two strings, ignoring the case of str1 and
   assuming str2 is lowercase. Break if we find a string
   terminator in str2 and consider it a match as str1
   will not always have a string terminator. */
int str_compare(const char *str1, const char *str2) {

#ifdef DEBUG
        ASSERT(str2);
        ASSERT(strlen(str2) > 0);
        ASSERT(str1 != str2);
#endif

        while (tolower(*str1) == *str2) {
                str1++;
                str2++;
                if (*str2 == '\0') return 0;
        }

        return tolower(*str1) - *str2;
}
