/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>
  Licensed under GPLv2. For further information, see COPYING file.

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
        size_t len = strlen(str);

#ifdef DEBUG
        ASSERT(str);
        ASSERT(strlen(str) > 0);
#endif

        while (isspace(*str)) str++;
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

/* Copy at most len characters from src to dest, guaranteeing
   dest will be properly terminated. Returns the total number of
   characters copied, not including the string terminator. */
int str_copy(char *dest, const char *src, size_t len) {
        const char *start = dest;

        if (len > 0) {
                while ((*src != '\0') && --len) {
                        *dest++ = *src++;
                }
                *dest = '\0';
        }

        return dest - start;
}

/* Wrapper function around str_copy() that first allocates
   memory for the destination string and then copies the
   parameter string into it. */
char *str_duplicate(const char *str) {
        char *new;
        size_t len = strlen(str);

        if ((new = malloc(len + 1)) == NULL)
                return NULL;

#ifdef DEBUG
        ASSERT(str_copy(new, str, len + 1) <= (len + 1));
#else
        str_copy(new, str, len + 1);
#endif

        return new;
}

/* Implementation of Jenkins's One-at-a-Time hash, as described on
   this page: http://www.burtleburtle.net/bob/hash/doobs.html */
unsigned int hash_str(char *str, unsigned int hashsize) {
        unsigned long int hash;

#ifdef DEBUG
        ASSERT(str);
        ASSERT(strlen(str) > 0);
#endif

        for (hash = 0; *str != '\0'; str++) {
                hash += tolower(*str);
                hash += (hash << 10);
                hash ^= (hash >> 6);
        }

        hash += (hash << 3);
        hash ^= (hash >> 11);
        hash += (hash << 15);

        /* Restrict hash value to a maximum of hashsize;
           hashsize must be a power of 2 */
        return (unsigned int) (hash & (hashsize - 1));
}
