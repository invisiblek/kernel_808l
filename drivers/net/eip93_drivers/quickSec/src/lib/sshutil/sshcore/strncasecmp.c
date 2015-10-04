/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 */
/*
 *        Program: sshutil
 *
 *        Creation          : 06:56 Aug 20 1996 kivinen
 *        Last Modification : 13:48 Sep  8 2006 kivinen
 *        Version           : 1.6
 *        
 *
 *        Description       : Replacement functions for strncasecmp
 *
 *
 */

#include "sshincludes.h"

int strncasecmp(const char *s1, const char *s2, size_t len)
{
  if (len==0)
    return 0;

  while (len-- > 1 && *s1 &&
	 (*s1 == *s2 ||
	  tolower(*(unsigned char *)s1) ==
	  tolower(*(unsigned char *)s2)))
    {
      s1++;
      s2++;
    }
  return (int) tolower(*(unsigned char *)s1)
       - (int) tolower(*(unsigned char *)s2);
}
