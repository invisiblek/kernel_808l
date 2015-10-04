/**

Memory region comparison utility functions. 

<keywords memory comparison, comparison/memory, 
utility functions/memory comparison>

File: sshmemcmp.c

@author
Kenneth Oksanen <cessu@ssh.com>

@copyright
Copyright (c) 2002, 2003 SFNT Finland Oy, all rights reserved. 

*/


#ifndef SSHMEMCMP_H
#define SSHMEMCMP_H

/** This is a re-implementation of the standard memcmp function 
    which so often seemed to differ (read: was broken) in various 
    platforms. 

    @return
    This implementation of memcmp GUARANTEES that a positive value is 
    returned if and only if the first differing byte (when treated as 
    an unsigned char) in p1[0..n-1] is greater than the 
    corresponding byte in p2[0..n-1].  */

int ssh_memcmp(const void *p1, const void *p2, size_t n);

#endif /* SSHMEMCMP_H */
