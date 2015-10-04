/*

  sshmempool.c

  Author: Timo J. Rinne <tri@ssh.com>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Reverse mapping of SANA assigned memory pool numbers.

*/

#include "sshincludes.h"
#include "sshmempool.h"

const char *ssh_mempool_name_generated(int mempool_num);

const char *ssh_mempool_name(int mempool_num)
{
  const char *r;

  if ((r = ssh_mempool_name_generated(mempool_num)) != NULL)
    return r;
  else
    return "Unassigned memory pool number!!!";
}

/* eof (sshmempool.c) */
