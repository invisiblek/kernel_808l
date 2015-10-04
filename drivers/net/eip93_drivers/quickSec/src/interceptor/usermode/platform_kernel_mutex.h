/**
   
   @copyright
   Copyright (c) 2006 - 2010, AuthenTec Oy.  All rights reserved.
   
   platform_kernel_mutex.h
   
   
   Platform dependent things for the kernel allocation routines.  This
   files is included from engine-interface/kernel_mutex.h.
   
   
*/


#ifndef PLATFORM_KERNEL_MUTEX_H
#define PLATFORM_KERNEL_MUTEX_H 1

#include "sshmutex.h"

typedef struct SshKernelMutexRec
{
  Boolean taken;
  SshMutex mutex;
} SshKernelMutexStruct;

typedef struct SshKernelRWMutexRec
{
  Boolean taken;
  SshMutex mutex;
} SshKernelRWMutexStruct;

typedef struct SshKernelCriticalSectionRec
{
  Boolean taken;
  SshMutex mutex;
} SshKernelCriticalSectionStruct;

#endif /* PLATFORM_KERNEL_MUTEX_H */
