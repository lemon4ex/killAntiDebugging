//
//  killAntiDebugging.mm
//  killAntiDebugging
//
//  Created by lemon4ex on 16/11/15.
//  Copyright (c) 2016年 __MyCompanyName__. All rights reserved.
//

// CaptainHook by Ryan Petrich
// see https://github.com/rpetrich/CaptainHook/

#import <Foundation/Foundation.h>
#import "CaptainHook/CaptainHook.h"
#include <sys/sysctl.h>
#include <substrate.h>

// Objective-C runtime hooking using CaptainHook:
//   1. declare class using CHDeclareClass()
//   2. load class using CHLoadClass() or CHLoadLateClass() in CHConstructor
//   3. hook method using CHOptimizedMethod()
//   4. register hook using CHHook() in CHConstructor
//   5. (optionally) call old method using CHSuper()
static int	(*old_sysctl)(int *, u_int, void *, size_t *, void *, size_t);

static int	new_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
    int result = old_sysctl(name,namelen,oldp,oldlenp,newp,newlen);
    if (*oldlenp == sizeof(struct kinfo_proc)) {
        struct kinfo_proc *info = (struct kinfo_proc *)oldp;
        info->kp_proc.p_flag &= ~(P_TRACED);
    }
    return result;
}

static void	 (*old_exit)(int);
static void	 new_exit(int)
{
    
}

typedef int (*ptr_ptrace_t)(int _request, pid_t _pid, caddr_t _addr, int _data);
static ptr_ptrace_t old_ptrace;
static int new_ptrace(int _request, pid_t _pid, caddr_t _addr, int _data)
{
    if(_request == 31) //PT_DENY_ATTACH
    {
        return 0;
    }
    
    return old_ptrace(_request,_pid,_addr,_data);
}

CHConstructor // code block that runs immediately upon load
{
	@autoreleasepool
	{
        NSLog(@"===============================");
        NSLog(@"=      killAntiDebugging      =");
        NSLog(@"=         by lemon4ex         =");
        NSLog(@"===============================");
        
        NSLog(@"Hook sysctl function");
        MSHookFunction((void *)sysctl, (void *)new_sysctl, (void **)&old_sysctl);
        NSLog(@"Hook exit function");
        MSHookFunction((void *)exit, (void *)new_exit, (void **)&old_exit);
        
        void* handle = dlopen(0, RTLD_GLOBAL | RTLD_NOW);
        ptr_ptrace_t ptrace = (ptr_ptrace_t)dlsym(handle, "ptrace");
        NSLog(@"Hook ptrace function");
        MSHookFunction((void *)ptrace, (void *)new_ptrace, (void **)&old_ptrace);
	}
}
