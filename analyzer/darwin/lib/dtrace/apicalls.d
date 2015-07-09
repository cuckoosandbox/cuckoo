#pragma D option destructive
#pragma D option quiet
/* apicalls.d
 *
 * Copyright (C) 2015 Dmitry Rodionov
 * This software may be modified and distributed under the terms
 * of the MIT license. See the LICENSE file for details.
 *
 * This script prints results in JSON format, each log entry is a dictionary:
 * {
 *     api         : string,            // e.g. "fprintf"
 *     args        : array,             // e.g. [1489124712123, "Hello\n!"]
 *     retval      : string OR integer, // e.g. "kkk"
 *     timestamp   : integer,           // e.g. 1433765405
 *     pid         : integer,           // e.g. 9213
 *     ppid        : integer,           // e.g. 9210
 *     tid         : integer            // e.g. 269040
 * }
 *
 */
#define SCRIPT_NAME "apicalls.d"

#ifndef ANALYSIS_TIMEOUT
    #define ANALYSIS_TIMEOUT (-1)
#endif

dtrace:::BEGIN
 {
     countdown = ANALYSIS_TIMEOUT;

     self->deeplevel = 0;
     self->arg0  = (int64_t)0;
     self->arg1  = (int64_t)0;
     self->arg2  = (int64_t)0;
     self->arg3  = (int64_t)0;
     self->arg4  = (int64_t)0;
     self->arg5  = (int64_t)0;
     self->arg6  = (int64_t)0;
     self->arg7  = (int64_t)0;
     self->arg8  = (int64_t)0;
     self->arg9  = (int64_t)0;
     self->arg10 = (int64_t)0;
     self->arg11 = (int64_t)0;
 }

profile:::tick-1sec
/ countdown > 0 /
{
    --countdown;
}

profile:::tick-1sec
/ countdown == 0 /
{
    exit(0);
}

#pragma mark - Following children
#include "follow_children.d"

/* ******* **************************** ******* */
self int64_t arguments_stack[unsigned long, string];
self deeplevel;
/* ******* **************************** ******* */

#pragma mark - Probes

#pragma mark Entry probes

/* One argument */
pid$target::system:entry,
pid$target::printf:entry,
pid$target:libsystem_c.dylib:atoi:entry
{
    self->deeplevel++;
    /* Save the arguments we've already got for our callee */
    self->arguments_stack[self->deeplevel, "arg0"] = self->arg0;
    /* And remember our own arguments */
    self->arg0 = arg0;
}

/* Two arguments */
pid$target:libdyld:dlopen:entry,
pid$target:libdyld:dlsym:entry,
pid$target::fprintf:entry
{
    ++self->deeplevel;
    self->arguments_stack[self->deeplevel, "arg0"] = self->arg0;
    self->arguments_stack[self->deeplevel, "arg1"] = self->arg1;
    self->arg0 = arg0;
    self->arg1 = arg1;
}

/* Three arguments. These may not return, so we just dump them early */
pid$target::execve:entry
{
    this->retval = 0;
    this->is_success = 1;
    this->timestamp_ms = walltimestamp/1000000;

    printf("{\"api\":\"%s\", \"args\":[\"%S\", %llu, %llu], \"retval\":%d, \"is_success\": %s, \"timestamp\":%ld, \"pid\":%d, \"ppid\":%d, \"tid\":%d}\n",
        probefunc,
        copyinstr(arg0), (unsigned long long)arg1, (unsigned long long)arg2,
        (int)this->retval, this->is_success ? "true" : "false",
        this->timestamp_ms, pid, ppid, tid);
}

#pragma mark Return probes

/* No arguments, retval: int */
pid$target::fork:return
{
    this->retval = arg1;
    this->timestamp_ms = walltimestamp/1000000;

    printf("{\"api\":\"%s\", \"args\":[], \"retval\":%d, \"timestamp\":%ld, \"pid\":%d, \"ppid\":%d, \"tid\":%d}\n",
        probefunc,
        (int)this->retval,
        this->timestamp_ms, pid, ppid, tid);
}

/* One argument: char *, retval: int */
pid$target::system:return,
pid$target::printf:return,
pid$target:libsystem_c.dylib:atoi:return
{
    this->retval = arg1;
    this->is_success = (probefunc == "system" ? this->retval == 0 :
                       (probefunc == "atoi"   ? 1 : this->retval > 0));
    this->timestamp_ms = walltimestamp/1000000;

    printf("{\"api\":\"%s\", \"args\":[\"%S\"], \"retval\":%d, \"timestamp\":%ld, \"pid\":%d, \"ppid\":%d, \"tid\":%d}\n",
        probefunc,
        copyinstr(self->arg0),
        (int)this->retval,
        this->timestamp_ms, pid, ppid, tid);

    /* Restore arguments for our callee */
    self->arg0 = self->arguments_stack[self->deeplevel, "arg0"];
    /* Release the memory for the current level stack */
    self->arguments_stack[self->deeplevel, "arg0"] = 0;
    --self->deeplevel;
}

/* Two arguments: [char*, int]; retval: void* */
pid$target:libdyld:dlopen:return
{
    this->retval = arg1;
    this->is_success = (this->retval > 0);
    this->timestamp_ms = walltimestamp/1000000;

    printf("{\"api\":\"%s\", \"args\":[\"%S\", %d], \"retval\":%llu, \"timestamp\":%ld, \"pid\":%d, \"ppid\":%d, \"tid\":%d}\n",
        probefunc,
        copyinstr(self->arg0), (int)self->arg1,
        (unsigned long long)this->retval,
        this->timestamp_ms, pid, ppid, tid);

    self->arg0 = self->arguments_stack[self->deeplevel, "arg0"];
    self->arg1 = self->arguments_stack[self->deeplevel, "arg1"];
    self->arguments_stack[self->deeplevel, "arg0"] = 0;
    self->arguments_stack[self->deeplevel, "arg1"] = 0;
    --self->deeplevel;
}

/* Two arguments: [void*, char *], retval: void* */
pid$target::dlsym:return,
pid$target::fprintf:return
{
    this->retval = arg1;
    this->is_success = (this->retval > 0);
    this->timestamp_ms = walltimestamp/1000000;

    printf("{\"api\":\"%s\", \"args\":[%llu, \"%S\"], \"retval\":%llu, \"timestamp\":%ld, \"pid\":%d, \"ppid\":%d, \"tid\":%d}\n",
        probefunc,
        (unsigned long long)self->arg0, copyinstr(self->arg1),
        (unsigned long long)this->retval,
        this->timestamp_ms, pid, ppid, tid);

    self->arg0 = self->arguments_stack[self->deeplevel, "arg0"];
    self->arg1 = self->arguments_stack[self->deeplevel, "arg1"];
    self->arguments_stack[self->deeplevel, "arg0"] = 0;
    self->arguments_stack[self->deeplevel, "arg1"] = 0;
    --self->deeplevel;
}
