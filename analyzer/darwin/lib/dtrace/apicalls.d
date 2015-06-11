#!/usr/sbin/dtrace -C -s
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
 *     pid         : integer            // e.g. 9213
 * }
 *
 */

#ifndef ANALYSIS_TIMEOUT
    #define ANALYSIS_TIMEOUT (-1)
#endif

#pragma mark -
 dtrace:::BEGIN
 {
     countdown = ANALYSIS_TIMEOUT;

     self->deeplevel = 0;
     self->arg0 = (int64_t)0;
     self->arg1 = (int64_t)0;
     self->arg2 = (int64_t)0;
     self->arg3 = (int64_t)0;
     self->arg4 = (int64_t)0;
     self->arg5 = (int64_t)0;
     self->arg6 = (int64_t)0;
     self->arg7 = (int64_t)0;
 }

 profile:::tick-1sec
 /countdown > 0/
{
    --countdown;
}

 profile:::tick-1sec
 / countdown == 0 /
 {
     exit(0);
 }

 dtrace:::END
 {
     printf("## apicalls.d done ##");
 }

/* ******* **************************** ******* */
self int64_t arguments_stack[unsigned long, string];
self deeplevel;
/* ******* **************************** ******* */

/* No arguments, retval: int */
pid$target::fork:return
{
    this->timestamp = walltimestamp / 1000000000;
    printf("{\"api\":\"%s\", \"args\":[], \"retval\":%d, \"timestamp\":%d, \"pid\":%d}\n",
        probefunc,
        (int)arg1,
        this->timestamp, pid);
}

/* One argument */
pid$target::system:entry,
pid$target::printf:entry,
pid$target::strlen:entry
{
    self->deeplevel++;
    /* Save the arguments we already have for our callee */
    self->arguments_stack[self->deeplevel, "arg0"] = self->arg0;
    /* And remember our own arguments */
    self->arg0 = arg0;
}

/* One argument: char *, return value: int */
pid$target::system:return,
pid$target::printf:return,
pid$target::strlen:return
{
    this->timestamp = walltimestamp / 1000000000;
    printf("{\"api\":\"%s\", \"args\":[\"%S\"], \"retval\":%d, \"timestamp\":%d, \"pid\":%d}\n",
        probefunc,
        copyinstr(self->arg0),
        (int)arg1,
        this->timestamp, pid);

    /* Restore arguments for our callee */
    self->arg0 = self->arguments_stack[self->deeplevel, "arg0"];
    /* Release the memory for the current level stack */
    self->arguments_stack[self->deeplevel, "arg0"] = 0;
    --self->deeplevel;
}

pid$target:libsystem_malloc:malloc:entry,
pid$target:libdyld:dlopen:entry,
pid$target:libdyld:dlsym:entry
{
    ++self->deeplevel;
    self->arguments_stack[self->deeplevel, "arg0"] = self->arg0;
    self->arguments_stack[self->deeplevel, "arg1"] = self->arg1;
    self->arg0 = arg0;
    self->arg1 = arg1;
}

/* One argument: [size_t], retval: void* */
pid$target:libsystem_malloc:malloc:return
{
    this->timestamp = walltimestamp / 1000000000;
    printf("{\"api\":\"%s\", \"args\":[%llu], \"retval\":%lu, \"timestamp\":%d, \"pid\":%d}\n",
        probefunc,
        (size_t)self->arg0,
        (unsigned long long)arg1,
        this->timestamp, pid);

    self->arg0 = self->arguments_stack[self->deeplevel, "arg0"];
    self->arg1 = self->arguments_stack[self->deeplevel, "arg1"];
    self->arguments_stack[self->deeplevel, "arg0"] = 0;
    self->arguments_stack[self->deeplevel, "arg1"] = 0;
    --self->deeplevel;
}

/* Two arguments: [char*, int]; retval: void* */
pid$target:libdyld:dlopen:return
{
    this->timestamp = walltimestamp / 1000000000;
    printf("{\"api\":\"%s\", \"args\":[\"%S\", %d], \"retval\":%lu, \"timestamp\":%d, \"pid\":%d}\n",
        probefunc,
        copyinstr(self->arg0), (int)self->arg1,
        (unsigned long long)arg1,
        this->timestamp, pid);

    self->arg0 = self->arguments_stack[self->deeplevel, "arg0"];
    self->arg1 = self->arguments_stack[self->deeplevel, "arg1"];
    self->arguments_stack[self->deeplevel, "arg0"] = 0;
    self->arguments_stack[self->deeplevel, "arg1"] = 0;
    --self->deeplevel;
}

/* Two argument: [void*, char *], retval: void* */
pid$target::dlsym:return
{
    this->timestamp = walltimestamp / 1000000000;
    printf("{\"api\":\"%s\", \"args\":[%lu, \"%S\"], \"retval\":%lu, \"timestamp\":%d, \"pid\":%d}\n",
        probefunc,
        (unsigned long long)self->arg0, copyinstr(self->arg1),
        (unsigned long long)arg1,
        this->timestamp, pid);

    self->arg0 = self->arguments_stack[self->deeplevel, "arg0"];
    self->arg1 = self->arguments_stack[self->deeplevel, "arg1"];
    self->arguments_stack[self->deeplevel, "arg0"] = 0;
    self->arguments_stack[self->deeplevel, "arg1"] = 0;
    --self->deeplevel;
}
