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
 *     tid         : integer,           // e.g. 269040
 *     errno       : integer            // e.g. 22
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

/* We may use `sudo -u` to drop (root) privileges before running a target.
 * If this were the case, we wouldn't care about API calls of sudo itself, thus
 * no probes.
 */
#ifndef SUDO

/* ******* **************************** ******* */
self int64_t arguments_stack[unsigned long, string];
self deeplevel;
/* ******* **************************** ******* */

#pragma mark - Probes
#include "probes.d"

/* exec* probes are special: they don't return on success; so catch them early */
pid$target::execve:entry
{
    this->retval = 0;
    this->timestamp_ms = walltimestamp/1000000;

    printf("{\"api\":\"%s\", \"args\":[\"%S\", %llu, %llu], \"retval\":%d, \"timestamp\":%lld, \"pid\":%d, \"ppid\":%d, \"tid\":%d, \"errno\":%d}\n",
        probefunc,
        arg0 != (int64_t)NULL ? copyinstr(arg0) : "<NULL>", (unsigned long long)arg1, (unsigned long long)arg2,
        (int)this->retval,
        (int64_t)this->timestamp_ms, pid, ppid, tid, errno);
}

#endif /* not SUDO */
