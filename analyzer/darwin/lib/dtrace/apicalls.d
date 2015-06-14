#!/usr/sbin/dtrace -C -s
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
 *     pid         : integer            // e.g. 9213
 * }
 *
 */
#define SCRIPT_NAME "apicalls.d"

#ifndef ANALYSIS_TIMEOUT
    #define ANALYSIS_TIMEOUT (-1)
#endif

/* Preprocessor magic: stringification */
#define str(s) str0(s)
#define str0(s) #s
/* Since there's no built-in way to get an output file of the current script,
 * we have to inject it into the source code if the script with a preprocessor
 * directive. */
#if !defined(CHILD_MODE) && !defined(OUTPUT_FILE)
    #error Please, specify the output file for this scrip via "-C -DOUTPUT_FILE=./foo.log"
#endif

#if !defined(CHILD_MODE) && !defined(SCRIPT_PATH)
    #error Please, specify the full path to the current script
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

/* All probes from `pid` provider are, well, pid-specific. This means that the
 * probes installed for the parent process won't fire for its children (because,
 * you know, their pids are different). Thus, we have to re-install all these
 * probes for children processes manually as they are spawned.
 *
 * To do so we (1) stop the newborn; (2) attach dtrace to it via something like
 * system("dtrace CURRENT_SCRIPT -p CHILD_PID"); (3) as we've loaded our script,
 * resume the child via pidresume() [Note: this function only exists in Apple's
 * implementation of dtrace].
 *
 * Since progenyof() test enables us to catch *every progeny* of our main
 * parent process, we don't duplicate this "watch-my-children" logic in child
 * scripts.
 */
#ifdef CHILD_MODE
    dtrace:::BEGIN
    {
        pidresume($target); /* Let this child go. */
    }
    /* TODO(rodionovd): it looks like there's a bug in Apple dtrace that keeps
     * dtrace tracing even when its target (specified via -p) is already terminated.
     * Maybe I'm doing something wrong, but here's a temporary workaround.
     */
    syscall::exit:entry
    /pid == $target/
    {
        exit(0);
    }
#else
    /* There's a new process spawned which is a progeny of our main target */
    proc:::start
    /progenyof($target) && pid != $target/
    {
        self->tracked[pid] = 1;
    }
    /* If we try to attach dtrace from inside `proc:::start` above,
     * it'll fail to enable any probes on shared libraries because `proc:::start`
     * happens when none of these libraries are actually loaded into the newborn
     * process. So instead, we wait until some syscalls which only happen at the
     * end of a process initialization: at this point all the required libraries
     * will be loaded and we'll be able to install probes on them. */
    syscall::stat64:entry,
    syscall::bsdthread_register:return
    / self->tracked[pid] == 1 &&
    	((probefunc == "stat64" && copyinstr(arg0) == "/AppleInternal\0")
      || (probefunc == "bsdthread_register" && (int)arg0 == -1)) /
    {
        self->tracked[pid] == 0;
        /* Stop this child right now. Otherwise it may finish running even before
         * we attach dtrace to it. */
        stop();
        /* Attach `dtrace` to the child via it's pid. We specify the same output
         * file we already have so all the results will be just in one place. */
        system("sudo dtrace -Z -C -DCHILD_MODE=1 -DANALYSIS_TIMEOUT=%d -s \"%s\" -o \"%s\" -p %d &",
               countdown, str(SCRIPT_PATH), str(OUTPUT_FILE), pid);
    }

    dtrace:::END
    {
        printf("## %s done ##", SCRIPT_NAME);
    }
#endif


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

#pragma mark Return probes

/* No arguments, retval: int */
pid$target::fork:return
{
    this->timestamp = walltimestamp / 1000000000;
    printf("{\"api\":\"%s\", \"args\":[], \"retval\":%d, \"timestamp\":%d, \"pid\":%d}\n",
        probefunc,
        (int)arg1,
        this->timestamp, pid);
}

/* One argument: char *, retval: int */
pid$target::system:return,
pid$target::printf:return,
pid$target:libsystem_c.dylib:atoi:return
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

/* One argument: [size_t], retval: void* */
pid$target:libsystem_malloc:malloc:return
{
    this->timestamp = walltimestamp / 1000000000;
    printf("{\"api\":\"%s\", \"args\":[%llu], \"retval\":%llu, \"timestamp\":%d, \"pid\":%d}\n",
        probefunc,
        (unsigned long long)self->arg0,
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
    printf("{\"api\":\"%s\", \"args\":[\"%S\", %d], \"retval\":%llu, \"timestamp\":%d, \"pid\":%d}\n",
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

/* Two arguments: [void*, char *], retval: void* */
pid$target::dlsym:return
{
    this->timestamp = walltimestamp / 1000000000;
    printf("{\"api\":\"%s\", \"args\":[%llu, \"%S\"], \"retval\":%llu, \"timestamp\":%d, \"pid\":%d}\n",
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
