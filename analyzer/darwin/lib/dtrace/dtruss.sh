#!/bin/sh
# #!/usr/bin/sh
#
# dtruss - print process system call time details.
#          Written using DTrace (Solaris 10 3/05).
#
# 17-Jun-2005, ver 0.80         (check for newer versions)
#
# USAGE: dtruss [-acdeflhoLs] [-t syscall] { -p PID | -n name | command }
#
#          -p PID          # examine this PID
#          -n name         # examine this process name
#          -t syscall      # examine this syscall only
#          -a              # print all details
#          -c              # print system call counts
#          -d              # print relative timestamps (us)
#          -e              # print elapsed times (us)
#          -f              # follow children as they are forked
#          -l              # force printing of pid/lwpid per line
#          -o              # print on cpu times (us)
#          -s              # print stack backtraces
#          -L              # don't print pid/lwpid per line
#          -b bufsize      # dynamic variable buf size (default is "4m")
#          -K timeout      # timeout of analysis
#          -W file         # redirect all output to a specified file
#  eg,
#       dtruss df -h       # run and examine the "df -h" command
#       dtruss -p 1871     # examine PID 1871
#       dtruss -n tar      # examine all processes called "tar"
#       dtruss -f test.sh  # run test.sh and follow children
#
# The elapsed times are interesting, to help identify syscalls that take
#  some time to complete (during which the process may have context
#  switched off the CPU).
#
# SEE ALSO: procsystime    # DTraceToolkit
#           dapptrace      # DTraceToolkit
#           truss
#
# COPYRIGHT: Copyright (c) 2005 Brendan Gregg.
#
# CDDL HEADER START
#
#  The contents of this file are subject to the terms of the
#  Common Development and Distribution License, Version 1.0 only
#  (the "License").  You may not use this file except in compliance
#  with the License.
#
#  You can obtain a copy of the license at Docs/cddl1.txt
#  or http://www.opensolaris.org/os/licensing.
#  See the License for the specific language governing permissions
#  and limitations under the License.
#
# CDDL HEADER END
#
# Author: Brendan Gregg  [Sydney, Australia]
#
# TODO: Track signals, more output formatting.
#
# 29-Apr-2005   Brendan Gregg   Created this.
# 09-May-2005      "      "     Fixed evaltime (thanks Adam L.)
# 16-May-2005      "      "     Added -t syscall tracing.
# 17-Jun-2005      "      "     Added -s stack backtraces.
#


##############################
# --- Process Arguments ---
#

### Default variables
opt_pid=0; opt_name=0; pid=0; pname="."
opt_elapsed=0; opt_cpu=0; opt_counts=0;
opt_relative=0; opt_printid=0; opt_follow=0
opt_command=0; command=""; opt_buf=0; buf="4m"
opt_trace=0; trace="."; opt_stack=0;
opt_timeout=0; timeout=-1; output_file="/dev/stderr"

### Process options
while getopts ab:cdefhln:op:st:K:W:L name
do
        case $name in
    b)    opt_buf=1; buf=$OPTARG ;;
    p)    opt_pid=1; pid=$OPTARG ;;
    n)    opt_name=1; pname=$OPTARG ;;
    t)    opt_trace=1; trace=$OPTARG ;;
    a)    opt_counts=1; opt_relative=1; opt_elapsed=1; opt_follow=1
          opt_printid=1; opt_cpu=1 ;;
    c)    opt_counts=1 ;;
    d)    opt_relative=1 ;;
    e)    opt_elapsed=1 ;;
    f)    opt_follow=1 ;;
    l)    opt_printid=1 ;;
    o)    opt_cpu=1 ;;
    L)    opt_printid=-1 ;;
    s)    opt_stack=-1 ;;
    K)  opt_timeout=1; timeout=$OPTARG ;;
    W)  output_file=$OPTARG ;;
        h|?)    cat <<-END >&2
        USAGE: dtruss [-acdefholLs] [-t syscall] { -p PID | -n name | command }

                  -p PID          # examine this PID
                  -n name         # examine this process name
                  -t syscall      # examine this syscall only
                  -a              # print all details
                  -c              # print syscall counts
                  -d              # print relative times (us)
                  -e              # print elapsed times (us)
                  -f              # follow children
                  -l              # force printing pid/lwpid
                  -o              # print on cpu times
                  -s              # print stack backtraces
                  -L              # don't print pid/lwpid
                  -b bufsize      # dynamic variable buf size
           eg,
               dtruss df -h       # run and examine "df -h"
               dtruss -p 1871     # examine PID 1871
               dtruss -n tar      # examine all processes called "tar"
               dtruss -f test.sh  # run test.sh and follow children
        END
        exit 1
        esac
done
shift `expr $OPTIND - 1`

### Option logic
if [ $opt_pid -eq 0 -a $opt_name -eq 0 ]; then
    opt_command=1
    if [ "$*" = "" ]; then
        $0 -h
        exit
    fi
    command="$*"    # yes, I meant $*!
fi
if [ $opt_follow -eq 1 -o $opt_name -eq 1 ]; then
    if [ $opt_printid -ne -1 ]; then
        opt_printid=1
    else
        opt_printid=0
    fi
fi

### Option translation
## if [ "$trace" = "exec" ]; then trace="exece"; fi
if [ "$trace" = "exec" ]; then trace="execve"; fi


#################################
# --- Main Program, DTrace ---
#

### Define D Script
dtrace='
 #pragma D option quiet

 /*
  * Command line arguments
  */
 inline int OPT_command   = '$opt_command';
 inline int OPT_follow    = '$opt_follow';
 inline int OPT_printid   = '$opt_printid';
 inline int OPT_relative  = '$opt_relative';
 inline int OPT_elapsed   = '$opt_elapsed';
 inline int OPT_cpu       = '$opt_cpu';
 inline int OPT_counts    = '$opt_counts';
 inline int OPT_pid       = '$opt_pid';
 inline int OPT_name      = '$opt_name';
 inline int OPT_trace     = '$opt_trace';
 inline int OPT_stack     = '$opt_stack';
 inline int OPT_timeout   = '$opt_timeout';
 inline int PID           = '$pid';
 inline string NAME       = "'$pname'";
 inline string TRACE      = "'$trace'";

 dtrace:::BEGIN
 {
    /* print header */
    /* OPT_printid  ? printf("%-8s  ","PID/LWP") : 1; */
    /*OPT_printid  ? printf("\t%-8s  ","PID/THRD") : 1;
    OPT_relative ? printf("%8s ","RELATIVE") : 1;
    OPT_elapsed  ? printf("%7s ","ELAPSD") : 1;
    OPT_cpu      ? printf("%6s ","CPU") : 1;*/
    /*printf("SYSCALL(args) \t\t = return\n");*/

    /* globals */
    trackedpid[pid] = 0;
    self->child = 0;
    this->type = 0;
    TIMEOUT = '$timeout';
 }

 /*
  * Save syscall entry info
  */

 /* MacOS X: notice first appearance of child from fork. Its parent
    fires syscall::*fork:return in the ususal way (see below) */
 syscall:::entry
 /OPT_follow && trackedpid[ppid] == -1 && 0 == self->child/
 {
    /* set as child */
    self->child = 1;

    /* print output */
    self->code = errno == 0 ? "" : "Err#";
    /* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
    OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
    OPT_relative ? printf("%8d:  ",vtimestamp/1000) : 1;
    OPT_elapsed  ? printf("%7d:  ",0) : 1;
    OPT_cpu      ? printf("%6d ",0) : 1;

    /*
    printf("%s()\t\t = %d %s%d\n","fork",
        0,self->code,(int)errno);
    */

    this->timestamp = walltimestamp / 1000000000;
    printf("{\"syscall\":\"%s\", \"args\":[], \"retval\":%d, \"errno\":%d, \"timestamp\":%d, \"pid\":%d}\n",
        "fork", 0, (int)errno, this->timestamp, pid);
 }

 /* MacOS X: notice first appearance of child and parent from vfork */
 syscall:::entry
 /OPT_follow && trackedpid[ppid] > 0 && 0 == self->child/
 {
    /* set as child */
    this->vforking_tid = trackedpid[ppid];
    self->child = (this->vforking_tid == tid) ? 0 : 1;

    /* print output */
    self->code = errno == 0 ? "" : "Err#";
    /* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
    /*OPT_printid  ? printf("%5d/0x%x:  ",(this->vforking_tid == tid) ? ppid : pid,tid) : 1;
    OPT_relative ? printf("%8d:  ",vtimestamp/1000) : 1;
    OPT_elapsed  ? printf("%7d:  ",0) : 1;
    OPT_cpu      ? printf("%6d ",0) : 1;*/

    /*
    printf("%s()\t\t = %d %s%d\n","vfork",
        (this->vforking_tid == tid) ? pid : 0,self->code,(int)errno);
    */

    this->timestamp = walltimestamp / 1000000000;
    printf("{\"syscall\":\"%s\", \"args\":[], \"retval\":%d, \"errno\":%d, \"timestamp\":%d, \"pid\":%d}\n",
        "vfork",
        (this->vforking_tid == tid) ? pid : 0,
        (int)errno,
        this->timestamp, pid);
 }

 syscall:::entry
 /(OPT_command && pid == $target) ||
  (OPT_pid && pid == PID) ||
  (OPT_name && NAME == strstr(NAME, execname)) ||
  (OPT_name && execname == strstr(execname, NAME)) ||
  (self->child)/
 {
    /* set start details */
    self->start = timestamp;
    self->vstart = vtimestamp;
    self->arg0 = arg0;
    self->arg1 = arg1;
    self->arg2 = arg2;

    /* count occurances */
    OPT_counts == 1 ? @Counts[probefunc] = count() : 1;
 }

/* 5 and 6 arguments */
 syscall::select:entry,
 syscall::mmap:entry,
 syscall::pwrite:entry,
 syscall::pread:entry
 /(OPT_command && pid == $target) ||
  (OPT_pid && pid == PID) ||
  (OPT_name && NAME == strstr(NAME, execname)) ||
  (OPT_name && execname == strstr(execname, NAME)) ||
  (self->child)/
 {
    self->arg3 = arg3;
    self->arg4 = arg4;
    self->arg5 = arg5;
 }

 /*
  * Follow children
  */
 syscall::fork:entry
 /OPT_follow && self->start/
 {
    /* track this parent process */
    trackedpid[pid] = -1;
 }

 syscall::vfork:entry
 /OPT_follow && self->start/
 {
    /* track this parent process */
    trackedpid[pid] = tid;
 }

 /* syscall::rexit:entry */
 syscall::exit:entry
 {
    /* forget child */
    self->child = 0;
    trackedpid[pid] = 0;
 }

 /*
  * Check for syscall tracing
  */
 syscall:::entry
 /OPT_trace && probefunc != TRACE/
 {
    /* drop info */
    self->start = 0;
    self->vstart = 0;
    self->arg0 = 0;
    self->arg1 = 0;
    self->arg2 = 0;
    self->arg3 = 0;
    self->arg4 = 0;
    self->arg5 = 0;
 }

 /*
  * Print return data
  */

 /*
  * NOTE:
  *  The following code is written in an intentionally repetetive way.
  *  The first versions had no code redundancies, but performed badly during
  *  benchmarking. The priority here is speed, not cleverness. I know there
  *  are many obvious shortcuts to this code, Ive tried them. This style has
  *  shown in benchmarks to be the fastest (fewest probes, fewest actions).
  */

 /* print 3 args, return as hex */
 syscall::sigprocmask:return
 /self->start/
 {
    /* calculate elapsed time */
    this->elapsed = timestamp - self->start;
    self->start = 0;
    this->cpu = vtimestamp - self->vstart;
    self->vstart = 0;
    self->code = errno == 0 ? "" : "Err#";

    /* print optional fields */
    /* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
    /*OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
    OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
    OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
    OPT_cpu ? printf("%6d ",this->cpu/1000) : 1;*/

    /* print main data */

    /*
    printf("%s(0x%X, 0x%X, 0x%X)\t\t = 0x%X %s%d\n",probefunc,
        (int)self->arg0,self->arg1,self->arg2,(int)arg0,
        self->code,(int)errno);
    */

    this->timestamp = walltimestamp / 1000000000;
    printf("{\"syscall\":\"%s\", \"args\":[%u, %u, %u], \"retval\":%d, \"errno\":%d, \"timestamp\":%d, \"pid\":%d}\n",
        probefunc,
        (int)self->arg0, self->arg1, self->arg2,
        (int)arg0,
        (int)errno,
        this->timestamp, pid);

    OPT_stack ? ustack()    : 1;
    OPT_stack ? trace("\n") : 1;
    self->arg0 = 0;
    self->arg1 = 0;
    self->arg2 = 0;
 }

 /* print 3 args, arg0 as a string */
 syscall::execve:return,
 syscall::stat:return,
 syscall::stat64:return,
 syscall::lstat:return,
 syscall::lstat64:return,
 syscall::access:return,
 syscall::mkdir:return,
 syscall::chdir:return,
 syscall::chroot:return,
 syscall::getattrlist:return, /* XXX 5 arguments */
 syscall::chown:return,
 syscall::lchown:return,
 syscall::chflags:return,
 syscall::readlink:return,
 syscall::utimes:return,
 syscall::pathconf:return,
 syscall::truncate:return,
 syscall::getxattr:return,
 syscall::setxattr:return,
 syscall::removexattr:return,
 syscall::unlink:return,
 syscall::open:return,
 syscall::open_nocancel:return
 /self->start/
 {
    /* calculate elapsed time */
    this->elapsed = timestamp - self->start;
    self->start = 0;
    this->cpu = vtimestamp - self->vstart;
    self->vstart = 0;
    self->code = errno == 0 ? "" : "Err#";

    /* print optional fields */
    /* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
    /*OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
    OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
    OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
    OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;*/

    /* print main data */
    /*
    printf("%s(\"%S\", 0x%X, 0x%X)\t\t = %d %s%d\n",probefunc,
        copyinstr(self->arg0),self->arg1,self->arg2,(int)arg0,
        self->code,(int)errno);
    */

    this->timestamp = walltimestamp / 1000000000;
    printf("{\"syscall\":\"%s\", \"args\":[\"%S\", %u, %u], \"retval\":%d, \"errno\":%d, \"timestamp\":%d, \"pid\":%d}\n",
        probefunc,
        copyinstr(self->arg0), self->arg1, self->arg2,
        (int)arg0,
        (int)errno,
        this->timestamp, pid);

    OPT_stack ? ustack()    : 1;
    OPT_stack ? trace("\n") : 1;
    self->arg0 = 0;
    self->arg1 = 0;
    self->arg2 = 0;
 }

 /* print 3 args, arg1 as a string */
 syscall::write:return,
 syscall::write_nocancel:return,
 syscall::read:return,
 syscall::read_nocancel:return
 /self->start/
 {
    /* calculate elapsed time */
    this->elapsed = timestamp - self->start;
    self->start = 0;
    this->cpu = vtimestamp - self->vstart;
    self->vstart = 0;
    self->code = errno == 0 ? "" : "Err#";

    /* print optional fields */
    /* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
    /*OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
    OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
    OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
    OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;*/

    /* print main data */

    /*
    printf("%s(0x%X, \"%S\", 0x%X)\t\t = %d %s%d\n",probefunc,self->arg0,
        arg0 == -1 ? "" : stringof(copyin(self->arg1,arg0)),self->arg2,(int)arg0,
        self->code,(int)errno);

    */

    this->timestamp = walltimestamp / 1000000000;
    printf("{\"syscall\":\"%s\", \"args\":[%u, \"%S\", %u], \"retval\":%d, \"errno\":%d, \"timestamp\":%d, \"pid\":%d}\n",
        probefunc,
        self->arg0, arg0 == -1 ? "" : stringof(copyin(self->arg1,arg0)), self->arg2,
        (int)arg0,
        (int)errno,
        this->timestamp, pid);


    OPT_stack ? ustack()    : 1;
    OPT_stack ? trace("\n") : 1;
    self->arg0 = 0;
    self->arg1 = 0;
    self->arg2 = 0;
 }

 /* print 2 args, arg0 and arg1 as strings */
 syscall::rename:return,
 syscall::symlink:return,
 syscall::link:return
 /self->start/
 {
    /* calculate elapsed time */
    this->elapsed = timestamp - self->start;
    self->start = 0;
    this->cpu = vtimestamp - self->vstart;
    self->vstart = 0;
    self->code = errno == 0 ? "" : "Err#";

    /* print optional fields */
    /* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
    /*OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
    OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
    OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
    OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;*/

    /* print main data */
    /*
    printf("%s(\"%S\", \"%S\")\t\t = %d %s%d\n",probefunc,
        copyinstr(self->arg0), copyinstr(self->arg1),
        (int)arg0,self->code,(int)errno);
    */

    this->timestamp = walltimestamp / 1000000000;
    printf("{\"syscall\":\"%s\", \"args\":[\"%S\", \"%S\"], \"retval\":%d, \"errno\":%d, \"timestamp\":%d, \"pid\":%d}\n",
        probefunc,
        copyinstr(self->arg0), copyinstr(self->arg1),
        (int)arg0,
        (int)errno,
        this->timestamp, pid);



    OPT_stack ? ustack()    : 1;
    OPT_stack ? trace("\n") : 1;
    self->arg0 = 0;
    self->arg1 = 0;
    self->arg2 = 0;
 }

 /* print 0 arg output */
 syscall::*fork:return
 /self->start/
 {
    /* calculate elapsed time */
    this->elapsed = timestamp - self->start;
    self->start = 0;
    this->cpu = vtimestamp - self->vstart;
    self->vstart = 0;
    self->code = errno == 0 ? "" : "Err#";

    /* print optional fields */
    /* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
    /*OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
    OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
    OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
    OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;*/

    /* print main data */
    /*
    printf("%s()\t\t = %d %s%d\n",probefunc,
        (int)arg0,self->code,(int)errno);

    */

    this->timestamp = walltimestamp / 1000000000;
    printf("{\"syscall\":\"%s\", \"args\":[], \"retval\":%d, \"errno\":%d, \"timestamp\":%d, \"pid\":%d}\n",
        probefunc,
        (int)arg0,
        (int)errno,
        this->timestamp, pid);


    OPT_stack ? ustack()    : 1;
    OPT_stack ? trace("\n") : 1;
    self->arg0 = 0;
    self->arg1 = 0;
    self->arg2 = 0;
 }

 /* print 1 arg output */
 syscall::close:return,
 syscall::close_nocancel:return
 /self->start/
 {
    /* calculate elapsed time */
    this->elapsed = timestamp - self->start;
    self->start = 0;
    this->cpu = vtimestamp - self->vstart;
    self->vstart = 0;
    self->code = errno == 0 ? "" : "Err#";

    /* print optional fields */
    /* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
    /*OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
    OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
    OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
    OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;*/

    /* print main data */
    /*
    printf("%s(0x%X)\t\t = %d %s%d\n",probefunc,self->arg0,
        (int)arg0,self->code,(int)errno);
    */

    this->timestamp = walltimestamp / 1000000000;
    printf("{\"syscall\":\"%s\", \"args\":[%u], \"retval\":%d, \"errno\":%d, \"timestamp\":%d, \"pid\":%d}\n",
        probefunc,
        self->arg0,
        (int)arg0,
        (int)errno,
        this->timestamp, pid);


    OPT_stack ? ustack()    : 1;
    OPT_stack ? trace("\n") : 1;
    self->arg0 = 0;
    self->arg1 = 0;
    self->arg2 = 0;
 }

 /* print 2 arg output */
 syscall::utimes:return,
 syscall::munmap:return
 /self->start/
 {
    /* calculate elapsed time */
    this->elapsed = timestamp - self->start;
    self->start = 0;
    this->cpu = vtimestamp - self->vstart;
    self->vstart = 0;
    self->code = errno == 0 ? "" : "Err#";

    /* print optional fields */
    /* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
    /*OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
    OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
    OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
    OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;*/

    /* print main data */
    /*
    printf("%s(0x%X, 0x%X)\t\t = %d %s%d\n",probefunc,self->arg0,
        self->arg1,(int)arg0,self->code,(int)errno);
    */

    this->timestamp = walltimestamp / 1000000000;
    printf("{\"syscall\":\"%s\", \"args\":[%u, %u], \"retval\":%d, \"errno\":%d, \"timestamp\":%d, \"pid\":%d}\n",
        probefunc,
        self->arg0, self->arg1,
        (int)arg0,
        (int)errno,
        this->timestamp, pid);


    OPT_stack ? ustack()    : 1;
    OPT_stack ? trace("\n") : 1;
    self->arg0 = 0;
    self->arg1 = 0;
    self->arg2 = 0;
 }

 /* print pread/pwrite with 4 arguments */
 syscall::pread*:return,
 syscall::pwrite*:return
 /self->start/
 {
    /* calculate elapsed time */
    this->elapsed = timestamp - self->start;
    self->start = 0;
    this->cpu = vtimestamp - self->vstart;
    self->vstart = 0;
    self->code = errno == 0 ? "" : "Err#";

    /* print optional fields */
    /* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
    /*OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
    OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
    OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
    OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;*/

    /* print main data */
    /*
    printf("%s(0x%X, \"%S\", 0x%X, 0x%X)\t\t = %d %s%d\n",probefunc,self->arg0,
        stringof(copyin(self->arg1,self->arg2)),self->arg2,self->arg3,(int)arg0,self->code,(int)errno);
    */

    this->timestamp = walltimestamp / 1000000000;
    printf("{\"syscall\":\"%s\", \"args\":[%u, %u, %u, %u], \"retval\":%d, \"errno\":%d, \"timestamp\":%d, \"pid\":%d}\n",
        probefunc,
        self->arg0, self->arg1, self->arg2, self->arg3,
        (int)arg0,
        (int)errno,
        this->timestamp, pid);

    OPT_stack ? ustack()    : 1;
    OPT_stack ? trace("\n") : 1;
    self->arg0 = 0;
    self->arg1 = 0;
    self->arg2 = 0;
    self->arg3 = 0;
 }

 /* print select with 5 arguments */
 syscall::select:return
 /self->start/
 {
    /* calculate elapsed time */
    this->elapsed = timestamp - self->start;
    self->start = 0;
    this->cpu = vtimestamp - self->vstart;
    self->vstart = 0;
    self->code = errno == 0 ? "" : "Err#";

    /* print optional fields */
    /* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
    /*OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
    OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
    OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
    OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;*/

    /* print main data */
    /*
    printf("%s(0x%X, 0x%X, 0x%X, 0x%X, 0x%X)\t\t = %d %s%d\n",probefunc,self->arg0,
        self->arg1,self->arg2,self->arg3,self->arg4,(int)arg0,self->code,(int)errno);
    */


    this->timestamp = walltimestamp / 1000000000;
    printf("{\"syscall\":\"%s\", \"args\":[%u, %u, %u, %u, %u], \"retval\":%d, \"errno\":%d, \"timestamp\":%d, \"pid\":%d}\n",
        probefunc,
        self->arg0, self->arg1,self->arg2,self->arg3,self->arg4,
        (int)arg0,
        (int)errno,
        this->timestamp, pid);

    OPT_stack ? ustack()    : 1;
    OPT_stack ? trace("\n") : 1;
    self->arg0 = 0;
    self->arg1 = 0;
    self->arg2 = 0;
    self->arg3 = 0;
    self->arg4 = 0;
 }

 /* mmap has 6 arguments */
 syscall::mmap:return
 /self->start/
 {
    /* calculate elapsed time */
    this->elapsed = timestamp - self->start;
    self->start = 0;
    this->cpu = vtimestamp - self->vstart;
    self->vstart = 0;
    self->code = errno == 0 ? "" : "Err#";

    /* print optional fields */
    /* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
    /*OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
    OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
    OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
    OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;*/

    /* print main data */
    /*
    printf("%s(0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X)\t\t = 0x%X %s%d\n",probefunc,self->arg0,
        self->arg1,self->arg2,self->arg3,self->arg4,self->arg5, arg0,self->code,(int)errno);
    */


    this->timestamp = walltimestamp / 1000000000;
    printf("{\"syscall\":\"%s\", \"args\":[%u, %u, %u, %u, %u, %u], \"retval\":%d, \"errno\":%d, \"timestamp\":%d, \"pid\":%d}\n",
        probefunc,
        self->arg0, self->arg1, self->arg2, self->arg3, self->arg4, self->arg5,
        (int)arg0,
        (int)errno,
        this->timestamp, pid);


    OPT_stack ? ustack()    : 1;
    OPT_stack ? trace("\n") : 1;
    self->arg0 = 0;
    self->arg1 = 0;
    self->arg2 = 0;
    self->arg3 = 0;
    self->arg4 = 0;
    self->arg5 = 0;
 }

 /* print 3 arg output - default */
 syscall:::return
 /self->start/
 {
    /* calculate elapsed time */
    this->elapsed = timestamp - self->start;
    self->start = 0;
    this->cpu = vtimestamp - self->vstart;
    self->vstart = 0;
    self->code = errno == 0 ? "" : "Err#";

    /* print optional fields */
    /* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
    /*OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
    OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
    OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
    OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;*/

    /* print main data */
    /*
    printf("%s(0x%X, 0x%X, 0x%X)\t\t = %d %s%d\n",probefunc,self->arg0,
        self->arg1,self->arg2,(int)arg0,self->code,(int)errno);
    */

    this->timestamp = walltimestamp / 1000000000;
    printf("{\"syscall\":\"%s\", \"args\":[%u, %u, %u], \"retval\":%d, \"errno\":%d, \"timestamp\":%d, \"pid\":%d}\n",
        probefunc,
        self->arg0, self->arg1, self->arg2,
        (int)arg0,
        (int)errno,
        this->timestamp, pid);

    OPT_stack ? ustack()    : 1;
    OPT_stack ? trace("\n") : 1;
    self->arg0 = 0;
    self->arg1 = 0;
    self->arg2 = 0;
 }

 profile:::tick-1sec
 /OPT_timeout && TIMEOUT > 0/
 {
     --TIMEOUT;
 }

 profile:::tick-1sec
 /OPT_timeout && TIMEOUT == 0/
 {
     exit(0);
 }

 /* print counts */
 dtrace:::END
 {
    OPT_counts == 1 ? printf("\n%-32s %16s\n","CALL","COUNT") : 1;
    OPT_counts == 1 ? printa("%-32s %@16d\n",@Counts) : 1;
    printf("## dtruss.sh done ##");
 }
'

### Run DTrace
#if [ $opt_command -eq 1 ]; then
#    /usr/sbin/dtrace -x dynvarsize=$buf -x evaltime=exec -n "$dtrace" \
#        -c "$command" >&2
#else
#    /usr/sbin/dtrace -x dynvarsize=$buf -n "$dtrace" >&2
#fi

### Run DTrace (Mac OS X)
if [ $opt_command -eq 1 ]; then
    sudo /usr/sbin/dtrace -x dynvarsize=$buf -x evaltime=exec -n "$dtrace" \
    -o "$output_file" -c "$command"
else
    sudo /usr/sbin/dtrace -x dynvarsize=$buf -n "$dtrace" >&2 -o "$output_file"
fi
