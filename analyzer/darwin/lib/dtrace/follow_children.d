/* apicalls.d
*
* Copyright (C) 2015 Dmitry Rodionov
* This software may be modified and distributed under the terms
* of the MIT license. See the LICENSE file for details.
*
*
* Usage:
*  1) `SCRIPT_NAME` and `OUTPUT_FILE` macros must be set in a master script;
*  2) Global integer variable `countdown` must exist;
*/

/* Preprocessor magic: stringification */
#define str(s) str0(s)
#define str0(s) #s
/* Since there's no built-in way to get an output file of the current script,
* we have to inject it into the source code with preprocessor. */
#if !defined(OUTPUT_FILE)
#error Please, specify the output file (e.g. "-DOUTPUT_FILE=./foo.log")
#endif

#ifdef CHILD
dtrace:::BEGIN
{
    pidresume($target);
#ifdef WAS_EXECED
    /* Since (1) we have now dtrace scripts attached to both
    * parent and child processes and (2) they both have *the same* PID,
    * we'll get the same results from both these scripts.
    * To fix this, I just stop tracing the child here. */
    exit(0);
#endif /* WAS_EXECED */
}

/* TODO(rodionovd): it looks like there's a bug in Apple dtrace that keeps
* dtrace running even when its target (specified via -p) was already terminated.
* Maybe I'm doing something wrong, but here's a temporary workaround.
*/
syscall::exit:entry
/ pid == $target/
{
    exit(0);
}
#endif /* CHILD */

/* FORK */
proc:::create
/ pid == $target /
{
    tracked[args[0]->pr_pid] = 1;
}

/* Attach a new instance of dtrace to the new child process.
 * Note that we pause the process before attaching dtrace to it, so we'll even
 * catch short-lived ones.
 */
proc:::start
/ tracked[pid] == 1 /
{
    tracked[pid] = 0;
    stop();
    system("sudo dtrace -Z -I./ -C -DCHILD=1 -DANALYSIS_TIMEOUT=%d -DSCRIPT_PATH=./%s -DOUTPUT_FILE=%s -s ./%s -o %s -p %d &",
    countdown, SCRIPT_NAME, str(OUTPUT_FILE), SCRIPT_NAME, str(OUTPUT_FILE), pid);
}

/* EXEC */
proc:::exec
/ pid == $target /
{
    tracked[pid] = 2;
}

/* Well, we were exec*(), now what?
 * Since a new image does contain different symbols and also may require different
 * shared libraries -- and we really want to be able to install probes on them -- we
 * must re-attach dtrace to this process again so it can see these new stuff.
 *
 * We wait some time to make sure that all shared libraries are loaded, stop()
 * (actually, pause) the process and then spawn a new instance of dtrace attached
 * to this process.
 * Why start64("/AppleInternal")? This syscall happens at the end of a programm
 * initialization process, so it's a great place to do our thing.
 */
syscall::stat64:entry
/ tracked[pid] == 2 && copyinstr(arg0) == "/AppleInternal\0" /
{
    tracked[pid] = 0;
    stop();
    system("sudo dtrace -Z -I./ -C -DCHILD=1 -DWAS_EXECED=1 -DANALYSIS_TIMEOUT=%d -DSCRIPT_PATH=./%s -DOUTPUT_FILE=%s -s ./%s -o %s -p %d &",
    countdown, SCRIPT_NAME, str(OUTPUT_FILE), SCRIPT_NAME, str(OUTPUT_FILE), pid);
}

dtrace:::END
{
#ifdef TOPLEVELSCRIPT
    system("sleep 1.5 && echo \"## %s done ##\" >> \"%s\"", SCRIPT_NAME, str(OUTPUT_FILE));
#endif
}
