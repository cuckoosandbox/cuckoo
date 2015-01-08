import logging
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger import (ProcessExit, ProcessSignal, NewProcessEvent, ProcessExecution)
from ptrace.debugger.child import createChild
from ptrace.tools import locateProgram
from ptrace.func_call import FunctionCallOptions
from ptrace.ctypes_tools import formatAddress
from ptrace.error import PtraceError, PTRACE_ERRORS
from errno import EPERM
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from threading import Thread

log = logging.getLogger()

class MyHandler(FileSystemEventHandler):
    """ Logs all the events captured. """
    def on_moved(self, event):
        super(MyHandler, self).on_moved(event)

        what = 'directory' if event.is_directory else 'file'
        log.info("Moved %s: from %s to %s", what, event.src_path,
                     event.dest_path)

    def on_created(self, event):
        super(MyHandler, self).on_created(event)

        what = 'directory' if event.is_directory else 'file'
        log.info("Created %s: %s", what, event.src_path)

    def on_deleted(self, event):
        super(MyHandler, self).on_deleted(event)

        what = 'directory' if event.is_directory else 'file'
        log.info("Deleted %s: %s", what, event.src_path)

    def on_modified(self, event):
        super(MyHandler, self).on_modified(event)

        what = 'directory' if event.is_directory else 'file'
        log.info("Modified %s: %s", what, event.src_path)


class FilesystemTracer(Thread):
    """ File system tracer.
    
        File system tracer observes specific directories for several activities
        (create, delete, modify and move).
    """
     
    def __init__(self):
        """ Init thread, event handler and observer classes. 
            init some default paths to observe. 
        """
        Thread.__init__(self)
        log.debug('FilesystemTracer started.')
        self.directory_paths = [['/etc/',True],
                           ['/proc/sys', True],
                           ['/tmp', True],
                           ['/var/tmp', True]]
        self.event_handler = MyHandler()
        self.observer = Observer()
        
        self.prepare()
        
    def prepare(self):
        for path in self.directory_paths:
            log.debug('Monitoring %s, recursive=%s', path[0], path[1])
            self.observer.schedule(self.event_handler, str(path[0]), recursive=path[1])
        
    def run(self):
        """ Run Watchdog observer """
        self.observer.start()
        
    def stop(self):
        """ Stop observer. """
        self.observer.stop()
        
    def join(self):
        """ Wait for threads """
        self.observer.join()
        
    def add_directory(self,path,recursive=True):
        """ Add a directory to observer scheduler """
        log.debug('Monitoring %s, recursive=%s',path,recursive)
        #self.directory_paths.append([path,recursive])
        self.observer.schedule(self.event_handler, path, recursive)


class SyscallTracer(Thread):
    ''' Trace and control processes using (python)-ptrace '''
    def __init__(self, program):
        log.debug("SyscallTracer started.")
        Thread.__init__(self)
        self.program = program
        self.no_stdout = False
        self.received_kill = False
        
    def runDebugger(self):
        ''' init and run debugger '''
        # Set Options to trace fork and exec calls
        self.debugger.traceFork()
        self.debugger.traceExec()
        
        # Create traced process
        process = self.createProcess()
        if not process:
            return
        
        # Set syscall options (print options)
        self.syscall_options = FunctionCallOptions(
            write_types=False,
            write_argname=False,
            string_max_length=8192,
            replace_socketcall=True,
            write_address=False,
            max_array_count=100,
        )
        
        # Start process tracing
        self.syscallTrace(process)
    
    def syscallTrace(self, process):
        ''' Main process trace method '''
        # Break at first syscall
        # (https://github.com/qikon/python-ptrace/blob/master/ptrace/debugger/process.py)
        process.syscall()
        
        while not self.received_kill:
            # No process?
            if not self.debugger:
                break;
            
            try:
                event = self.debugger.waitSyscall()
                process = event.process
            except ProcessExit, event:
                state = event.process.syscall_state
                if (state.next_event == "exit") and state.syscall:
                    print("[%d] exit() : exit process" % event.process.pid)
                    self.debugger.deleteProcess(pid=event.process.pid)
                continue
            except ProcessSignal, event:
                print("*** SIGNAL pid=%s ***" % event.process.pid)
                event.display()
                event.process.syscall(event.signum)
                continue
            except NewProcessEvent, event:
                self.newProcess(event)
                continue
            except ProcessExecution, event:
                print("*** Process %s execution ***" % event.process.pid)
                event.process.syscall()
                continue
            
            self.get_syscall_str(process)
            # Break at next syscall
            process.syscall()
    
    def newProcess(self, event):
        ''' Event handler.
            Used to trace new child processes
        '''
        print("*** New process %s ***" % event.process.pid)
        event.process.syscall()
        event.process.parent.syscall()
        
    def createProcess(self):
        ''' create a process and add it to debugger '''
        print self.program
        pid = self.createChild(self.program)
        is_attached = True
        
        try:
            return self.debugger.addProcess(pid, is_attached)
        except (ProcessExit, PtraceError) as err:
            if isinstance(err, PtraceError) \
            and err.errno == EPERM:
                print "ERROR: You are not allowed to trace process %s (permission denied or process already traced)" % pid
            else:
                print "ERROR: Process can no be attached! %s" % err
        return None
    
    def createChild(self, program, env=None):
        ''' Fork a new child process '''
        pid = createChild(program, self.no_stdout, env)
        print "execve(%s, %s, [/* 40 vars */]) = %s" % (
            program[0], program, pid)
        return pid
    
    def run(self):
        ''' init and run debugger '''
        self.debugger = PtraceDebugger()
        try:
            self.runDebugger()
        except ProcessExit, event:
            self.processExited(event)
        except PtraceError, e:
            print "ptrace() error:", e
        except KeyboardInterrupt:
            print "Interrupted."
        except PTRACE_ERRORS, e:
            print "Debugger error:", e
        self.debugger.quit()

    def get_syscall_str(self, process):
        ''' Print catched syscalls '''
        state = process.syscall_state
        syscall = state.event(self.syscall_options)
        if syscall and (syscall.result is not None):
            name = syscall.name
            text = syscall.format()
            prefix = []
            prefix.append("[%s]" % process.pid)
            text = ''.join(prefix) + ' ' + text
            print text
        #else:
        #    return "" 


if __name__ == "__main__":
    try:      
        tracer = SyscallTracer(['test/fork',''])
        tracer.start()
            
    except KeyboardInterrupt:
        tracer.received_kill = True        