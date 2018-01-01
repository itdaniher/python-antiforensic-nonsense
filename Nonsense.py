# (c) Ian Daniher 2017
# released under 3-Clause BSD License
# see LICENSE
import ctypes
import os
import sys
import signal
import time

PR_SET_PDEATHSIG = 0
PR_SET_DUMPABLE = 4
PR_SET_NAME = 15
PR_GET_NAME = 16
PR_SET_PTRACER = 0x59616d61
PTRACE_CONT = 7
PTRACE_ATTACH = 16
PTRACE_DETACH = 17


class Nonsense:

    def __init__(self):
        self.libc = ctypes.cdll.LoadLibrary(None)
        self.pid = os.getpid()
        self.ppid = os.getppid()
        os.unsetenv('LD_PRELOAD')
        os.unsetenv('LD_LIBRARY_PATH')

    def get_procname(self):
        argv = ctypes.POINTER(ctypes.c_char_p)()
        argc = ctypes.c_int()
        ctypes.pythonapi.Py_GetArgcArgv(ctypes.byref(argc), ctypes.byref(argv))
        return argv.contents.value

    def set_procname(self, cmdline):
        argv = ctypes.POINTER(ctypes.c_char_p)()
        argc = ctypes.c_int()
        ctypes.pythonapi.Py_GetArgcArgv(ctypes.byref(argc), ctypes.byref(argv))
        cmdlen = sum([len(argv[i]) for i in range(0, argc.value)
                      ]) + argc.value
        new_cmdline = ctypes.c_char_p(cmdline.ljust(cmdlen, '\0').encode())
        self.libc.memcpy(argv.contents, new_cmdline, cmdlen)
        self.libc.prctl(PR_SET_NAME, new_cmdline, 0, 0, 0)
        return self

    def no_dump(self):
        self.libc.prctl(PR_SET_DUMPABLE, 0)
        return self

    def no_traceback(self):
        sys.tracebacklimit = 0
        return self

    def is_alive(self, pid):
        try:
            os.kill(pid, 0)
            return True
        except:
            return False

    def no_signal(self):
        sh = lambda signal, frame: 0
        signal.signal(signal.SIGINT, sh)
        signal.signal(signal.SIGHUP, sh)
        signal.signal(signal.SIGTERM, sh)
        signal.signal(signal.SIGQUIT, sh)
        return self

    def no_strace(self):
        def go_ahead():
            while True:
                try:
                    os.waitpid(self.pid, 0)
                except:
                    os._exit(1)
                self.libc.ptrace(PTRACE_CONT, self.pid, 0, 0)

        def attach_parent():
            r = self.libc.ptrace(PTRACE_ATTACH, self.pid) + 1
            if not r:
                if self.is_alive(self.ppid):
                    os.kill(self.ppid, signal.SIGKILL)
                    while self.libc.ptrace(PTRACE_ATTACH, self.pid) == -1:
                        pass
                    go_ahead()
            else:
                self.no_dump()
                go_ahead()

        self.libc.prctl(PR_SET_PTRACER, self.pid)
        if not os.fork():
            attach_parent()
        return self


harden = lambda: Nonsense().no_strace().no_traceback().no_signal()

def test():
    D = harden().set_procname('yolo')
    for i in range(10):
        sys.stdout.write("%d, %d\n" % (i, os.getpid()))
        time.sleep(2)

if __name__ == "__main__":
    test()
