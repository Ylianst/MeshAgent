#!/usr/bin/env python3
"""Compile the production POSIX signal listener and verify fork isolation."""
from pathlib import Path
import subprocess,tempfile
source=(Path(__file__).resolve().parents[1]/'microscript/ILibDuktape_ScriptContainer.c').read_text()
start=source.index('void ILibDuktape_ScriptContainer_Process_SignalListener(int signum,')
end=source.index('\n#endif',start)
with tempfile.TemporaryDirectory() as directory:
    c=Path(directory)/'signal.c'; binary=Path(directory)/'signal-test'
    c.write_text('#define _GNU_SOURCE\n#include <signal.h>\n#include <unistd.h>\n#include <fcntl.h>\n#include <sys/wait.h>\n#include <poll.h>\n#include <stdio.h>\n#include <stdlib.h>\nint SignalDescriptors[2];\npid_t SignalDescriptorsOwner;\n#define ignore_result(x) ((void)(x))\n'+source[start:end]+'\nint main(void) {\n pipe(SignalDescriptors); SignalDescriptorsOwner=getpid();\n struct sigaction sa={0}; sa.sa_sigaction=ILibDuktape_ScriptContainer_Process_SignalListener;\n sa.sa_flags=SA_SIGINFO; sigaction(SIGTERM,&sa,0);\n pid_t child=fork();\n if(child==0){raise(SIGTERM);_exit(0);}\n waitpid(child,0,0);\n struct pollfd fd={SignalDescriptors[0],POLLIN,0};\n int forwarded=poll(&fd,1,30)>0;\n if(forwarded){int b[2];read(SignalDescriptors[0],b,sizeof(b));}\n raise(SIGTERM); fd.revents=0;\n int own=poll(&fd,1,30)>0;\n printf("child_forwarded=%d parent_signal_delivered=%d\\n",forwarded,own);\n return forwarded||!own;\n}\n')
    subprocess.run(['cc','-Wall','-Wextra','-o',str(binary),str(c)],check=True)
    subprocess.run([str(binary)],check=True)
