from bcc import BPF
from ctypes import cast, POINTER, c_char

include_path = "-I/usr/include/"
def_path = "-I/usr/include/clang/10/include/"
b = BPF(src_file="prog.ebpf.c", cflags=["-O2", include_path, def_path], debug=0)

b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptSetExecPath", fn_name="uprobe_poptSetExecPath")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptSetExecPath", fn_name="uretprobe_poptSetExecPath")
b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptGetContext", fn_name="uprobe_poptGetContext")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptGetContext", fn_name="uretprobe_poptGetContext")
b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptResetContext", fn_name="uprobe_poptResetContext")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptResetContext", fn_name="uretprobe_poptResetContext")
b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="findProgramPath", fn_name="uprobe_findProgramPath")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="findProgramPath", fn_name="uretprobe_findProgramPath")
b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptSaveLong", fn_name="uprobe_poptSaveLong")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptSaveLong", fn_name="uretprobe_poptSaveLong")
b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptSaveInt", fn_name="uprobe_poptSaveInt")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptSaveInt", fn_name="uretprobe_poptSaveInt")
b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptGetNextOpt", fn_name="uprobe_poptGetNextOpt")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptGetNextOpt", fn_name="uretprobe_poptGetNextOpt")
b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptGetOptArg", fn_name="uprobe_poptGetOptArg")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptGetOptArg", fn_name="uretprobe_poptGetOptArg")
b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptGetArg", fn_name="uprobe_poptGetArg")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptGetArg", fn_name="uretprobe_poptGetArg")
b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptPeekArg", fn_name="uprobe_poptPeekArg")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptPeekArg", fn_name="uretprobe_poptPeekArg")
b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptGetArgs", fn_name="uprobe_poptGetArgs")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptGetArgs", fn_name="uretprobe_poptGetArgs")
b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptFreeContext", fn_name="uprobe_poptFreeContext")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptFreeContext", fn_name="uretprobe_poptFreeContext")
b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptAddAlias", fn_name="uprobe_poptAddAlias")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptAddAlias", fn_name="uretprobe_poptAddAlias")
b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptAddItem", fn_name="uprobe_poptAddItem")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptAddItem", fn_name="uretprobe_poptAddItem")
b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptBadOption", fn_name="uprobe_poptBadOption")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptBadOption", fn_name="uretprobe_poptBadOption")
b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptStrerror", fn_name="uprobe_poptStrerror")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptStrerror", fn_name="uretprobe_poptStrerror")
b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptStuffArgs", fn_name="uprobe_poptStuffArgs")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptStuffArgs", fn_name="uretprobe_poptStuffArgs")
b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptGetInvocationName", fn_name="uprobe_poptGetInvocationName")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptGetInvocationName", fn_name="uretprobe_poptGetInvocationName")
b.attach_uprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptStrippedArgv", fn_name="uprobe_poptStrippedArgv")
b.attach_uretprobe(name="/home/rrs5612/Research/rsync-3.3.0/tls", sym="poptStrippedArgv", fn_name="uretprobe_poptStrippedArgv")
while True:
  try:
    b.trace_print()
  except KeyboardInterrupt:
    break
