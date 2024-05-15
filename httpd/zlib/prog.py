from bcc import BPF
from ctypes import cast, POINTER, c_char

include_path = "-I/usr/include/"
def_path = "-I/usr/include/clang/10/include/"
b = BPF(src_file="prog.ebpf.c", cflags=["-O2", include_path, def_path], debug=0)

#b.attach_uprobe(name="/home/rrs5612/Research/zlib-1.3/libz.so", sym="deflateInit2_", fn_name="uprobe_deflateInit2_")
#b.attach_uretprobe(name="/home/rrs5612/Research/zlib-1.3/libz.so", sym="deflateInit2_", fn_name="uretprobe_deflateInit2_")
b.attach_uprobe(name="/home/rrs5612/Research/zlib-1.3/lib/libz.so", sym="deflateEnd", fn_name="uprobe_deflateEnd")
b.attach_uretprobe(name="/home/rrs5612/Research/zlib-1.3/lib/libz.so", sym="deflateEnd", fn_name="uretprobe_deflateEnd")
b.attach_uprobe(name="/home/rrs5612/Research/zlib-1.3/lib/libz.so", sym="deflate", fn_name="uprobe_deflate")
b.attach_uretprobe(name="/home/rrs5612/Research/zlib-1.3/lib/libz.so", sym="deflate", fn_name="uretprobe_deflate")
while True:
  try:
    b.trace_print()
  except KeyboardInterrupt:
    break
