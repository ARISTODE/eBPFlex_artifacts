from bcc import BPF
from ctypes import cast, POINTER, c_char

include_path = "-I/usr/include/"
def_path = "-I/usr/include/clang/10/include/"
b = BPF(src_file="prog.ebpf.c", cflags=["-O2", include_path, def_path], debug=0)

b.attach_uprobe(name="pcre2-8", sym="pcre2_match_data_create_8", fn_name="uprobe_pcre2_match_data_create_8")
b.attach_uretprobe(name="pcre2-8", sym="pcre2_match_data_create_8", fn_name="uretprobe_pcre2_match_data_create_8")
b.attach_uprobe(name="pcre2-8", sym="pcre2_match_data_free_8", fn_name="uprobe_pcre2_match_data_free_8")
b.attach_uretprobe(name="pcre2-8", sym="pcre2_match_data_free_8", fn_name="uretprobe_pcre2_match_data_free_8")
b.attach_uprobe(name="pcre2-8", sym="pcre2_get_ovector_pointer_8", fn_name="uprobe_pcre2_get_ovector_pointer_8")
b.attach_uretprobe(name="pcre2-8", sym="pcre2_get_ovector_pointer_8", fn_name="uretprobe_pcre2_get_ovector_pointer_8")
while True:
  try:
    b.trace_print()
  except KeyboardInterrupt:
    break
