import random
import string
import os
import time
import subprocess

pwd = os.environ["PWD"]
src = pwd+"/src_dir/"
dst = pwd+"/dst_dir/"
rsync = "/usr/bin/rsync"
rsync_eBPF = "/usr/local/bin/rsync"
arguments = "  -aq --recursive --update -p -t "+src+" "+dst
time_no_eBPF = []
time_eBPF = []

def create_data():
    size_list = {0,64,512,4096}

    for size in size_list:
        all_chars = string.printable
        random_chars = ''.join(random.choice(all_chars) for _ in range(size))
        file_path = src+"/data_"+str(size)
        if not os.path.exists(file_path):
            with open(file_path, "w") as file:
                file.write(random_chars)

def exec(cmd,args):
    subprocess.run(cmd+args, shell=True, text=True)

def cleanup():
    subprocess.run("rm "+dst+"*", shell=True, text=True)
    
def proc():
    st=time.process_time()
    exec(rsync,arguments)
    et=time.process_time()
    res=et-st
#   print("CPU time without eBPF policies: ",res,'milliseconds')
    time_no_eBPF.append(res)
    cleanup()

    st=time.process_time()
    exec(rsync_eBPF,arguments)
    et=time.process_time()
    res=et-st
#   print("CPU time with eBPF policies: ",res,'milliseconds')
    time_eBPF.append(res)
    cleanup()


create_data()

for i in range(30):
    proc()

col_width=30
diff=[]
print("Without eBPF (ms)".ljust(col_width),"With eBPF (ms)".ljust(col_width),"Difference (ms)".ljust(col_width))
for t1,t2 in zip(time_no_eBPF,time_eBPF):
    diff.append(t2-t1)
    print(str(t1).ljust(col_width), str(t2).ljust(col_width),str(t2-t1).ljust(col_width))
print("Average overhead (ms): ",sum(diff))

