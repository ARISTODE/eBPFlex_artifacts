import random
import string
import os
import time
import subprocess

pwd = os.environ["PWD"]
src = pwd+"/src_dir/"
#dst = pwd+"/dst_dir/"
tls = "~/Research/rsync-3.3.0-og/tls"
tls_eBPF = "~/Research/rsync-3.3.0/tls"
arguments = " -U -l -L -f "+src+" > /dev/null"
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
    exec(tls,arguments)
    et=time.process_time()
    res=et-st
    time_no_eBPF.append(res)

    st=time.process_time()
    exec(tls_eBPF,arguments)
    et=time.process_time()
    res=et-st
    time_eBPF.append(res)


create_data()
times=30
for i in range(times):
    proc()

col_width=30
diff=[]
print("Without eBPF (ms)".ljust(col_width),"With eBPF (ms)".ljust(col_width),"Difference (ms)".ljust(col_width))
for t1,t2 in zip(time_no_eBPF,time_eBPF):
    diff.append(t2-t1)
    print(str(t1).ljust(col_width), str(t2).ljust(col_width),str(t2-t1).ljust(col_width))
print("Average overhead (ms): ",sum(diff))

