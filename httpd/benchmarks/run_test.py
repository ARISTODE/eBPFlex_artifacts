import os
import subprocess
import time
import string

pwd=os.environ["PWD"]
config_file="/lhttpd.conf"
wrk="~/Research/wrk/wrk"
wrk_args=" -t3 -c20 -d20s http://localhost:5080"
#apache="sudo /usr/local/apache2/bin/apachectl"
apache="sudo ~/Research/httpd-2.4.59/httpd"
#apache_eBPF="sudo /usr/local/apache2/bin/apachectl"
apache_eBPF="sudo ~/Research/httpd-2.4.59/httpd"
apache_args=" -f "+pwd+config_file
apache_kill="sudo killall httpd"
log_clean='rm '+pwd+'/logs/'

def exec(cmd,args):
    subprocess.run(cmd+args, shell=True, text=True)

def proc():
    input("Without eBPF (press enter): \n")
    exec(apache,apache_args)
    exec(wrk,wrk_args)
    exec(log_clean,"access_log")
#    exec(log_clean,"error_log")
    exec(apache_kill,"")

    input("With eBPF (press enter after attaching probes): \n")

    exec(apache_eBPF,apache_args)
    exec(wrk,wrk_args)
    exec(log_clean,"access_log")
 #   exec(log_clean,"error_log")
    exec(apache_kill,"")

times=1

for i in range(times):
    proc()
