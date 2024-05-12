import os
import subprocess
import time
import string

pwd=os.environ["PWD"]
config_file="/httpd.conf"
wrk="~/Research/wrk/wrk"
wrk_args=" -t4 -c20 -d60s http://localhost:5080"
apache="/usr/apache2/bin/apachectl"
apache_eBPF="sudo /usr/local/apache2/bin/apachectl"
apache_args=" -f "+pwd+config_file
apache_kill="sudo killall httpd"
log_clean='echo "" > '+pwd+'/logs/'

def exec(cmd,args):
    subprocess.run(cmd+args, shell=True, text=True)

def proc():
    #exec(apache,apache_args)
    #exec(wrk,wrk_args)
    #exec(log_clean,"access_log")
    #exec(log_clean,"error_log")
    
    exec(apache_kill,"")

    exec(apache_eBPF,apache_args)
    exec(wrk,wrk_args)
    exec(log_clean,"access_log")
    exec(log_clean,"error_log")

    exec(apache_kill,"")

times=1

for i in range(times):
    proc()
