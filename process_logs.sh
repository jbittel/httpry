#!/bin/sh

# process_logs.sh 6/29/2005 #

# Copyright (c) 2005, Corban College. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the College nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COLLEGE OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

log_fn="out.log"
offense_fn="offensive.txt"
base_dir="/home/jbittel/httpry"
logs_dir="/home/jbittel/httpry/logs"
parse_fn="`date +%-m-%-d-%Y`.log"
email_addr="jasonbittel@corban.edu"
user="jbittel"
group="users"

# Stop the HTTPry service if it is running
if [ -e "/var/run/httpry.pid" ]; then
        echo "`date` Stopping HTTPry service" > httpry.log
        kill `cat /var/run/httpry.pid`
fi

sleep 1

if [ `ps -e | grep httpry` ]; then
        echo "`date` HTTPry service not stopped, forcing kill" >> httpry.log
        killall -9 httpry
fi

# Compress/move/purge log files
if [ -e "$base_dir/$log_fn" ]; then
        echo "`date` Rotating log file" >> httpry.log
        perl $base_dir/rotate_log.pl -c -t -i $base_dir/$log_fn -d $logs_dir
fi

# Start the HTTPry service
echo "`date` Starting HTTPry service" >> httpry.log
$base_dir/httpry -d -o $base_dir/$log_fn

# Process new log file data
if [ -e "$logs_dir/$parse_fn" ]; then
        echo "`date` Parsing new logfile(s)" >> httpry.log
        perl $base_dir/parse_log.pl -fs -l $base_dir/$offense_fn -o $logs_dir/$parse_fn.txt -c 20 -e $email_addr $logs_dir/$parse_fn
fi

# Change ownership of logs directory
chown $user:$group $logs_dir/*
