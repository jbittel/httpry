#!/bin/sh

#
# process_logs.sh 6/29/2005
#
# Copyright (c) 2005, Jason Bittel. All rights reserved.
# See included LICENSE file for specific licensing information
#
# Example shell script for orchestrating the included tools. This
# is designed to stop the httpry service, move the log file to a
# different directory, restart httpry and then process the new log
# file. This demonstrates the majority of the functionality included
# in these different tools, and should help in modifying them to
# your particular use.  Note that this file is merely an example of
# how to automate this process; most of these programs have additional
# options that are not shown here.
#

# --------------------
# --- MODIFY THESE ---
# --------------------
# Change these values to reflect your particular setup.

tools_dir=""  # Change this to the location of the perl tool scripts
logs_dir=""   # Change this to where you want to store your logs
email_addr="" # Email address used by parse_log.pl reports
user=""       # User to run httpry as
group=""      # Group of the above user

# --------------------

log_fn="out.log"                  # Default file name for active log file
offense_fn="offensive.txt"        # File name of content checks file; put in tools dir
parse_fn="`date +%-m-%-d-%Y`.log" # This is the default format used by rotate_log.pl

# Stop the httpry service if it is running
if [ -e "/var/run/httpry.pid" ]; then
        kill `cat /var/run/httpry.pid`
else
        killall httpry
fi

# Compress/move/purge log files
if [ -e "$tools_dir/$log_fn" ]; then
        perl $tools_dir/rotate_log.pl -c -t -i $logs_dir/$log_fn -d $logs_dir
fi

# Start the httpry service
httpry -d -u $user -o $logs_dir/$log_fn

# Process new log file data
if [ -e "$logs_dir/$parse_fn" ]; then
        perl $tools_dir/parse_log.pl -s -l $tools_dir/$offense_fn -o $logs_dir/$parse_fn.txt -c 20 -e $email_addr $logs_dir/$parse_fn
fi

# Change ownership of logs directory.
chown $user:$group $logs_dir/*
