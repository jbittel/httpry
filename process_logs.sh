#!/bin/sh

#
# process_logs.sh 6/29/2005
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
# Change these values to reflect your particular setup. If you do not
# provide an option here, be sure to remove that parameter in the script
# below.

tools_dir=""     # Change this to the location of the perl tool scripts
logs_dir=""      # Change this to where you want to store your logs
email_addr=""    # Email address used by parse_log.pl reports
content_fn=""    # File name of content checks file; put in tools dir
config_file=""   # Path to httpry config file

# --------------------

log_fn="out.log"                  # Default file name for active log file
parse_fn="`date +%-m-%-d-%Y`.log" # This is the date format used by rotate_log.pl
out_fn="`date +%-m-%-d-%Y`"       # Use current date as base filename for output files

# Stop the httpry service if it is running
if [ -r "/var/run/httpry.pid" ]; then
        kill `cat /var/run/httpry.pid`
else
        killall httpry
fi

# Compress/move/purge log files
if [ -e "$tools_dir/$log_fn" ]; then
        perl $tools_dir/rotate_log.pl -ct -i $logs_dir/$log_fn -d $logs_dir
fi


# Restart the httpry service
if [ -e "/var/run/httpry.pid" ]; then
        rm -rf /var/run/httpry.pid
fi
httpry -c $config_file

# Process new log file data
if [ -e "$logs_dir/$parse_fn" ]; then
        perl $tools_dir/parse_log.pl -s -o $logs_dir/$out_fn-log.txt -c 20 -e $email_addr $logs_dir/$parse_fn
        perl $tools_dir/trace_flows.pl -m -o $logs_dir/$parse_fn.flows $logs_dir/$parse_fn
        perl $tools_dir/parse_flows.pl -sx -l $tools_dir/$content_fn -d $logs_dir -o $logs_dir/$out_fn-flow.txt -e $email_addr $logs_dir/$parse_fn.flows
fi
