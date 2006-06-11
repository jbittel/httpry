#!/bin/sh

#
# process_logs.sh | created: 6/29/2005
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

tools_dir=""  # Change this to the location of the perl tool scripts
logs_dir=""   # Change this to where you want to store your logs
email_addr="" # Email address used by parse_log.pl reports
content_fn="" # File name of content checks file; put in tools dir

# --------------------

log_fn="out.log"                  # Default file name for active log file
parse_fn="`date +%-m-%-d-%Y`.log" # This is the date format used by rotate_log.pl
out_fn="`date +%-m-%-d-%Y`"       # Use current date as base filename for output files

# Stop the httpry service if it is running
/etc/rc.d/rc.httpry stop

# Compress/move/purge log files
if [ -e "$tools_dir/$log_fn" ]; then
        perl $tools_dir/rotate_log.pl -ct -i $tools_dir/$log_fn -d $logs_dir
fi

# Restart the httpry service
/etc/rc.d/rc.httpry start

# Process new log file data; make sure appropriate plugins are
# enabled/disabled for parse_log.pl
if [ -e "$logs_dir/$parse_fn" ]; then
        perl $tools_dir/content_check.pl -e $email_addr -l $tools_dir/$content_fn -o $logs_dir/$out_fn-content.txt $logs_dir/$parse_fn
        perl $tools_dir/parse_log.pl -p $tools_dir/plugins $logs_dir/$parse_fn
fi
