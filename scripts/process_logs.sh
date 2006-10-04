#!/bin/sh

#
# process_logs.sh | created: 6/29/2005
#
# Example shell script for orchestrating the included tools. This
# is designed to stop the httpry service, move the log file to a
# different directory, restart httpry and then process the new log
# file. This demonstrates the majority of the functionality included
# in these different tools, and should help in modifying them to
# your particular use.
#

# !!! Change these values to reflect your particular setup !!!

tools_dir=""      # Change this to the location of the perl tool scripts
logs_dir=""       # Change this to where you want to store your logs
log_fn="out.log"  # Default file name for active log file


die() {
        if [ -n "${1}" ] ; then
                echo "Error: ${1}" >&2
        fi

        exit 1
}

if [ ! -d "${tools_dir}" ] ; then
        die "Tools directory is not set or is invalid"
fi
if [ ! -d "${logs_dir}" ] ; then
        die "Log file directory is not set or is invalid"
fi
if [ ! -r "${tools_dir}/${log_fn}" ] ; then
        die "Log file does not exist or is unreadable"
fi

# Stop the httpry service if it is running
/etc/rc.d/rc.httpry stop

# Compress/move/purge log files
perl ${tools_dir}/rotate_log.pl -ct -i ${tools_dir}/${log_fn} -d ${logs_dir}

# Restart the httpry service
/etc/rc.d/rc.httpry start

# Process new log file data; make sure appropriate plugins are
# enabled/disabled for parse_log.pl
if [ `ls -l ${logs_dir}/*.log | wc -l` -gt "0" ] ; then
        perl ${tools_dir}/parse_log.pl -p ${tools_dir}/plugins ${logs_dir}/*.log
else
        die "No log files found in ${logs_dir}"
fi
