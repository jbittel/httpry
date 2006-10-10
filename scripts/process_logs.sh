#!/bin/sh

#
# process_logs.sh | created: 6/29/2005
#
# Am example shell script for orchestrating some of the included tools.
# This script stops the httpry daemon, moves the log file to a
# different directory, restarts httpry and then processes the new log
# file.
#
# Some error checking is performed, but is intentionally not extensive
# so as to not obfuscate the code. A production environment would
# probably want to augment this script.
#

# !!! Change these values to reflect your particular setup !!!

tools_dir=""                       # Change this to the location of the perl tool scripts
logs_dir=""                        # Change this to where you want to store your logs
log_fn="out.log"                   # Default file name for active log file
parse_fn="`date +%-m-%-d-%Y`.log"  # Default date format used by rotate_log.pl

# Generalized error sub; useful if you want to add file logging or somesuch
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
if [ -r "${logs_dir}/${parse_fn}" ] ; then
        perl ${tools_dir}/parse_log.pl -p ${tools_dir}/plugins ${logs_dir}/${parse_fn}
else
        if [ -n ${parse_fn} ] ; then
                die "File ${logs_dir}/${parse_fn} does not exist or is unreadable"
        else
                die "Parse file is not set"
        fi
fi
