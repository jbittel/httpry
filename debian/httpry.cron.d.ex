#
# Regular cron jobs for the httpry package
#
0 4	* * *	root	[ -x /usr/bin/httpry_maintenance ] && /usr/bin/httpry_maintenance
