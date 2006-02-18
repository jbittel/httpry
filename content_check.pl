#!/usr/bin/perl -w

#
# content_check.pl 2/16/2006
#
# Copyright (c) 2005, Jason Bittel <jbittel@corban.edu>. All rights reserved.
# See included LICENSE file for specific licensing information
#

use strict;
use Getopt::Std;
use File::Basename;
use MIME::Lite;
use Socket qw(inet_ntoa inet_aton);
use Time::Local qw(timelocal);
#use IO::File;
#use POSIX qw(tmpnam);

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PATTERN = "\t";
my $PROG_NAME = "content_check.pl";
my $PROG_VER = "0.0.1";
my $SENDMAIL = "/usr/lib/sendmail -i -t";
my $FLOW_TIMEOUT = 300;
my $FLOW_DISCARD = 10;
my $TAGGED_LIMIT = 5;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %opts = ();
my @input_files = ();
my $host_detail;
my $email_addr;
my $hitlist_file;
my $output_file;
my $flows_summary;
#my $temp_file;
#my $temp_fh;
#my $temp_name;

# Counter variables
my $file_cnt = 0;
my $size_cnt = 0;
my $total_line_cnt = 0;
my $flow_cnt = 0;
my $flow_line_cnt = 0;
my $flow_min_len = 999999;
my $flow_max_len = 0;
my $tagged_flows_cnt = 0;
my $total_tagged_lines_cnt = 0;

# Data structures
my %flow_info = ();             # Holds metadata about each flow
my %flow_data_lines = ();       # Holds actual data lines for each flow
my %flow_hits = ();             # Flow data lines for tagged flows
my %hostname_hits = ();         # Individual hostnames tagged within tagged flows
my @hitlist = ();
my @host_data = ();

# -----------------------------------------------------------------------------
# Main Program
# -----------------------------------------------------------------------------
&get_arguments();

# Create temp file
#do { $temp_name = tmpnam() }
#        until $temp_file = IO::File->new($temp_name, O_RDWR|O_CREAT|O_EXCL);
#END { unlink($temp_file) || die "Error: couldn't unlink '$temp_file': $!" }
#$temp_fh = IO::File->new_tmpfile || die "Error: unable to make new temporary file: $!";

&trace_flows();

#seek($temp_fh, 0, 0) || die "Error: unable to rewind temporary file: $!";

#&parse_flows();
&write_summary_file() if $flows_summary;
&send_email() if $email_addr;

# -----------------------------------------------------------------------------
#
# -----------------------------------------------------------------------------
sub trace_flows {
        my $curr_line;
        my $curr_file;
        my $key;
        my ($timestamp, $epochstamp, $src_ip, $dst_ip, $hostname, $uri);

        foreach $curr_file (@input_files) {
                unless(open(INFILE, "$curr_file")) {
                        print "\nWarning: Cannot open $curr_file - $!\n";
                        print "           Skipping that particular file...\n";
                        next;
                }

                $file_cnt++;
                $size_cnt += int((stat(INFILE))[7] / 1000000);

                foreach $curr_line (<INFILE>) {
                        chomp $curr_line;
                        $curr_line =~ tr/\x80-\xFF//d; # Strip non-printable chars

                        # Convert hex characters to ASCII
                        $curr_line =~ s/%25/%/g; # Sometimes '%' chars are double encoded
                        $curr_line =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
                        next if $curr_line eq "";
                        $total_line_cnt++;
                        
                        ($timestamp, $src_ip, $dst_ip, $hostname, $uri) = split(/$PATTERN/, $curr_line);

                        # Convert timestamp of current record to epoch seconds
                        $timestamp =~ /(\d\d)\/(\d\d)\/(\d\d\d\d) (\d\d)\:(\d\d)\:(\d\d)/;
                        $epochstamp = timelocal($6, $5, $4, $2, $1 - 1, $3);

                        if (!exists $flow_info{$src_ip}) {
                                $flow_cnt++;
                                $flow_line_cnt++;
                                
                                $flow_info{$src_ip}->{"src_ip"} = $src_ip;
                                $flow_info{$src_ip}->{"start_time"} = $timestamp;
                                $flow_info{$src_ip}->{"end_time"} = $timestamp;
                                $flow_info{$src_ip}->{"start_epoch"} = $epochstamp;
                                $flow_info{$src_ip}->{"end_epoch"} = $epochstamp;
                                $flow_info{$src_ip}->{"length"} = 1;
                                $flow_info{$src_ip}->{"tagged_lines"} = 0;

                                push(@{$flow_data_lines{$src_ip}}, $curr_line);

                                if ($hitlist_file && &content_check($hostname, $uri)) {
                                        $hostname_hits{$src_ip}->{$hostname}++; # TODO: switch this to a per host/flow unique key
                                        $flow_info{$src_ip}->{"tagged_lines"}++;
                                }
                        } else {
                                $flow_line_cnt++;
                                
                                $flow_info{$src_ip}->{"end_time"} = $timestamp;
                                $flow_info{$src_ip}->{"end_epoch"} = $epochstamp;
                                $flow_info{$src_ip}->{"length"}++;

                                push(@{$flow_data_lines{$src_ip}}, $curr_line);

                                if ($hitlist_file && &content_check($hostname, $uri)) {
                                        $hostname_hits{$src_ip}->{$hostname}++; # TODO: switch this to a per host/flow unique key
                                        $flow_info{$src_ip}->{"tagged_lines"}++;
                                }
                        }

                        # Timeout old flows
                        foreach $key (keys %flow_info) {
                                next if (($epochstamp - $flow_info{$key}->{"end_epoch"}) > $FLOW_TIMEOUT);

                                # Set minimum/maximum flow length
                                if ($flow_info{$key}->{"length"} < $flow_min_len) {
                                        $flow_min_len = $flow_info{$key}->{"length"};
                                }
                                if ($flow_info{$key}->{"length"} > $flow_max_len) {
                                        $flow_max_len = $flow_info{$key}->{"length"};
                                }
                                        
                                if ($flow_info{$key}->{"tagged_lines"} > $TAGGED_LIMIT) {
                                        $tagged_flows_cnt++;
                                        $total_tagged_lines_cnt += $flow_info{$key}->{"tagged_lines"};

                                        &append_host_subfile("$host_detail/detail_$key.txt") if $host_detail;

                                        push(@{$flow_hits{$key}}, "[" . $flow_info{$key}->{"start_time"} . "]->[" . \
                                                $flow_info{$key}->{"end_time"} . "]\t" . $flow_info{$key}->{"tagged_lines"} . \
                                                "/" . $flow_info{$key}->{"length"} . "\t" . \
                                                percent_of($flow_info{$key}->{"tagged_lines"}, $flow_info{$key}->{"length"}) . "%");
                                }
                                        
                                &timeout_flow($key);
                        }
                }
        }

        return;
}

# -----------------------------------------------------------------------------
# Core parsing engine, processes all input files based on options provided
# -----------------------------------------------------------------------------
#sub parse_flows {
#        my $curr_line;
#        my $curr_file;
#        my ($timestamp, $src_ip, $dst_ip, $hostname, $uri);
#        my ($ip, $flow_len, $flow_start, $flow_end, $tagged_lines); # Flow detail information
#
#        #open(INFILE, "$temp_file") || die "\nError: Cannot open $temp_file: $!\n";
#
#        foreach $curr_line (<$temp_fh>) {
#                chomp $curr_line;
#                next if $curr_line eq "";
#
#                if ($curr_line =~ /^>>> (.*)!(.*)!(.*)!(.*) >/) { # Start of flow marker + metadata
#                        $ip = $1;
#                        $flow_len = $2;
#                        $flow_start = $3;
#                        $flow_end = $4;
#
#                        # Set up variables for new flow
#                        @host_data = ();
#                        $tagged_lines = 0;
#                        $flow_cnt++;
#                        $flow_line_cnt += $flow_len;
#
#                        # Set minimum/maximum flow length
#                        if ($flow_len < $flow_min_len) {
#                                $flow_min_len = $flow_len;
#                        }
#                        if ($flow_len > $flow_max_len) {
#                                $flow_max_len = $flow_len;
#                        }
#                } elsif ($curr_line =~ /^<<</) { # End of flow marker
#                        if ($tagged_lines > $TAGGED_LIMIT) {
#                                $tagged_flows_cnt++;
#                                $total_tagged_lines_cnt += $tagged_lines;
#
#                                &write_host_subfile("$host_detail/detail_$ip.txt") if $host_detail;
#                                push(@{$flow_hits{$ip}}, "[$flow_start]->[$flow_end]\t$tagged_lines/$flow_len\t".percent_of($tagged_lines, $flow_len)."%");
#                        }
#                } else { # Flow data line
#                        push(@host_data, $curr_line);
#
#                        if ($hitlist_file) {
#                                ($timestamp, $src_ip, $dst_ip, $hostname, $uri) = split(/$PATTERN/, $curr_line);
#
#                                if (&content_check($hostname, $uri)) {
#                                                $hostname_hits{$ip}->{$hostname}++;
#                                                $tagged_lines++;
#                                }
#                        }
#                }
#
#                #close(INFILE);
#        }
#}

# -----------------------------------------------------------------------------
# Search fields for specified content; returns true if match occurs
# -----------------------------------------------------------------------------
sub content_check {
        my $hostname = shift;
        my $uri = shift;
        my $word;

        $hostname = quotemeta($hostname);
        $uri = quotemeta($uri);
        foreach $word (@hitlist) {
                chomp $word;
                if (($hostname =~ /$word/i) || ($uri =~ /$word/i)) {
                        return 1;
                }
        }

        return 0;
}

# -----------------------------------------------------------------------------
# Write detail subfile for specified client ip
# -----------------------------------------------------------------------------
sub append_host_subfile {
        my $path = shift;

        open(HOSTFILE, ">>$path") || die "\nError: cannot open $path - $!\n";

        print HOSTFILE '>' x 80 . "\n";
        foreach (@host_data) {
                print HOSTFILE "$_\n";
        }
        print HOSTFILE '<' x 80 . "\n";

        close(HOSTFILE);
}

# -----------------------------------------------------------------------------
# Handle end of flow duties: flush to disk and delete hash entry
# -----------------------------------------------------------------------------
sub timeout_flow {
        my $flow_key = shift;

        # Discard brief flows
        if ($flow_info{$flow_key}->{'length'} <= $FLOW_DISCARD) {
                delete $flow_info{$flow_key};
                delete $flow_data_lines{$flow_key};

                return;
        }

        # TODO: move flow_hits appending here

        #&print_flow($flow_key);

        delete $flow_info{$flow_key};
        delete $flow_data_lines{$flow_key};
}

# -----------------------------------------------------------------------------
# Print flow to output file along with start/end markers
# -----------------------------------------------------------------------------
#sub print_flow {
#        my $flow_key = shift;
#        my $line;
#        my $metadata;
#
#        #open(OUTFILE, ">>$temp_file") || die "\nError: cannot open $temp_file - $!\n";
#
#        # Print flow header line
#        $metadata = sprintf("%s!%d!%s!%s", $flow_info{$flow_key}->{'src_ip'},
#                                           $flow_info{$flow_key}->{'length'},
#                                           $flow_info{$flow_key}->{'start_time'},
#                                           $flow_info{$flow_key}->{'end_time'});
#        print $temp_fh ">>> $metadata " . '>' x (75 - length($metadata)) . "\n";
#
#        # Print flow data lines
#        foreach $line ( @{$flow_data_lines{$flow_key}} ) {
#                print $temp_fh "$line\n";
#        }
#
#        # Print flow footer line
#        print $temp_fh '<' x 80 . "\n";
#
#        #close(OUTFILE);
#}

# -----------------------------------------------------------------------------
# Write summary information to specified output file
# -----------------------------------------------------------------------------
sub write_summary_file {
        my $key;
        my $flow;
        my $hostname;

        open(OUTFILE, ">$output_file") || die "\nError: Cannot open $output_file - $!\n";

        print OUTFILE "\n\nSUMMARY STATS\n\n";
        print OUTFILE "Generated:\t" . localtime() . "\n";
        print OUTFILE "Total files:\t$file_cnt\n";
        print OUTFILE "Total size:\t$size_cnt MB\n";
        print OUTFILE "Total lines:\t$total_line_cnt\n";

        print OUTFILE "\n\nFLOW STATS\n\n";
        print OUTFILE "Flow count:\t$flow_cnt\n";
        print OUTFILE "Flow lines:\t$flow_line_cnt\n";
        print OUTFILE "Min/Max/Avg:\t$flow_min_len/$flow_max_len/".sprintf("%d", $flow_line_cnt / $flow_cnt)."\n";

        if ($hitlist_file) {
                print OUTFILE "Tagged IPs:\t".(keys %flow_hits)."\n";
                print OUTFILE "Tagged flows:\t$tagged_flows_cnt\n";
                print OUTFILE "Tagged lines:\t$total_tagged_lines_cnt\n";
                print OUTFILE "\n\nFLOW CONTENT CHECKS\n";
                print OUTFILE "FILTER FILE: $hitlist_file\n\n";

                if ($total_tagged_lines_cnt > 0) {
                        foreach $key (map { inet_ntoa $_ }
                                      sort
                                      map { inet_aton $_ } keys %flow_hits) {
                                print OUTFILE "$key\n";
                                foreach $flow (@{$flow_hits{$key}}) {
                                        print OUTFILE "\t$flow\n";
                                        
                                        foreach $hostname (sort keys %{ $hostname_hits{$key} }) {
                                                print OUTFILE "\t\t$hostname\t$hostname_hits{$key}->{$hostname}\n";
                                        }
                                }
                                print OUTFILE "\n";
                        }
                } else {
                        print OUTFILE "No tagged flows found\n";
                }
        }

        close(OUTFILE);
}

# -----------------------------------------------------------------------------
# Send email to specified address and attach output file
# -----------------------------------------------------------------------------
sub send_email {
        my $msg;
        my $output_filename = basename($output_file);

        $msg = MIME::Lite->new(
                From    => 'admin@corban.edu',
                To      => "$email_addr",
                Subject => 'HTTPry Content Check Report - ' . localtime(),
                Type    => 'multipart/mixed'
                );

        $msg->attach(
                Type => 'TEXT',
                Data => 'HTTPry content check report for ' . localtime()
                );

        $msg->attach(
                Type        => 'TEXT',
                Path        => "$output_file",
                Filename    => "$output_filename",
                Disposition => 'attachment'
                );

        $msg->send('sendmail', $SENDMAIL) || die "\nError: Cannot send mail: $!\n";
}

# -----------------------------------------------------------------------------
# Retrieve and process command line arguments
# -----------------------------------------------------------------------------
sub get_arguments {
        getopts('d:e:l:o:s', \%opts) or &print_usage();

        # Print help/usage information to the screen if necessary
        &print_usage() if ($opts{h});
        unless ($ARGV[0]) {
                print "\nError: no input file(s) provided\n";
                &print_usage();
        }

        # Copy command line arguments to internal variables
        @input_files = @ARGV;
        $host_detail = 0 unless ($host_detail = $opts{d});
        $email_addr = 0 unless ($email_addr = $opts{e});
        $hitlist_file = 0 unless ($hitlist_file = $opts{l});
        $output_file = 0 unless ($output_file = $opts{o});
        $flows_summary = 0 unless ($flows_summary = $opts{s});

        # Check for required options and combinations
        if (!$output_file) {
                print "\nError: no output file provided\n";
                &print_usage();
        }
        if ($host_detail && !$hitlist_file) {
                print "\nWarning: -d requires -l, ignoring\n";
                $host_detail = 0;
        }

        # Read in option files
        if ($hitlist_file) {
                open(HITLIST, "$hitlist_file") || die "\nError: Cannot open $hitlist_file: $!\n";
                        @hitlist = <HITLIST>;
                close(HITLIST);
        }
}

# -----------------------------------------------------------------------------
# Print usage/help information to the screen and exit
# -----------------------------------------------------------------------------
sub print_usage {
        die <<USAGE;
$PROG_NAME version $PROG_VER
Usage: $PROG_NAME [-hs] [-d dir] [-e email] [-l file] [-o file] [input files]
USAGE
}
