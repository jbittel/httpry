#!/usr/bin/perl -w

#
# db_dump.pm | created: 7/5/2006
#
# Copyright (c) 2006, Jason Bittel <jbittel@corban.edu>. All rights reserved.
# See included LICENSE file for specific licensing information
#

package db_dump;

use DBI;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PATTERN = "\t";

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my $dbh;
my ($timestamp, $src_ip, $dst_ip, $hostname, $uri);

# -----------------------------------------------------------------------------
# Plugin core
# -----------------------------------------------------------------------------

&main::register_plugin(__PACKAGE__);

sub new {
        return bless {};
}

sub init {
        my $self = shift;
        my $plugin_dir = shift;
        my $sql;

        if (&load_config($plugin_dir) == 0) {
                return 0;
        }

        $dbh = &connect_db($type, $db, $host, $port, $user, $pass);

        # Remove old data as necessary
        #$sql = qq{ DELETE FROM $table WHERE
        #&execute_query($dbh, $sql);

        return 1;
}

sub main {
        my $self = shift;
        my $data = shift;
        my $sql;

        # Strip non-printable chars
        $data =~ tr/\x80-\xFF//d;

        # Convert hex characters to ASCII
        $data =~ s/%25/%/g; # Sometimes '%' chars are double encoded
        $data =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;

        ($timestamp, $src_ip, $dst_ip, $hostname, $uri) = split(/$PATTERN/, $data);

        # Reformat date/time string
        $timestamp =~ /(\d\d)\/(\d\d)\/(\d\d\d\d) (\d\d):(\d\d):(\d\d)/;
        $timestamp = "$3-$1-$2 $4:$5:$6";

        # Escape apostrophe/quote characters
        $hostname =~ s/'/\\'/g;
        $uri =~ s/'/\\'/g;
        $hostname =~ s/"/\\"/g;
        $uri =~ s/"/\\"/g;

        # Insert data into database
        $sql = qq{ INSERT INTO $table (timestamp, src_ip, dst_ip, hostname, uri)
                   VALUES ('$timestamp', '$src_ip', '$dst_ip', '$hostname', '$uri') };
        &execute_query($dbh, $sql);

        return;
}

sub end {
        &disconnect_db();

        return;
}

# -----------------------------------------------------------------------------
# Load config file and check for required options
# -----------------------------------------------------------------------------
sub load_config {
        my $plugin_dir = shift;

        # Load config file; by default in same directory as plugin
        if (-e "$plugin_dir/" . __PACKAGE__ . ".cfg") {
                require "$plugin_dir/" . __PACKAGE__ . ".cfg";
        }

        # Check for required options and combinations
        if (!$type) {
                print "Error: no database type provided\n";
                return 0;
        }
        if (!$db) {
                print "Error: no database name provided\n";
                return 0;
        }
        if (!$host) {
                print "Error: no database hostname provided\n";
                return 0;
        }
        if (!$table) {
                print "Error: no database table provided\n";
                return 0;
        }
        $port = '3306' unless ($port);

        return 1;
}

# -----------------------------------------------------------------------------
# Build connection to specified database
# -----------------------------------------------------------------------------
sub connect_db {
        my $type = shift;
        my $db   = shift;
        my $host = shift;
        my $port = shift;
        my $user = shift;
        my $pass = shift;
        my $dbh;
        my $dsn;

        $dsn = "DBI:$type:$db";
        $dsn .= ":$host" if $host;
        $dsn .= ":$port" if $port;

        $dbh = DBI->connect($dsn, $user, $pass, { RaiseError => 1, AutoCommit => 1 })
                or die "Error: cannot connect to database: " . DBI->errstr;

        &execute_query($dbh, qq{ USE $db });

        return $dbh;
}

# -----------------------------------------------------------------------------
# Generalized SQL query execution sub
# -----------------------------------------------------------------------------
sub execute_query {
        my $dbh = shift;
        my $sql = shift;
        my $sth;

        $sth = $dbh->prepare($sql) or die "Error: cannot prepare query: " . DBI->errstr;
        $sth->execute() or die "Error: cannot execute query: " . DBI->errstr;

        return $sth;
}

# -----------------------------------------------------------------------------
# Terminate active database connection
# -----------------------------------------------------------------------------
sub disconnect_db {
        $dbh->disconnect;
}

1;
