#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>
#

package db_dump;

use warnings;
use DBI;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my $dbh;

# -----------------------------------------------------------------------------
# Plugin core
# -----------------------------------------------------------------------------

main::register_plugin();

sub new {
        return bless {};
}

sub init {
        my $self = shift;
        my $cfg_dir = shift;
        my $sql;
        my $limit;

        _load_config($cfg_dir);

        $dbh = _connect_db($type, $db, $host, $port, $user, $pass);

        # Delete data inserted $rmbefore days prior
        if ($rmbefore > 0) {
                my ($year, $mon, $day, $hour, $min, $sec) = (localtime(time-(86400*$rmbefore)))[5,4,3,2,1,0];
                $limit = ($year+1900) . "-" . ($mon+1) . "-$day $hour:$min:$sec";

                $sql = qq{ DELETE FROM client_data WHERE timestamp < '$limit' };
                _execute_query($dbh, $sql);

                $sql = qq{ DELETE FROM server_data WHERE timestamp < '$limit' };
                _execute_query($dbh, $sql);
        }

        return;
}

sub list {
        return qw(direction timestamp source-ip dest-ip);
}

sub main {
        my $self = shift;
        my $record = shift;
        my $sth;
        my ($year, $mon, $day, $hour, $min, $sec) = (localtime)[5,4,3,2,1,0];
        my $now = ($year+1900) . "-" . ($mon+1) . "-$day $hour:$min:$sec";
        my @values = ($now, $record->{"timestamp"}, $record->{"source-ip"}, $record->{"dest-ip"});

        if ($record->{"direction"} eq '>') {
                push @values, $record->{"host"}, $record->{"request-uri"};
                $sth = $dbh->prepare(qq{ INSERT INTO client_data (timestamp, pktstamp, src_ip, dst_ip, hostname, uri)
                                         VALUES (?, ?, ?, ?, ?, ?) });
        } elsif ($record->{"direction"} eq '<') {
                push @values, $record->{"status-code"}, $record->{"reason-phrase"};
                $sth = $dbh->prepare(qq{ INSERT INTO server_data (timestamp, pktstamp, src_ip, dst_ip, status_code, reason_phrase)
                                         VALUES (?, ?, ?, ?, ?, ?) });
        }

        $sth->execute(@values);

        return;
}

sub end {
        _disconnect_db();

        return;
}

# -----------------------------------------------------------------------------
# Load config file and check for required options
# -----------------------------------------------------------------------------
sub _load_config {
        my $cfg_dir = shift;

        # Load config file; by default in same directory as plugin
        if (-e "$cfg_dir/" . __PACKAGE__ . ".cfg") {
                require "$cfg_dir/" . __PACKAGE__ . ".cfg";
        } else {
                die "No config file found\n";
        }

        # Check for required options and combinations
        if (!$type) {
                die "No database type provided\n";
        }
        if (!$db) {
                die "No database name provided\n";
        }
        if (!$host) {
                die "No database hostname provided\n";
        }
        $port = '3306' unless ($port);

        return;
}

# -----------------------------------------------------------------------------
# Build connection to specified database
# -----------------------------------------------------------------------------
sub _connect_db {
        my $type = shift;
        my $db = shift;
        my $host = shift;
        my $port = shift;
        my $user = shift;
        my $pass = shift;
        my $dbh;
        my $dsn;

        $dsn = "DBI:$type:$db";
        $dsn .= ":$host" if $host;
        $dsn .= ":$port" if $port;

        if ($dbh = DBI->connect($dsn, $user, $pass, { PrintError => 0, RaiseError => 0, AutoCommit => 1 })) {
                _execute_query($dbh, qq{ USE $db });
        } else {
                die "Cannot connect to database: " . DBI->errstr . "\n";
        }

        return $dbh;
}

# -----------------------------------------------------------------------------
# Generalized SQL query execution sub
# -----------------------------------------------------------------------------
sub _execute_query {
        my $dbh = shift;
        my $sql = shift;
        my $sth;

        $sth = $dbh->prepare($sql) or die "Cannot prepare query: " . DBI->errstr . "\n";
        $sth->execute() or die "Cannot execute query: " . DBI->errstr . "\n";

        return $sth;
}

# -----------------------------------------------------------------------------
# Terminate active database connection
# -----------------------------------------------------------------------------
sub _disconnect_db {
        $dbh->disconnect;
}

1;
