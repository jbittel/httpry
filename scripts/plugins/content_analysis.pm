#!/usr/bin/perl -w

#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2007 Jason Bittel <jason.bittel@gmail.com>
#

# This is an example plugin for the perl parse script parse_log.pl.  It shows
# the basic structure of a simple plugin and provides a good starting point for
# writing a custom plugin. Some of the other included plugins will also provide
# a good idea of how the different pieces work.

package content_analysis;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------

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

#        if (&load_config($plugin_dir) == 0) {
#                return 0;
#        }

        return 1;
}

sub main {
        my $self   = shift;
        my $record = shift;
        my $uri;

        return unless exists $record->{"host"};
        return unless exists $record->{"request-uri"};

        # URI regexp as given in RFC2396
        #
        # ^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?
        #  12            3  4          5       6  7        8 9
        #
        # scheme    = $2
        # authority = $4
        # path      = $5
        # query     = $7
        # fragment  = $9

        $uri = "$record->{'host'}$record->{'request-uri'}";
        print "$uri -> ";


#        $uri =~ /^(([^:\/?#]+):)?(\/\/([^\/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?/;
        $uri =~ /^([^\/?#]*)?([^?#]*)(\?([^#]*))?(#(.*))?/;

#        my $scheme = $2;
        my $host = $1;
        my $path = $2;
        my $query = $4;
        my $frag = $6;

#        print "$scheme :: $authority :: $path :: $query :: $fragment\n";
#        print "$authority :: $path :: $query :: $fragment\n";
        print "$host" if ($host);
        print " :: $path" if ($path);
        print " :: $query" if ($query);
        print " :: $frag" if ($frag);
        print "\n";

        return;
}

sub end {

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

        # Check for required options and combinations from the configuration
        # file variables. This can also be a good place to do file reads for
        # initializing run time data structures.

        return 1;
}

1;
