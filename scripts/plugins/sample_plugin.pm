#!/usr/bin/perl -w

#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2008 Jason Bittel <jason.bittel@gmail.com>
#

# This is an example plugin for the perl parse script parse_log.pl.  It shows
# the basic structure of a simple plugin and provides a good starting point for
# writing a custom plugin. Some of the other included plugins will also provide
# a good idea of how the different pieces work.

package sample_plugin;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Plugin core
# -----------------------------------------------------------------------------

# On initialization, this call registers the plugin with the core
&main::register_plugin(__PACKAGE__);

# This sub is called once at initialization to create the plugin object
sub new {
        return bless {};
}

# This sub is called once at initialization; all startup code should be
# included here. Currently this sub only loads the configuration file, but
# any startup specific code or subs are handled here.
sub init {
        my $self = shift;
        my $cfg_dir = shift;

        # Call our load configuration sub; this can be good to break out
        # into a separate sub like this, particularly if you end up with
        # many checks on the config variables
        unless (&load_config($cfg_dir)) {
                return 0;
        }

        return 1;
}

# This sub is called once for each data line in the input file(s). Note
# that the data is sent here as a single line and so must be parsed (if
# necessary) to act on individual components of the line.
sub main {
        my $self = shift;
        my $record = shift; # Reference to hash containing record data

        # Simple processing can be handled here; more complex processing
        # would probably be better handled in a different sub

        return;
}

# This sub is called once at program termination; all shutdown code (i.e.
# closing files, deleting temp files, etc) should be included here
sub end {

        return;
}

# -----------------------------------------------------------------------------
# Load config file and check for required options
# -----------------------------------------------------------------------------
sub load_config {
        my $cfg_dir = shift;

        # Load config file; by default in same directory as plugin
        if (-e "$cfg_dir/" . __PACKAGE__ . ".cfg") {
                require "$cfg_dir/" . __PACKAGE__ . ".cfg";
        }

        # Check for required options and combinations from the configuration
        # file variables. This can also be a good place to do file reads for
        # initializing run time data structures.

        return 1;
}

1;
