#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2009 Jason Bittel <jason.bittel@gmail.com>
#
# .spec file built and provided by Shawn Ashlee
#

#
# Setting initial dist defaults.  Do not modify these.
# Note: Mock sets these up... but we need to default for manual builds.
#
%{!?el4:%define el4 0}
%{!?el5:%define el5 0}
%{!?rhel:%define rhel 'empty'}

# Build Options
#
# In order to properly build you will likely need to add one of the
following
# build options:
#
#       --with el4
#       --with el5
#
#
# Note for maintainers/builders: mock handles all these defs.  We
include them
# here for manual builds.
#
%{?_with_el4:%define el4 1}
%{?_with_el4:%define rhel 4}
%{?_with_el4:%define dist .el4}

%{?_with_el5:%define el5 1}
%{?_with_el5:%define rhel 5}
%{?_with_el5:%define dist .el5}


Summary: specialized packet sniffer designed for displaying and logging
HTTP traffic
Name: httpry
Version: 0.1.5
Release: 1.rs%{?dist}
License: GPLv2
Group: Applications/Internet
URL: http://dumpsterventures.com/jason/httpry/
Vendor: Jason Bittel <jason.bittel@gmail.com>
Packager: Shawn Ashlee <shawn.ashlee@rackspace.com>
Source0:
http://dumpsterventures.com/jason/httpry/%{name}-%{version}.tar.gz
Buildroot: %{_tmppath}/%{name}-%{version}

%if %{el5}
BuildRequires: libpcap-devel
%else
BuildRequires: libpcap
%endif

Requires: /usr/bin/perl


%description
httpry is a tool designed for displaying and logging HTTP traffic. It is
not
intended to perform analysis itself, but instead to capture, parse
and/or
log the traffic for later analysis. It can be run in real-time
displaying
the live traffic on the wire, or as a daemon process that logs to an
output
file. It is written to be as lightweight and flexible as possible, so
that
it can be easily adaptable to different applications. It does not
display
the raw HTTP data transferred, but instead focuses on parsing and
displaying
the request/response line along with associated header fields.


%prep
%setup -q


%build
%{__make}


%install
[ "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}

%{__install} -D -m 0755 %{name} %{buildroot}%{_sbindir}/%{name}
%{__install} -D -m 0644 %{name}.1 %{buildroot}%{_mandir}/man1/%{name}.1
%{__install} -D -m 0755 rc.%{name} %{buildroot}%{_initrddir}/%{name}


%clean
[ "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}


%files
%defattr(-,root,root)
%doc doc scripts test
%{_sbindir}/%{name}
%{_mandir}/man1/%{name}.1.gz
%{_initrddir}/%{name}


%changelog
* Wed Jan 21 2009 Shawn Ashlee <shawn.ashlee@rackspace.com>
- updated to latest sources

* Fri Sep 05 2008 Shawn Ashlee <shawn.ashlee@rackspace.com>
- initial build
