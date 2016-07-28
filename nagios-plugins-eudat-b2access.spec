Name:		nagios-plugins-eudat-b2access
Version:	0.1
Release:	1%{?dist}
Summary:	Nagios B2ACCESS probes
License:	GPLv3+
Packager:	Shiraz Memon <a.memon@fz-juelich.de>

Source:		%{name}-%{version}.tar.gz
BuildArch:	noarch
BuildRoot:	%{_tmppath}/%{name}-%{version}

Requires:	python
Requires:	python-argparse
Requires:	python-lxml
Requires:	python-simplejson
Requires:	python-defusedxml
Requires:	python-httplib2
Requires:	python-json
Requires:	python-sys
Requires:	python-requests
Requires:	python-signal

%description
Nagios probes to check functionality of B2ACCESS Service

%prep
%setup -q

%define _unpackaged_files_terminate_build 0 

%install

install -d %{buildroot}/%{_libexecdir}/argo-monitoring/probes/%{name}
install -m 755 check_b2access.py %{buildroot}/%{_libexecdir}/argo-monitoring/probes/%{name}/check_b2access.py

%files
%dir /%{_libexecdir}/argo-monitoring
%dir /%{_libexecdir}/argo-monitoring/probes/
%dir /%{_libexecdir}/argo-monitoring/probes/%{name}

%attr(0755,root,root) /%{_libexecdir}/argo-monitoring/probes/%{name}/check_b2access.py

%changelog
* Thu Jul 28 2016 Shiraz Memon <a.memon@fz-juelich.de> - 0.1-1
- Initial version of the package