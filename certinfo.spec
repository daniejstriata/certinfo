Name: certinfo
Version: 1.0
Release: 1%{?dist}
Summary: Certificate Information Tool
License: MIT
URL: https://github.com/daniejstriata/certinfo
Source0: https://github.com/daniejstriata/certinfo/archive/refs/tags/%{version}.tar.gz

%define debug_package %{nil}

BuildRequires: gcc
BuildRequires: openssl-devel

%description
Certinfo is a tool to display information from X.509 certificates.

%prep
%autosetup -n certinfo-%{version}

%build
%configure
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}

%files
%{_bindir}/certinfo

%changelog
* Mon Feb 12 2024 Danie de Jager <danie.dejager@gmail.com> - 1.0-1
- Initial release
