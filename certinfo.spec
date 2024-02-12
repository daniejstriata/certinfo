Name: certinfo
Version: 1.1.1
Release: 1%{?dist}
Summary: Certificate Information Tool
License: MIT
URL: https://github.com/daniejstriata/certinfo
Source0: https://github.com/daniejstriata/certinfo/archive/refs/tags/%{version}.tar.gz

%define debug_package %{nil}

BuildRequires: gcc-c++
BuildRequires: openssl-devel

%description
Certinfo is a tool to display information from X.509 certificates.

%prep
%autosetup -n certinfo-%{version}
autoreconf -i

%build
%configure
make CFLAGS="%{optflags} -std=c99" %{?_smp_mflags}

%install
mkdir -p %{buildroot}/%{_bindir}
install -m 755 certinfo %{buildroot}/%{_bindir}

%files
%{_bindir}/certinfo

%changelog
* Mon Feb 12 2024 Danie de Jager <danie.dejager@gmail.com> - 1.1-1
- Process SAN entries.
* Mon Feb 12 2024 Danie de Jager <danie.dejager@gmail.com> - 1.0-2
- remove debug info.
* Mon Feb 12 2024 Danie de Jager <danie.dejager@gmail.com> - 1.0-1
- Initial release.
