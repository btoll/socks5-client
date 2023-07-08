Name:           socks5-client
Version:        VERSION
Release:        1%{?dist}
Summary:        Partial implementation of SOCKS 5 protocol

License:        GPLv3+
URL:            https://benjamintoll.com
Source0:        https://github.com/btoll/socks5-client/releases/download/VERSION/socks5-client_VERSION.tar.gz

BuildRequires:  gcc
Requires:       make

%description
Partial implementation of SOCKS 5 protocol

%prep
%setup -q

%build
make %{?_smp_mflags}

%install
%make_install

%files
%license LICENSE
%{_bindir}/%{name}

%changelog
