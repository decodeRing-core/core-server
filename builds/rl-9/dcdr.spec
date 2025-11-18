Name: dcdr
Version: 0.3
Release: 1%{?dist}
Summary: Initial release of the alpha decodeRing server / client tools

License: MIT
URL:     https://decodering.org
Source0: %{name}-%{version}.tar.gz
BuildArch: x86_64

BuildRequires: golang
BuildRequires: selinux-policy-devel

%description
Initial release of the alpha decodeRing server / client tools

%global debug_package %{nil}

%prep
%setup -q

%build
# build the server and client
go build -gcflags="all=-N -l" -o dcdr-server cmd/server/main.go
go build -gcflags="all=-N -l" -o dcdr cmd/client/main.go

# Build the SELinux policy module from builds/rl-9/SELinux
cd builds/rl-9/SELinux
make -f /usr/share/selinux/devel/Makefile NAME=dcdr.pp
cd -

# Move the compiled policy to the main build dir
#cp builds/rl-9/SELinux/dcdr.pp .


%install
# Cleanup any previous builds
rm -rf %{buildroot}
# Create directory structure
mkdir -p %{buildroot}/usr/sbin
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc/%{name}/backends.d
mkdir -p %{buildroot}/var/log/%{name}
mkdir -p %{buildroot}/usr/share/selinux/packages
mkdir -p %{buildroot}/usr/share/%{name}
mkdir -p %{buildroot}/usr/share/man/man1
mkdir -p %{buildroot}/usr/share/man/man8
mkdir -p %{buildroot}/usr/lib/systemd/system
mkdir -p %{buildroot}/usr/lib/tmpfiles.d
# Install server files
install -m 0755 dcdr-server %{buildroot}/usr/sbin/dcdr-server
install -m 0644 builds/rl-9/etc/dcdr/server.cfg %{buildroot}/etc/%{name}/server.cfg
install -m 0644 builds/rl-9/etc/dcdr/backends.d/aws-1.cfg %{buildroot}/etc/%{name}/backends.d/aws-1.cfg
install -m 0644 builds/rl-9/etc/dcdr/backends.d/azure-1.cfg %{buildroot}/etc/%{name}/backends.d/azure-1.cfg
install -m 0644 builds/rl-9/etc/dcdr/backends.d/bao-1.cfg %{buildroot}/etc/%{name}/backends.d/bao-1.cfg
install -m 0644 builds/rl-9/etc/dcdr/backends.d/vault-1.cfg %{buildroot}/etc/%{name}/backends.d/vault-1.cfg
install -m 0644 builds/rl-9/systemd/dcdr-server.service %{buildroot}/usr/lib/systemd/system/dcdr-server.service
install -m 0644 builds/rl-9/systemd/tmpfiles.d/dcdr-server.conf %{buildroot}/usr/lib/tmpfiles.d/dcdr-server.conf
# Install client
install -m 0755 dcdr %{buildroot}/usr/bin/dcdr
# Install SELinux policy
install -m 0644 builds/rl-9/SELinux/dcdr.pp %{buildroot}/usr/share/selinux/packages/dcdr.pp
# Install schema file
install -m 0644 builds/rl-9/pgsql-schema.sql %{buildroot}/usr/share/%{name}/pgsql-schema.sql
# Install man pages
install -m 0644 man/man1/dcdr.1 %{buildroot}/usr/share/man/man1/dcdr.1
install -m 0644 man/man8/dcdr-server.8 %{buildroot}/usr/share/man/man8/dcdr-server.8

%post
# Load SELinux policy on install
if [ $1 -eq 1 ]; then
    semodule -i /usr/share/selinux/packages/dcdr.pp || :

    semanage port -a -t dcdr_server_port_t -p tcp 8301

    # Apply file contexts from the .fc file
    restorecon -R -v /etc/dcdr || :
    restorecon -R -v /var/log/dcdr || :
fi

%postun
# Remove SELinux module when package is erased
if [ $1 -eq 0 ]; then
    semodule -r dcdr || :
fi

%files
%attr(0755, root, root) /usr/sbin/dcdr-server
%attr(0644, root, root) /etc/%{name}/server.cfg
%attr(0644, root, root) /etc/%{name}/backends.d/aws-1.cfg
%attr(0644, root, root) /etc/%{name}/backends.d/azure-1.cfg
%attr(0644, root, root) /etc/%{name}/backends.d/bao-1.cfg
%attr(0644, root, root) /etc/%{name}/backends.d/vault-1.cfg
%attr(0755, root, root) /usr/bin/dcdr
%attr(0644, root, root) /usr/share/selinux/packages/dcdr.pp
%attr(0644, root, root) /usr/share/%{name}/pgsql-schema.sql
%attr(0644, root, root) /usr/share/man/man1/dcdr.1.gz
%attr(0644, root, root) /usr/share/man/man8/dcdr-server.8.gz
%attr(0644, root, root) /usr/lib/systemd/system/dcdr-server.service
%attr(0644, root, root) /usr/lib/tmpfiles.d/dcdr-server.conf

%changelog
* Thu Sep 11 2025 Arthur Enright arthur.enright@decodering.org - 0.1-1
- Initial release with SELinux policy