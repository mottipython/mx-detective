Name:           mx-detective
Version:        0.1.0
Release:        1%{?dist}
Summary:        Public MX server, SMTP handshake and mail security diagnostic tool
License:        MIT
URL:            https://github.com/motti/mx-detective

%description
MX Detective is a comprehensive diagnostic tool with both GUI and CLI
for testing public MX server connections, evaluating anti-spam tarpitting,
detecting SMTP protocol misbehaviors, inspecting STARTTLS encryption,
and auditing SPF, DMARC, and Reverse DNS (PTR/FCrDNS).

%install
rm -rf $RPM_BUILD_ROOT
install -d -m 0755 $RPM_BUILD_ROOT%{_bindir}
install -d -m 0755 $RPM_BUILD_ROOT%{_datadir}/applications
install -m 0755 %{_sourcedir}/mx-detective $RPM_BUILD_ROOT%{_bindir}/mx-detective
install -m 0644 %{_sourcedir}/mx-detective.desktop $RPM_BUILD_ROOT%{_datadir}/applications/mx-detective.desktop

%files
%{_bindir}/mx-detective
%{_datadir}/applications/mx-detective.desktop

%changelog
* Fri Oct 23 2026 Motti Schleider <motti.schleider@gmail.com> - 0.1.0-1
- Initial release of mx-detective
