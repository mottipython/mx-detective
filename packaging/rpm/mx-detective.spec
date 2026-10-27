%{!?pkg_version:%global pkg_version 1.1.1}
Name:           mx-detective
Version:        %{pkg_version}
Release:        1%{?dist}
Summary:        Public MX server, SMTP handshake and mail security diagnostic tool
License:        MIT
URL:            https://github.com/mottipython/mx-detective

%description
MX Detective is a comprehensive diagnostic tool with both GUI and CLI
for testing every public MX server over IPv4 and IPv6: SMTP protocol behavior,
the real TLS certificate, DANE and MTA-STS, DNS blocklists, and the SPF,
DMARC, DKIM and reverse DNS records.

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
* Tue Oct 27 2026 Motti Schleider <motti.schleider@gmail.com> - 1.1.1-1
- Window exports include the changes since the baseline
* Mon Oct 26 2026 Motti Schleider <motti.schleider@gmail.com> - 1.1.0-1
- Compare a run with an earlier result: --baseline, --diff, --fail-on regression
* Mon Oct 26 2026 Motti Schleider <motti.schleider@gmail.com> - 1.0.0-1
- Report the real TLS certificate; test every MX address; add MTA-STS, DANE,
  DNSSEC, TLS-RPT, BIMI, blocklist and DKIM checks
* Fri Oct 23 2026 Motti Schleider <motti.schleider@gmail.com> - 0.1.0-1
- Initial release of mx-detective
