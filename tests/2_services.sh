#!/bin/env bash

check_2() {
  info "2 - Services"
  info "2.1     - inetd Services"
  test_wrapper 0 "2.1.1   - Ensure chargen services are not enabled (Scored)" test_dgram_stream_services_disabled chargen
  test_wrapper 0 "2.1.2   - Ensure daytime services are not enabled (Scored)" test_dgram_stream_services_disabled daytime
  test_wrapper 0 "2.1.3   - Ensure discard services are not enabled (Scored)" test_dgram_stream_services_disabled discard
  test_wrapper 0 "2.1.4   - Ensure echo services are not enabled (Scored)" test_dgram_stream_services_disabled echo
  test_wrapper 0 "2.1.5   - Ensure time services are not enabled (Scored)" test_dgram_stream_services_disabled time
  test_wrapper 0 "2.1.6   - Ensure tftp server is not enabled (Scored)" test_service_disable tftp
  test_wrapper 0 "2.1.7   - Ensure xinetd is not enabled (Scored)" test_service_disable xinetd
  info "2.2     - Special Purpose Services"
  info "2.2.1   - Time Synchronization"
  test_wrapper 0 "2.2.1.1 - Ensure time synchronization is in use (Not Scored)" test_time_sync_services_enabled
  test_service_enabled ntpd
  local do_skip_ntpd=$?
  test_wrapper $do_skip_ntpd "2.2.1.2 - Ensure ntp is configured (Scored)" test_ntp_cfg
  test_service_enabled chronyd
  local do_skip_chronyd=$?
  test_wrapper $do_skip_chronyd "2.2.1.3 - Ensure chrony is configured (Scored)" test_chrony_cfg
  test_wrapper 0 "2.2.2   - Ensure X Window System is not installed (Scored)" test_rpm_not_installed 'xorg-x11*'
  test_wrapper 0 "2.2.3   - Ensure Avahi Server is not enabled (Scored)" test_service_disable avahi-daemon
  test_wrapper 0 "2.2.4   - Ensure CUPS is not enabled (Scored)" test_service_disable cups
  test_wrapper 0 "2.2.5   - Ensure DHCP Server is not enabled (Scored)" test_service_disable dhcpd
  test_wrapper 0 "2.2.6   - Ensure LDAP server is not enabled (Scored)" test_service_disable slapd
  test_wrapper 0 "2.2.7   - Ensure NFS and RPC are not enabled (Scored)" test_nfs_rpcbind_services_disabled
  test_wrapper 0 "2.2.8   - Ensure DNS Server is not enabled (Scored)" test_service_disable named
  test_wrapper 0 "2.2.9   - Ensure FTP Server is not enabled (Scored)" test_service_disable vsftpd
  test_wrapper 0 "2.2.10  - Ensure HTTP server is not enabled (Scored)" test_service_disable httpd
  test_wrapper 0 "2.2.11  - Ensure IMAP and POP3 server is not enabled (Scored)" test_service_disable dovecot
  test_wrapper 0 "2.2.12  - Ensure Samba is not enabled (Scored)" test_service_disable smb
  test_wrapper 0 "2.2.13  - Ensure HTTP Proxy Server is not enabled (Scored)" test_service_disable squid
  test_wrapper 0 "2.2.14  - Ensure SNMP Server is not enabled (Scored)" test_service_disable snmpd
  test_wrapper 0 "2.2.15  - Ensure mail transfer agent is configured for local-only mode (Scored)" test_mta_local_only
  test_wrapper 0 "2.2.16  - Ensure NIS Server is not enabled (Scored)" test_service_disable ypserv
  test_wrapper 0 "2.2.17  - Ensure rsh server is not enabled (Scored)" test_rsh_service_disabled
  test_wrapper 0 "2.2.18  - Ensure telnet server is not enabled (Scored)" test_service_disable telnet.socket
  test_wrapper 0 "2.2.19  - Ensure tftp server is not enabled (Scored)" test_service_disable tftp.socket
  test_wrapper 0 "2.2.20  - Ensure rsync service is not enabled (Scored)" test_service_disable rsyncd
  test_wrapper 0 "2.2.21  - Ensure talk server is not enabled (Scored)" test_service_disable ntalk
  info "2.3     - Service Clients"
  test_wrapper 0 "2.3.1   - Ensure NIS Client is not installed (Scored)" test_rpm_not_installed ypbind
  test_wrapper 0 "2.3.2   - Ensure rsh client is not installed (Scored)" test_rpm_not_installed rsh
  test_wrapper 0 "2.3.3   - Ensure talk client is not installed (Scored)" test_rpm_not_installed talk
  test_wrapper 0 "2.3.4   - Ensure telnet client is not installed (Scored)" test_rpm_not_installed telnet
  test_wrapper 0 "2.3.5   - Ensure LDAP client is not installed (Scored)" test_rpm_not_installed openldap-clients
}