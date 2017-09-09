#!/bin/env bash

check_3() {
  info "3 - Network Configuration"
  info "3.1   - Network Parameters (Host Only)"
  test_wrapper 0 "3.1.1 - Ensure IP forwarding is disabled (Scored)" test_sysctl net.ipv4.ip_forward 0
  test_wrapper 0 "3.1.2 - Ensure packet redirect sending is disabled (Scored)" test_net_ipv4_conf_all_default send_redirects 0
  info "3.2   - Network Parameters (Host and Router)"
  test_wrapper 0 "3.2.1 - Ensure source routed packets are not accepted (Scored)" test_net_ipv4_conf_all_default accept_source_route 0
  test_wrapper 0 "3.2.2 - Ensure ICMP redirects are not accepted (Scored)" test_net_ipv4_conf_all_default accept_redirects 0
  test_wrapper 0 "3.2.3 - Ensure secure ICMP redirects are not accepted (Scored)" test_net_ipv4_conf_all_default secure_redirects 0
  test_wrapper 0 "3.2.4 - Ensure suspicious packets are logged (Scored)" test_net_ipv4_conf_all_default log_martians 1
  test_wrapper 0 "3.2.5 - Ensure broadcast ICMP requests are ignored (Scored)" test_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
  test_wrapper 0 "3.2.6 - Ensure bogus ICMP responses are ignored (Scored)" test_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
  test_wrapper 0 "3.2.7 - Ensure Reverse Path Filtering is enabled (Scored)" test_net_ipv4_conf_all_default rp_filter 1
  test_wrapper 0 "3.2.8 - Ensure TCP SYN Cookies is enabled (Scored)" test_sysctl net.ipv4.tcp_syncookies 1
  info "3.3   - IPv6"
  test_wrapper 0 "3.3.1 - Ensure IPv6 router advertisements are not accepted (Scored)" test_net_ipv6_conf_all_default accept_ra 0
  test_wrapper 0 "3.3.2 - Ensure IPv6 redirects are not accepted (Scored)" test_net_ipv6_conf_all_default accept_redirects 0
  test_wrapper 0 "3.3.3 - Ensure IPv6 is disabled (Not Scored)" test_ipv6_disabled
  info "3.4   - TCP Wrappers"
  test_wrapper 0 "3.4.1 - Ensure TCP Wrappers is installed (Scored)" test_tcp_wrappers_installed
  info "3.4.2 - Ensure /etc/hosts.allow is configured (Scored)"
  test_wrapper 0 "3.4.3 - Ensure /etc/hosts.deny is configured (Scored)" test_hosts_deny_content
  test_wrapper 0 "3.4.4 - Ensure permissions on /etc/hosts.allow are configured (Scored)" test_permissions_0644_root_root ${HOSTS_ALLOW}
  test_wrapper 0 "3.4.5 - Ensure permissions on /etc/hosts.deny are 644 (Scored)" test_permissions_0644_root_root ${HOSTS_DENY}
  info "3.5   - Uncommon Network Protocols"
  test_wrapper 0 "3.5.1 - Ensure DCCP is disabled (Not Scored)" test_module_disabled dccp
  test_wrapper 0 "3.5.2 - Ensure SCTP is disabled (Not Scored)" test_module_disabled sctp
  test_wrapper 0 "3.5.3 - Ensure RDS is disabled (Not Scored)" test_module_disabled rds
  test_wrapper 0 "3.5.4 - Ensure TIPC is disabled (Not Scored)" test_module_disabled tipc
  info "3.6   - Firewall Configuration"
  test_wrapper 0 "3.6.1 - Ensure iptables is installed (Scored)" test_rpm_installed iptables
  test_wrapper 0 "3.6.2 - Ensure default deny firewall policy (Scored)" test_firewall_policy
  test_wrapper 0 "3.6.3 - Ensure loopback traffic is configured (Scored)" test_loopback_traffic_conf
  info "3.6.4 - Ensure outbound and established connections are configured (Not Scored)"
  info "3.6.5 - Ensure firewall rules exist for all open ports (Scored)"
  test_wrapper 0 "3.7   - Ensure wireless interfaces are disabled (Not Scored)" test_wireless_if_disabled
}