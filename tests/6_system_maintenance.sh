#!/bin/env bash

check_6() {
  info "6 - System Maintenance"
  info "6.1    - System File Permissions"
  test_wrapper 0 "6.1.1  - Audit system file permissions (Not Scored)" test_system_file_perms
  test_wrapper 0 "6.1.2  - Ensure permissions on /etc/passwd are configured (Scored)" test_permissions_0644_root_root ${PASSWD}
  test_wrapper 0 "6.1.3  - Ensure permissions on /etc/shadow are configured (Scored)" test_permissions_0000_root_root ${SHADOW}
  test_wrapper 0 "6.1.4  - Ensure permissions on /etc/group are configured (Scored)" test_permissions_0644_root_root ${GROUP}
  test_wrapper 0 "6.1.5  - Ensure permissions on /etc/gshadow are configured (Scored)" test_permissions_0000_root_root ${GSHADOW}
  test_wrapper 0 "6.1.6  - Ensure permissions on /etc/passwd- are configured (Scored)" test_permissions_0644_root_root ${PASSWD}-
  test_wrapper 0 "6.1.7  - Ensure permissions on /etc/shadow- are configured (Scored)" test_permissions_0000_root_root ${SHADOW}-
  test_wrapper 0 "6.1.8  - Ensure permissions on /etc/group- are configured (Scored)" test_permissions_0644_root_root ${GROUP}-
  test_wrapper 0 "6.1.9  - Ensure permissions on /etc/gshadow- are configured (Scored)" test_permissions_0000_root_root ${GSHADOW}-
  test_wrapper 0 "6.1.10 - Ensure no world writable files exist (Scored)" test_wrld_writable_files
  test_wrapper 0 "6.1.11 - Ensure no unowned files or directories exist (Scored)" test_unowned_files
  test_wrapper 0 "6.1.12 - Ensure no ungrouped files or directories exist (Scored)" test_ungrouped_files
  test_wrapper 0 "6.1.13 - Audit SUID executables (Not Scored)" test_suid_executables
  test_wrapper 0 "6.1.14 - Audit SGID executables (Not Scored)" test_sgid_executables
  info "6.2    - User and Group Settings"
  todo "6.2.1  - Ensure password fields are not empty (Scored)"
  todo "6.2.2  - Ensure no legacy \"+\" entries exist in /etc/passwd (Scored)"
  todo "6.2.3  - Ensure no legacy \"+\" entries exist in /etc/shadow (Scored)"
  todo "6.2.4  - Ensure no legacy \"+\" entries exist in /etc/group (Scored)"
  todo "6.2.5  - Ensure root is the only UID 0 account (Scored)"
  todo "6.2.6  - Ensure root PATH Integrity (Scored)"
  todo "6.2.7  - Ensure all users' home directories exist (Scored)"
  todo "6.2.8  - Ensure users' home directories permissions are 750 or more restrictive (Scored)"
  todo "6.2.9  - Ensure users own their home directories (Scored)"
  todo "6.2.10 - Ensure users' dot files are not group or world writable (Scored)"
  todo "6.2.11 - Ensure no users have .forward files (Scored)"
  todo "6.2.12 - Ensure no users have .netrc files (Scored)"
  todo "6.2.13 - Ensure users' .netrc Files are not group or world accessible (Scored)"
  todo "6.2.14 - Ensure no users have .rhosts files (Scored)"
  todo "6.2.15 - Ensure all groups in /etc/passwd exist in /etc/group (Scored)"
  todo "6.2.16 - Ensure no duplicate UIDs exist (Scored)"
  todo "6.2.17 - Ensure no duplicate GIDs exist (Scored)"
  todo "6.2.18 - Ensure no duplicate user names exist (Scored)"
  todo "6.2.19 - Ensure no duplicate group names exist (Scored)"
}
