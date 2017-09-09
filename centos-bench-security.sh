#!/bin/env bash

# Simple input to skip slow tests
if [[ "$1" == "--skip-slow" ]]; then
  export BENCH_SKIP_SLOW=1
fi

. includes/log_utils.sh
. includes/test_utils.sh

func_wrapper() {
  local func=$1
  shift
  local args=$@
  ${func} ${args} 
  #2>/dev/null
  if [[ "$?" -eq 127 ]]; then
    warn "${func} not implemented"
  fi
}

main () {  
  yell "# ------------------------------------------------------------------------------
# CentOS Bench for Security 
# 
# Based on 'CIS CentOS Linux 7 Benchmark v2.1.1 (01-31-2017)'
# https://www.cisecurity.org/cis-benchmarks/
#
# Björn Oscarsson (c) 2017-
#
# Inspired by the Docker Bench for Security.
# ------------------------------------------------------------------------------"
  logit "Initializing $(date)"

  ID=$(id -u)
  if [[ "x$ID" != "x0" ]]; then
    logit ""
    warn "Tests requires root to run"
    logit ""
    exit 1
  fi
  
  for test in tests/*.sh
  do
    logit ""
    . ./"$test"
    func_wrapper check_$(echo "$test" | awk -F_ '{print $1}' | cut -d/ -f2)
  done

  logit ""  
}

main "$@"
