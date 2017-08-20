#!/bin/env bash

BLDRED='\033[1;31m'
BLDGRN='\033[1;32m'
BLDBLU='\033[1;34m'
BLDYLW='\033[1;33m' # Yellow
BLDMGT='\033[1;35m' # Magenta
BLDCYN='\033[1;36m' # Cyan 
TXTRST='\033[0m'

logit () {
  printf "%b\n" "$1"
}

info () {
  printf "%b\n" "${BLDBLU}[INFO]${TXTRST} $1"
}

pass () {
  printf "%b\n" "${BLDGRN}[PASS]${TXTRST} $1"
}

warn () {
  printf "%b\n" "${BLDRED}[WARN]${TXTRST} $1"
}

note () {
  printf "%b\n" "${BLDYLW}[NOTE]${TXTRST} $1"
}

todo() {
  printf "%b\n" "${BLDMGT}[TODO]${TXTRST} $1"
}

skip() {
  printf "%b\n" "${BLDCYN}[SKIP]${TXTRST} $1"
}

yell () {
  printf "%b\n" "${BLDYLW}$1${TXTRST}\n"
}