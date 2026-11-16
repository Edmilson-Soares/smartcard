#!/bin/sh
# Baixa a base de ATRs do pcsc-tools (Ludovic Rousseau, GPL-2.0) para data/.
# Use com scard.loadAtrList("data/smartcard_list.txt").
set -e
cd "$(dirname "$0")"
mkdir -p data
curl -fsSL https://pcsc-tools.apdu.fr/smartcard_list.txt -o data/smartcard_list.txt
echo "data/smartcard_list.txt atualizado"
