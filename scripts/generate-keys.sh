#!/usr/bin/env bash
set -e

mkdir -p keys
echo "Generating Ed25519 keypair for Kill Switch Operator..."

# Generate private key (NEVER store in DB)
openssl genpkey -algorithm ed25519 -out keys/operator_private.pem

# Extract public key
openssl pkey -in keys/operator_private.pem -pubout -out keys/operator_public.pem

echo "Success. Public key written to keys/operator_public.pem"
echo "Keep operator_private.pem offline and highly secure."
