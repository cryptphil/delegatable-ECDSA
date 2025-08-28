#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# zk-Recursive Proof CLI – EUDI Credential Wallet Binding with Key Derivation
###############################################################################

echo
echo "------------------------------------------------------"
echo " zk-Recursive Proof CLI"
echo "------------------------------------------------------"
echo

###############################################################################
# Ask for user configuration
###############################################################################
read -rp "Enter user ID: " USER_ID
[[ -n "$USER_ID" ]] || { echo "Error: No user ID provided." >&2; exit 1; }

echo
echo "Available derivation modes:"
echo "  sha512   - BIP32/HMAC-SHA512 derivation (default)"
echo "  poseidon - Poseidon-based derivation"
echo
read -rp "Enter derivation mode (sha512/poseidon) [sha512]: " DERIVE_MODE
DERIVE_MODE=${DERIVE_MODE:-sha512}

if [[ "$DERIVE_MODE" != "sha512" && "$DERIVE_MODE" != "poseidon" ]]; then
    echo "Error: Invalid derivation mode. Use 'sha512' or 'poseidon'." >&2
    exit 1
fi

echo
echo "Available proof modes:"
echo "  normal     - Run inner + outer proofs"
echo "  multi-step - Run multi-step recursion"
echo
read -rp "Enter proof mode (normal/multi-step) [normal]: " PROOF_MODE
PROOF_MODE=${PROOF_MODE:-normal}

if [[ "$PROOF_MODE" != "normal" && "$PROOF_MODE" != "multi-step" ]]; then
    echo "Error: Invalid proof mode. Use 'normal' or 'multi-step'." >&2
    exit 1
fi

###############################################################################
# Paths and constants
###############################################################################
INPUT_DIR="inputs"
SRC_FILE="../zk-backend/data/proof-preparation/${USER_ID}_recursive.json"
DEST_FILE="${INPUT_DIR}/input.json"

# Create input directory if needed
mkdir -p "$INPUT_DIR"

###############################################################################
# Step 1: Copy and prepare input file
###############################################################################
echo
echo "Step 1: Copying input file from backend ..."

if [[ ! -f "$SRC_FILE" ]]; then
    echo "Error: Missing input file: $SRC_FILE" >&2
    echo "Please run the backend recursive proof preparation endpoint first." >&2
    exit 1
fi

cp -f "$SRC_FILE" "$DEST_FILE"
echo "OK: Copied input file to ${DEST_FILE}"

###############################################################################
# Step 2: Poseidon mode processing (if needed)
###############################################################################
if [[ "$DERIVE_MODE" == "poseidon" ]]; then
    echo
    echo "Step 2: Converting to Poseidon mode ..."
    
    echo "Building generate_poseidon tool ..."
    cargo build --release --bin generate_poseidon
    
    echo "Converting input for Poseidon derivation ..."
    cargo run --release --bin generate_poseidon -- --input "$DEST_FILE" --output "$DEST_FILE"
    
    echo "OK: Input converted for Poseidon mode"
else
    echo
    echo "Step 2: SHA512 mode - no conversion needed"
fi

###############################################################################
# Step 3: Run proof generation
###############################################################################
echo
echo "Step 3: Generating zk-SNARK proof ..."
echo "Mode: $PROOF_MODE, Derivation: $DERIVE_MODE"
echo

# Set cargo command based on proof mode
if [[ "$PROOF_MODE" == "multi-step" ]]; then
    CARGO_CMD="cargo run --release --bin zk-recursive -- multi-step --input $DEST_FILE --sig-mode static --der-mode $DERIVE_MODE"
else
    CARGO_CMD="cargo run --release --bin zk-recursive -- outer --input $DEST_FILE --inner-sig-mode static --outer-derive-mode $DERIVE_MODE"
fi

echo "Executing: $CARGO_CMD"
echo "------------------------------------------------------"

# Execute the command and show all output
set +e  # Don't exit on error to handle exit code properly
$CARGO_CMD
CARGO_EXIT_CODE=$?
set -e  # Re-enable exit on error

echo "------------------------------------------------------"

if [[ $CARGO_EXIT_CODE -eq 0 ]]; then
    echo "Proof generation completed successfully!"
else
    echo "Proof generation failed with exit code $CARGO_EXIT_CODE"
    exit $CARGO_EXIT_CODE
fi

###############################################################################
# DONE
###############################################################################
echo
echo "------------------------------------------------------"
echo " All steps completed successfully for user: ${USER_ID}"
echo " Derivation mode: ${DERIVE_MODE}"
echo " Proof mode: ${PROOF_MODE}"
echo "------------------------------------------------------"