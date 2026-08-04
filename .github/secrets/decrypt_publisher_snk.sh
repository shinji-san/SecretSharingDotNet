#!/bin/bash
# Abort on the first failure. Without this the script keeps going after a failed gpg
# call and still exits 0, because the trailing sed always succeeds -- the workflow step
# then reports success and the run only breaks later, at signing time, with an error
# that points at the missing key file instead of the failed decryption.
set -euo pipefail
CDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Fail loudly on a missing or empty secret. An empty PUBLISHER_PUB_KEY would otherwise
# rewrite AssemblyInfo.cs with an empty public key rather than stopping the run.
: "${PUBLISHER_SNK:?PUBLISHER_SNK is unset or empty}"
: "${PUBLISHER_PUB_KEY:?PUBLISHER_PUB_KEY is unset or empty}"

rm -f "${CDIR}/../../src/SecretSharingDotNet.snk"
# Decrypt the file
# --batch to prevent interactive command --yes to assume "yes" for questions
gpg --quiet --batch --yes --decrypt --passphrase="$PUBLISHER_SNK" --output "${CDIR}/../../src/SecretSharingDotNet.snk" "${CDIR}/SecretSharingDotNetPublisher.snk.gpg"
sed -i -r "s/(InternalsVisibleTo.*PublicKey=)([0-9a-f]+)(.*)/\1$PUBLISHER_PUB_KEY\3/g" "${CDIR}/../../src/Properties/AssemblyInfo.cs"
