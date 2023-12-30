#!/bin/bash
CDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
rm -f ${CDIR}/../../src/SecretSharingDotNet.snk
# Decrypt the file
# --batch to prevent interactive command --yes to assume "yes" for questions
gpg --quiet --batch --yes --decrypt --passphrase="$PUBLISHER_SNK" --output ${CDIR}/../../src/SecretSharingDotNet.snk ${CDIR}/SecretSharingDotNetPublisher.snk.gpg
