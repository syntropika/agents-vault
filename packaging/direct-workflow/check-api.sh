#!/bin/sh
# Direct-mode development smoke check. The interpreter, this script, and curl
# receive the secret; this workflow does not provide protected credential custody.
set -eu
LC_ALL=C
export LC_ALL
: "${APP_ENV:?APP_ENV is required}"
: "${API_BASE_URL:?API_BASE_URL is required}"
: "${API_TOKEN:?API_TOKEN is required}"
case "$APP_ENV" in development|test) ;; *) printf '%s\n' 'Use a development or test environment.' >&2; exit 2 ;; esac
case "$API_TOKEN" in
    *[!A-Za-z0-9._~+/=-]*)
        printf '%s\n' 'API_TOKEN must contain only ASCII bearer-token characters.' >&2
        exit 2
        ;;
esac
if [ "$#" -ne 0 ]; then
    printf '%s\n' 'This development check takes no arguments.' >&2
    exit 2
fi
# The configured URL and every program/script in this direct task are trusted
# by the operator. Use a disposable development token for the local test fixture.
# Header input uses stdin so the token is not placed in curl's arguments.
# The restricted token alphabet prevents injected header lines. Redirects are
# disabled, and the pipeline preserves curl's exit status.
printf 'Authorization: Bearer %s\n' "$API_TOKEN" |
    /usr/bin/curl --disable --silent --show-error --fail --max-time 5 \
        --header @- "$API_BASE_URL/health"
