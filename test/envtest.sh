#!/bin/sh
# envtest.sh: an env -i child still reads PID 1's credential URI from /proc/1/environ.
#
#   docker run --rm --user 1000:1000 \
#     -e AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/DEMO \
#     -v "$PWD/test/envtest.sh:/envtest.sh:ro" alpine:3.20 /envtest.sh
env -i /bin/sh -c '
  echo "child own AWS vars: $(env | grep -c AWS_)"
  echo "child reads /proc/1/environ:"
  tr "\000" "\n" < /proc/1/environ | grep AWS_ || echo "  (nothing / denied)"
  echo "child uid: $(id -u)"
'
