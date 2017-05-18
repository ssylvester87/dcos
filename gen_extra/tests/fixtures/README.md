# Fixtures

This directory contains custom CA certificate fixutures that represent
various supported CA certificate configurations supported by DC/OS.

Files were copied from https://github.com/mesosphere/dcos-custom-ca-cert-configs/
repository which contians detailed information about each cerficiate set.

## Variants

* `rsa_root` - Certificate signed by RSA private key which is self signed root
   CA certificate.

   URL:
   https://github.com/mesosphere/dcos-custom-ca-cert-configs/tree/329f0ebaf5b26fa41f031f16cb8c10b03cc6c322/test_02

* `rsa_intermediate` - Certificate signed by RSA private key which is a second
   child certificate in a chain.

   URL:
   https://github.com/mesosphere/dcos-custom-ca-cert-configs/tree/329f0ebaf5b26fa41f031f16cb8c10b03cc6c322/test_03
