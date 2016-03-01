# Changelog

## 0.0.1 (2016-03-01)

* Initial Release

* Publish to [hex.pm](https://hex.pm/packages/libdecaf).

* Library Support
  * ECDH
    * `libdecaf:decaf_x25519_base_scalarmul/1`
    * `libdecaf:decaf_x25519_direct_scalarmul/2`
    * `libdecaf:decaf_x448_base_scalarmul/1`
    * `libdecaf:decaf_x448_direct_scalarmul/2`
  * EdDSA
    * `libdecaf:decaf_255_eddsa_derive_public_key/1`
    * `libdecaf:decaf_255_eddsa_sign/4`
    * `libdecaf:decaf_255_eddsa_verify/4`
    * `libdecaf:decaf_448_eddsa_derive_public_key/1`
    * `libdecaf:decaf_448_eddsa_sign/5`
    * `libdecaf:decaf_448_eddsa_verify/5`
  * SHA-2
    * `libdecaf:sha2_512/2`
    * Streaming support
      * `libdecaf:sha2_512_init/0`, `libdecaf:sha2_512_update/2`, `libdecaf:sha2_512_final/2`
  * SHA-3
    * `libdecaf:sha3_224/1`
    * `libdecaf:sha3_256/1`
    * `libdecaf:sha3_384/1`
    * `libdecaf:sha3_512/1`
    * `libdecaf:shake128/2`
    * `libdecaf:shake256/2`
    * Streaming support
      * `libdecaf:sha3_224_init/0`, `libdecaf:sha3_224_update/2`, `libdecaf:sha3_224_final/1`
      * `libdecaf:sha3_256_init/0`, `libdecaf:sha3_256_update/2`, `libdecaf:sha3_256_final/1`
      * `libdecaf:sha3_384_init/0`, `libdecaf:sha3_384_update/2`, `libdecaf:sha3_384_final/1`
      * `libdecaf:sha3_512_init/0`, `libdecaf:sha3_512_update/2`, `libdecaf:sha3_512_final/1`
      * `libdecaf:shake128_init/0`, `libdecaf:shake128_update/2`, `libdecaf:shake128_final/2`
      * `libdecaf:shake256_init/0`, `libdecaf:shake256_update/2`, `libdecaf:shake256_final/2`

* Basic Tests based on the [draft-irtf-cfrg-eddsa](https://tools.ietf.org/html/draft-irtf-cfrg-eddsa), [FIPS 180-4](http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf), [FIPS 202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf), and [RFC 7748](https://tools.ietf.org/html/rfc7748) test vectors.
