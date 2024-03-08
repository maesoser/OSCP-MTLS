# mTLS OCSP Validator

This small worker adds an OCSP verification option for mTLS client certificates. It can be attached to Cloudflare proxy endpoints protected by API Shield or Access mTLS with BYO CA.

## Usage

### Edit wrangler.toml

- **routes**: replace it with your mTLS application URL
- **vars**: 
  - `CA_CLIENT_ISSUER`: Replace it with your client certificate issuer
  - `CA_OCSP_ROOT`: Replace it with your OCSP responder's issuer
 
## TODO

  - Add OCSP validation response caching
  - Document the option of forcing an specific OCSP Validation URI
