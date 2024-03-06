#
# THIS SOFTWARE IS PROVIDED BY CLOUDFLARE "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL CLOUDFLARE BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES  (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
 # mTLS-OCSP

This is a test script to add an OCSP verification option for mTLS client certificates. It can be attached to Cloudflare proxy endpoints protected by API Shield or Access mTLS with BYO CA.

## Usage

### Forward a client certificate to a Worker

It is to expose a client certificate to a Worker via `cf-client-cert-der-base64` request header.

https://developers.cloudflare.com/ssl/client-certificates/enable-mtls/#forward-a-client-certificate
```
  --data '{
    "settings": [
        {
            "hostname": "<HOSTNAME>",
            "client_certificate_forwarding": true
        }
    ]
}'
```


### Edit wrangler.toml

`routes`:

replace it with your mTLS application URL

`vars`: 

`CA_CLIENT_ISSUER` - replace it with your client certificate issuer

`CA_OCSP_ROOT` - replace it with your OCSP responder's issuer

* remove BEGIN/END lines and LF from a PEM


### Install packages asn1js and pkijs


