/**
 * THIS SOFTWARE IS PROVIDED BY CLOUDFLARE "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL CLOUDFLARE BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES  (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

import * as asn1js from 'asn1js'
import { getRandomValues, Certificate, Extension, OCSPRequest, OCSPResponse,  GeneralName, BasicOCSPResponse } from 'pkijs';

export class MTLSValidator {
  constructor(clientCA, rootCA) {
    this.clientCA = this.buildCertificate(this.b64stringToArrayBuffer(clientCA));
    this.rootCA = this.buildCertificate(this.b64stringToArrayBuffer(rootCA));
  }
  
  b64stringToArrayBuffer(b64str) {
    let byteStr = atob(b64str);
    let bytes = new Uint8Array(byteStr.length);
    for (let i = 0; i < byteStr.length; i++) {
      bytes[i] = byteStr.charCodeAt(i);
    }
    return bytes.buffer;
  }    

  buildCertificate(certificateBuffer) {
    let asn1 = asn1js.fromBER(certificateBuffer);
    if(asn1.offset === (-1)) {
      throw new Error("Cannot parse binary data - CAs not correctly loaded");
      return null
    } 
    return new Certificate({ schema: asn1.result });
  }

  getOCSPUrl(){
    const extAIA = this.clientCert.extensions.find((extension) => extension.extnID === '1.3.6.1.5.5.7.1.1');
    const parsedOcspValue = extAIA.parsedValue.accessDescriptions.find((parsedValue) => parsedValue.accessMethod === '1.3.6.1.5.5.7.48.1');
    return parsedOcspValue.accessLocation.value;
  }

  //https://pkijs.org/docs/classes/ResponseData.html#responses
  async validateOCSPResponse(OCSPResponse){
          
    const asnOcspRespBasic = asn1js.fromBER(OCSPResponse.responseBytes.response.valueBlock.valueHex);
    const ocspBasicResp = new BasicOCSPResponse({ schema: asnOcspRespBasic.result });
    
    const ok = await ocspBasicResp.verify({ trustedCerts: [this.rootCA] });
    return ok
  }

  async doOCSPRequest(){
    const ocspReq = new OCSPRequest();
    ocspReq.tbsRequest.requestorName = new GeneralName({ type: 4, value: this.clientCert.subject, });
    
    await ocspReq.createForCertificate(this.clientCert, { hashAlgorithm: "SHA-256", issuerCertificate: this.clientCA, });
    
    const nonce = getRandomValues(new Uint8Array(10));
    ocspReq.tbsRequest.requestExtensions = [
      new Extension({
        extnID: "1.3.6.1.5.5.7.48.1.2", // nonce
        extnValue: new asn1js.OctetString({ valueHex: nonce.buffer }).toBER(),
      })
    ];
    // Encode OCSP request
    const ocspReqRaw = ocspReq.toSchema(true).toBER();
    
    const ocspUrl = this.getOCSPUrl()

    const oRequest = new Request(ocspUrl, { method: 'POST', body: ocspReqRaw });
    oRequest.headers.set('content-type', 'application/ocsp-request');
    const oResponce = await fetch(oRequest);
  
    // Parse OCSP response
    const ocspRespRaw = await oResponce.arrayBuffer();
    const asnOcspResp = asn1js.fromBER(ocspRespRaw);
    const ocspResp = new OCSPResponse({ schema: asnOcspResp.result });
    if (!ocspResp.responseBytes) {
      throw new Error("Empty OCSP Response - nothing to verify");
    }
    return ocspResp
  }

  async getCertificateStatus(clientCertificate){
    this.clientCert = this.buildCertificate(this.b64stringToArrayBuffer(clientCertificate));
    const OCSPResponse = await this.doOCSPRequest();
    const ResponseIsValidated = this.validateOCSPResponse(OCSPResponse);
    if (!ResponseIsValidated){
      throw new Error("OCSP Response is not valid");
    }
    const certstatus = await ocspResp.getCertificateStatus(this.clientCert, this.clientCA);
    return certstatus.status;
  }

  async isRevoked(clientCertificate){
    //https://datatracker.ietf.org/doc/html/rfc6960
    // 0 is Good
    // 1 is Revoked
    // 2 is Unknown
    const status = await this.getCertificateStatus(clientCertificate);
    console.log(status);
    if (status === 1) return true;
    return false;
  }
}

export default {

  async fetch(request, env, ctx) {
    try{
      let mTLSValidator = new MTLSValidator(`${env.CA_CLIENT_ISSUER}`,`${env.CA_OCSP_ROOT}`)
      
      const b64ClientCert = request.headers.get('cf-client-cert-der-base64') || null;

      if (b64ClientCert == null){
        return new Response(JSON.stringify({ error: "cert_not_found" }), { status:400 })
      }
      
      /* Simpler version
      let isRevoked = await mTLSValidator.IsRevoked(b64ClientCert);
      if (isRevoked === true){
        return new Response({ error: "cert_revoked" }, { status:400 })
      }
      */
      const status = await mTLSValidator.getCertificateStatus(b64ClientCert)
      let newRequest = new Request(request);
      newRequest.headers.set("OCSP-Processed","True")
      newRequest.headers.set("OCSP-Status",status)
      newRequest.headers.set("OCSP-Revoked",status === 1 ? "True" : "False")
      return await fetch(newRequest)

    }catch(e){
      return new Response(JSON.stringify({ error: e.message }), { status: 500 })
    }
  }
}

