//
// HttpsClientStream.cs: Glue between HttpWebRequest and SslClientStream to
//      reduce reflection usage.
//
// Author:
//      Sebastien Pouliot  <sebastien@ximian.com>
//
// Copyright (C) 2004-2007 Novell, Inc. (http://www.novell.com)
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System;
using System.IO;
using System.Net;
using SNS = System.Net.Security;
using SNCX = System.Security.Cryptography.X509Certificates;

namespace Mono.Security.Protocol.Tls
{
    // Note: DO NOT REUSE this class - instead use SslClientStream

    [Obsolete("This class is obsolete and will be removed shortly.")]
    internal class HttpsClientStream : SslClientStream
    {
        private readonly HttpWebRequest _request;
        private int _status;

        public HttpsClientStream(Stream stream, SNCX.X509CertificateCollection clientCertificates,
            HttpWebRequest request, byte[] buffer)
            : base(stream, request.Address.Host, false, (SecurityProtocolType)
                ServicePointManager.SecurityProtocol, clientCertificates)
        {
            // this constructor permit access to the WebRequest to call
            // ICertificatePolicy.CheckValidationResult
            _request = request;
            _status = 0;
            if (buffer != null)
                InputBuffer.Write(buffer, 0, buffer.Length);
            // also saved from reflection
            CheckCertRevocationStatus = ServicePointManager.CheckCertificateRevocationList;

            ClientCertSelection += delegate(SNCX.X509CertificateCollection clientCerts,
                SNCX.X509Certificate serverCertificate,
                string targetHost, SNCX.X509CertificateCollection serverRequestedCertificates)
            {
                return clientCerts == null || clientCerts.Count == 0 ? null : clientCerts[0];
            };
            PrivateKeySelection += delegate(SNCX.X509Certificate certificate, string targetHost)
            {
                var cert = certificate as SNCX.X509Certificate2;
                return cert == null ? null : cert.PrivateKey;
            };
        }

        public bool TrustFailure
        {
            get
            {
                switch (_status)
                {
                    case -2146762486: // CERT_E_CHAINING		0x800B010A
                    case -2146762487: // CERT_E_UNTRUSTEDROOT	0x800B0109
                        return true;
                    default:
                        return false;
                }
            }
        }

        internal override bool RaiseServerCertificateValidation(SNCX.X509Certificate certificate,
            int[] certificateErrors)
        {
            var failed = certificateErrors.Length > 0;
            // only one problem can be reported by this interface
            _status = failed ? certificateErrors[0] : 0;

#pragma warning disable 618
            if (ServicePointManager.CertificatePolicy != null)
            {
                var sp = _request.ServicePoint;
                var res = ServicePointManager.CertificatePolicy.CheckValidationResult(sp, certificate, _request,
                    _status);
                if (!res)
                    return false;
                failed = true;
            }
#pragma warning restore 618
            if (HaveRemoteValidation2Callback)
                return failed; // The validation already tried the 2.0 callback 

            var cb = ServicePointManager.ServerCertificateValidationCallback;
            if (cb != null)
            {
                SNS.SslPolicyErrors ssl_errors = 0;
                foreach (var i in certificateErrors)
                    if (i == -2146762490) // TODO: is this what happens when the purpose is wrong?
                        ssl_errors |= SNS.SslPolicyErrors.RemoteCertificateNotAvailable;
                    else if (i == -2146762481)
                        ssl_errors |= SNS.SslPolicyErrors.RemoteCertificateNameMismatch;
                    else
                        ssl_errors |= SNS.SslPolicyErrors.RemoteCertificateChainErrors;
                var cert2 = new SNCX.X509Certificate2(certificate.GetRawCertData());
                var chain = new SNCX.X509Chain();
                if (!chain.Build(cert2))
                    ssl_errors |= SNS.SslPolicyErrors.RemoteCertificateChainErrors;
                return cb(_request, cert2, chain, ssl_errors);
            }

            return failed;
        }
    }
}