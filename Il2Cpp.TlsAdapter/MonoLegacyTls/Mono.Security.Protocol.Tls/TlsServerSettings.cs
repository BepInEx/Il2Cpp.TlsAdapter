// Transport Security Layer (TLS)
// Copyright (c) 2003-2004 Carlos Guzman Alvarez

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

extern alias MonoSecurity;
using System.Security.Cryptography;
using Mono.Security.Cryptography;
using Mono.Security.Protocol.Tls.Handshake;
using MonoSecurity::Mono.Security.X509;

namespace Mono.Security.Protocol.Tls
{
    internal class TlsServerSettings
    {
        #region Methods

        public void UpdateCertificateRSA()
        {
            if (Certificates == null ||
                Certificates.Count == 0)
            {
                CertificateRSA = null;
            }
            else
            {
                CertificateRSA = new RSAManaged(
                    Certificates[0].RSA.KeySize);

                CertificateRSA.ImportParameters(
                    Certificates[0].RSA.ExportParameters(false));
            }
        }

        #endregion

        #region Constructors

        #endregion

        #region Fields

        #endregion

        #region Properties

        public bool ServerKeyExchange { get; set; }

        public X509CertificateCollection Certificates { get; set; }

        public RSA CertificateRSA { get; private set; }

        public RSAParameters RsaParameters { get; set; }

        public byte[] SignedParams { get; set; }

        public bool CertificateRequest { get; set; }

        public ClientCertificateType[] CertificateTypes { get; set; }

        public string[] DistinguisedNames { get; set; }

        #endregion
    }
}