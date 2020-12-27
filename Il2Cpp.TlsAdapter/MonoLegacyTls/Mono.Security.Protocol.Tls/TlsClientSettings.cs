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
using System.Security.Cryptography.X509Certificates;
using Mono.Security.Cryptography;

namespace Mono.Security.Protocol.Tls
{
    internal sealed class TlsClientSettings
    {
        #region Fields

        //private SecurityCompressionType		compressionMethod;
        private X509Certificate clientCertificate;

        #endregion

        #region Constructors

        public TlsClientSettings()
        {
            // this.compressionMethod	= SecurityCompressionType.None;
            Certificates = new X509CertificateCollection();
            TargetHost = string.Empty;
        }

        #endregion

        #region Methods

        public void UpdateCertificateRSA()
        {
            if (clientCertificate == null)
            {
                CertificateRSA = null;
            }
            else
            {
                var cert = new MonoSecurity::Mono.Security.X509.X509Certificate(clientCertificate.GetRawCertData());

                CertificateRSA = new RSAManaged(
                    cert.RSA.KeySize);

                CertificateRSA.ImportParameters(
                    cert.RSA.ExportParameters(false));
            }
        }

        #endregion

        #region Properties

        public string TargetHost { get; set; }

        public X509CertificateCollection Certificates { get; set; }

        public X509Certificate ClientCertificate
        {
            get => clientCertificate;
            set
            {
                clientCertificate = value;
                UpdateCertificateRSA();
            }
        }

        public RSAManaged CertificateRSA { get; private set; }

        /*
        public SecurityCompressionType CompressionMethod
        {
            get { return this.compressionMethod; }
            set 
            { 
                if (value != SecurityCompressionType.None)
                {
                    throw new NotSupportedException("Specified compression method is not supported");
                }
                this.compressionMethod = value; 
            }
        }
        */

        #endregion
    }
}