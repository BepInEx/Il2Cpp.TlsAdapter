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
using Mono.Security.Protocol.Tls.Handshake;
using MonoSecurity::Mono.Security.Interface;
using MonoSecurity::Mono.Security.X509;
using X509Certificate = System.Security.Cryptography.X509Certificates.X509Certificate;
using X509CertificateCollection = MonoSecurity::Mono.Security.X509.X509CertificateCollection;

namespace Mono.Security.Protocol.Tls
{
    internal class ServerContext : Context
    {
        #region Constructors

        public ServerContext(
            SslServerStream stream,
            SecurityProtocolType securityProtocolType,
            X509Certificate serverCertificate,
            bool clientCertificateRequired,
            bool requestClientCertificate)
            : base(securityProtocolType)
        {
            SslStream = stream;
            ClientCertificateRequired = clientCertificateRequired;
            RequestClientCertificate = requestClientCertificate;

            // Convert the System.Security cert to a Mono Cert
            var cert = new MonoSecurity::Mono.Security.X509.X509Certificate(serverCertificate.GetRawCertData());

            // Add server certificate to the certificate collection
            ServerSettings.Certificates = new X509CertificateCollection();
            ServerSettings.Certificates.Add(cert);

            ServerSettings.UpdateCertificateRSA();

            if (CertificateValidationHelper.SupportsX509Chain)
            {
                // Build the chain for the certificate and if the chain is correct, add all certificates 
                // (except the root certificate [FIRST ONE] ... the client is supposed to know that one,
                // otherwise the whole concept of a trusted chain doesn't work out ... 
                var chain = new X509Chain(X509StoreManager.IntermediateCACertificates);

                if (chain.Build(cert))
                    for (var j = chain.Chain.Count - 1; j > 0; j--)
                        ServerSettings.Certificates.Add(chain.Chain[j]);
            }

            // Add requested certificate types
            ServerSettings.CertificateTypes = new ClientCertificateType [ServerSettings.Certificates.Count];
            for (var j = 0; j < ServerSettings.CertificateTypes.Length; j++)
                ServerSettings.CertificateTypes[j] = ClientCertificateType.RSA;

            if (CertificateValidationHelper.SupportsX509Chain)
            {
                // Add certificate authorities
                var trusted = X509StoreManager.TrustedRootCertificates;
                var list = new string [trusted.Count];
                var i = 0;
                foreach (var root in trusted) list[i++] = root.IssuerName;
                ServerSettings.DistinguisedNames = list;
            }
        }

        #endregion

        #region Fields

        #endregion

        #region Properties

        public SslServerStream SslStream { get; }

        public bool ClientCertificateRequired { get; }

        public bool RequestClientCertificate { get; }

        #endregion
    }
}