// Transport Security Layer (TLS)
// Copyright (c) 2003-2004 Carlos Guzman Alvarez
// Copyright (C) 2006 Novell, Inc (http://www.novell.com)
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
using System;
using System.Collections;
using MonoSecurity::Mono.Security.X509;
using MonoSecurity::Mono.Security.X509.Extensions;
using SSCX = System.Security.Cryptography.X509Certificates;

namespace Mono.Security.Protocol.Tls.Handshake.Server
{
    internal class TlsClientCertificate : HandshakeMessage
    {
        #region Fields

        private X509CertificateCollection clientCertificates;

        #endregion

        #region Constructors

        public TlsClientCertificate(Context context, byte[] buffer)
            : base(context, HandshakeType.Certificate, buffer)
        {
        }

        #endregion

        #region Methods

        public override void Update()
        {
            foreach (var certificate in clientCertificates)
                Context.ClientSettings.Certificates.Add(new SSCX.X509Certificate(certificate.RawData));
        }

        public bool HasCertificate => clientCertificates.Count > 0;

        #endregion

        #region Protected Methods

        protected override void ProcessAsSsl3()
        {
            ProcessAsTls1();
        }

        protected override void ProcessAsTls1()
        {
            var bytesRead = 0;
            var length = ReadInt24();
            clientCertificates = new X509CertificateCollection();
            while (length > bytesRead)
            {
                var certLength = ReadInt24();
                bytesRead += certLength + 3;
                var cert = ReadBytes(certLength);
                clientCertificates.Add(new X509Certificate(cert));
            }

            if (clientCertificates.Count > 0)
                validateCertificates(clientCertificates);
            else if ((Context as ServerContext).ClientCertificateRequired)
                throw new TlsException(AlertDescription.NoCertificate);
        }

        #endregion

        #region Private Methods

        private bool checkCertificateUsage(X509Certificate cert)
        {
            var context = (ServerContext) Context;

            // certificate extensions are required for this
            // we "must" accept older certificates without proofs
            if (cert.Version < 3)
                return true;

            var ku = KeyUsages.none;
            switch (context.Negotiating.Cipher.ExchangeAlgorithmType)
            {
                case ExchangeAlgorithmType.RsaSign:
                case ExchangeAlgorithmType.RsaKeyX:
                    ku = KeyUsages.digitalSignature;
                    break;
                case ExchangeAlgorithmType.DiffieHellman:
                    ku = KeyUsages.keyAgreement;
                    break;
                case ExchangeAlgorithmType.Fortezza:
                    return false; // unsupported certificate type
            }

            KeyUsageExtension kux = null;
            ExtendedKeyUsageExtension eku = null;

            var xtn = cert.Extensions["2.5.29.15"];
            if (xtn != null)
                kux = new KeyUsageExtension(xtn);

            xtn = cert.Extensions["2.5.29.37"];
            if (xtn != null)
                eku = new ExtendedKeyUsageExtension(xtn);

            if (kux != null && eku != null)
                // RFC3280 states that when both KeyUsageExtension and 
                // ExtendedKeyUsageExtension are present then BOTH should
                // be valid
                return kux.Support(ku) &&
                       eku.KeyPurpose.Contains("1.3.6.1.5.5.7.3.2");
            if (kux != null)
                return kux.Support(ku);
            if (eku != null)
                // Client Authentication (1.3.6.1.5.5.7.3.2)
                return eku.KeyPurpose.Contains("1.3.6.1.5.5.7.3.2");

            // last chance - try with older (deprecated) Netscape extensions
            xtn = cert.Extensions["2.16.840.1.113730.1.1"];
            if (xtn != null)
            {
                var ct = new NetscapeCertTypeExtension(xtn);
                return ct.Support(NetscapeCertTypeExtension.CertTypes.SslClient);
            }

            // certificate isn't valid for SSL server usage
            return false;
        }

        private void validateCertificates(X509CertificateCollection certificates)
        {
            var context = (ServerContext) Context;
            var description = AlertDescription.BadCertificate;
            SSCX.X509Certificate client = null;
            int[] certificateErrors = null;

            // note: certificate may be null is no certificate is sent
            // (e.g. optional mutual authentication)
            if (certificates.Count > 0)
            {
                var leaf = certificates[0];

                var errors = new ArrayList();

                // SSL specific check - not all certificates can be 
                // used to server-side SSL some rules applies after 
                // all ;-)
                if (!checkCertificateUsage(leaf))
                    // WinError.h CERT_E_PURPOSE 0x800B0106
                    errors.Add(-2146762490);

                X509Chain verify;
                // was a chain supplied ? if so use it, if not
                if (certificates.Count > 1)
                {
                    // if so use it (and don't build our own)
                    var chain = new X509CertificateCollection(certificates);
                    chain.Remove(leaf);
                    verify = new X509Chain(chain);
                }
                else
                {
                    // if not, then let's build our own (based on what's available in the stores)
                    verify = new X509Chain();
                }

                var result = false;

                try
                {
                    result = verify.Build(leaf);
                }
                catch (Exception)
                {
                    result = false;
                }

                if (!result)
                    switch (verify.Status)
                    {
                        case X509ChainStatusFlags.InvalidBasicConstraints:
                            // WinError.h TRUST_E_BASIC_CONSTRAINTS 0x80096019
                            errors.Add(-2146869223);
                            break;

                        case X509ChainStatusFlags.NotSignatureValid:
                            // WinError.h TRUST_E_BAD_DIGEST 0x80096010
                            errors.Add(-2146869232);
                            break;

                        case X509ChainStatusFlags.NotTimeNested:
                            // WinError.h CERT_E_VALIDITYPERIODNESTING 0x800B0102
                            errors.Add(-2146762494);
                            break;

                        case X509ChainStatusFlags.NotTimeValid:
                            // WinError.h CERT_E_EXPIRED 0x800B0101
                            description = AlertDescription.CertificateExpired;
                            errors.Add(-2146762495);
                            break;

                        case X509ChainStatusFlags.PartialChain:
                            // WinError.h CERT_E_CHAINING 0x800B010A
                            description = AlertDescription.UnknownCA;
                            errors.Add(-2146762486);
                            break;

                        case X509ChainStatusFlags.UntrustedRoot:
                            // WinError.h CERT_E_UNTRUSTEDROOT 0x800B0109
                            description = AlertDescription.UnknownCA;
                            errors.Add(-2146762487);
                            break;

                        default:
                            // unknown error
                            description = AlertDescription.CertificateUnknown;
                            errors.Add((int) verify.Status);
                            break;
                    }

                client = new SSCX.X509Certificate(leaf.RawData);
                certificateErrors = (int[]) errors.ToArray(typeof(int));
            }
            else
            {
                certificateErrors = new int[0];
            }

            var certCollection = new SSCX.X509CertificateCollection();
            foreach (var certificate in certificates) certCollection.Add(new SSCX.X509Certificate(certificate.RawData));
            if (!context.SslStream.RaiseClientCertificateValidation(client, certificateErrors))
                throw new TlsException(
                    description,
                    "Invalid certificate received from client.");

            Context.ClientSettings.ClientCertificate = client;
        }

        #endregion
    }
}