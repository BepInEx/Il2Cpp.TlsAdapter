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

using System.Security.Cryptography.X509Certificates;

namespace Mono.Security.Protocol.Tls.Handshake.Client
{
    internal class TlsClientCertificate : HandshakeMessage
    {
        private X509Certificate clientCert;
        private bool clientCertSelected;

        #region Constructors

        public TlsClientCertificate(Context context)
            : base(context, HandshakeType.Certificate)
        {
        }

        #endregion

        #region Properties

        public X509Certificate ClientCertificate
        {
            get
            {
                if (!clientCertSelected)
                {
                    GetClientCertificate();
                    clientCertSelected = true;
                }

                return clientCert;
            }
        }

        #endregion

        #region Methods

        public override void Update()
        {
            base.Update();
            Reset();
        }

        #endregion

        #region Protected Methods

        private void GetClientCertificate()
        {
// TODO: Client certificate selection is unfinished
            var context = (ClientContext) Context;

            // note: the server may ask for mutual authentication 
            // but may not require it (i.e. it can be optional).
            if (context.ClientSettings.Certificates != null &&
                context.ClientSettings.Certificates.Count > 0)
                clientCert = context.SslStream.RaiseClientCertificateSelection(
                    Context.ClientSettings.Certificates,
                    new X509Certificate(Context.ServerSettings.Certificates[0].RawData),
                    Context.ClientSettings.TargetHost,
                    null);
            // Note: the application code can raise it's 
            // own exception to stop the connection too.

            // Update the selected client certificate
            context.ClientSettings.ClientCertificate = clientCert;
        }

        private void SendCertificates()
        {
            var chain = new TlsStream();

            var currentCert = ClientCertificate;
            while (currentCert != null)
            {
                var rawCert = currentCert.GetRawCertData();
                chain.WriteInt24(rawCert.Length);
                chain.Write(rawCert);
                currentCert = FindParentCertificate(currentCert);
            }

            WriteInt24((int) chain.Length);
            Write(chain.ToArray());
        }

        protected override void ProcessAsSsl3()
        {
            if (ClientCertificate != null) SendCertificates();
        }

        protected override void ProcessAsTls1()
        {
            if (ClientCertificate != null)
                SendCertificates();
            else // return message with empty certificate (see 7.4.6 in RFC2246)
                WriteInt24(0);
        }

        private X509Certificate FindParentCertificate(X509Certificate cert)
        {
#pragma warning disable 618
            // This certificate is the root certificate
            if (cert.GetName() == cert.GetIssuerName())
                return null;

            foreach (var certificate in Context.ClientSettings.Certificates)
                if (certificate.GetName() == cert.GetIssuerName())
                    return certificate;
            return null;
#pragma warning restore 618
        }

        #endregion
    }
}