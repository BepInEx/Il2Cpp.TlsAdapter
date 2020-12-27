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

namespace Mono.Security.Protocol.Tls.Handshake.Client
{
    internal class TlsServerKeyExchange : HandshakeMessage
    {
        #region Constructors

        public TlsServerKeyExchange(Context context, byte[] buffer)
            : base(context, HandshakeType.ServerKeyExchange, buffer)
        {
            verifySignature();
        }

        #endregion

        #region Methods

        public override void Update()
        {
            base.Update();

            Context.ServerSettings.ServerKeyExchange = true;
            Context.ServerSettings.RsaParameters = rsaParams;
            Context.ServerSettings.SignedParams = signedParams;
        }

        #endregion

        #region Private Methods

        private void verifySignature()
        {
            var hash = new MD5SHA1();

            // Calculate size of server params
            var size = rsaParams.Modulus.Length + rsaParams.Exponent.Length + 4;

            // Create server params array
            var stream = new TlsStream();

            stream.Write(Context.RandomCS);
            stream.Write(ToArray(), 0, size);

            hash.ComputeHash(stream.ToArray());

            stream.Reset();

            var isValidSignature = hash.VerifySignature(
                Context.ServerSettings.CertificateRSA,
                signedParams);

            if (!isValidSignature)
                throw new TlsException(
                    AlertDescription.DecodeError,
                    "Data was not signed with the server certificate.");
        }

        #endregion

        #region Fields

        private RSAParameters rsaParams;
        private byte[] signedParams;

        #endregion

        #region Protected Methods

        protected override void ProcessAsSsl3()
        {
            ProcessAsTls1();
        }

        protected override void ProcessAsTls1()
        {
            rsaParams = new RSAParameters();

            // Read modulus
            rsaParams.Modulus = ReadBytes(ReadInt16());

            // Read exponent
            rsaParams.Exponent = ReadBytes(ReadInt16());

            // Read signed params
            signedParams = ReadBytes(ReadInt16());
        }

        #endregion
    }
}