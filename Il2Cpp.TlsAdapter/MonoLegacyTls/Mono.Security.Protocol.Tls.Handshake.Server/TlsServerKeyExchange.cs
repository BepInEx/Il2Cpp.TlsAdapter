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
using System;
using System.Security.Cryptography;
using SX509 = System.Security.Cryptography.X509Certificates;

namespace Mono.Security.Protocol.Tls.Handshake.Server
{
    internal class TlsServerKeyExchange : HandshakeMessage
    {
        #region Constructors

        public TlsServerKeyExchange(Context context)
            : base(context, HandshakeType.ServerKeyExchange)
        {
        }

        #endregion

        #region Methods

        public override void Update()
        {
            throw new NotSupportedException();
        }

        #endregion

        #region Private Methods

        private byte[] createSignature(RSA rsa, byte[] buffer)
        {
            var hash = new MD5SHA1();

            // Create server params array
            var stream = new TlsStream();

            stream.Write(Context.RandomCS);
            stream.Write(buffer, 0, buffer.Length);

            hash.ComputeHash(stream.ToArray());

            stream.Reset();

            return hash.CreateSignature(rsa);
        }

        #endregion

        #region Protected Methods

        protected override void ProcessAsSsl3()
        {
            ProcessAsTls1();
        }

        protected override void ProcessAsTls1()
        {
            var context = (ServerContext) Context;

            // Select the private key information
            var rsa = (RSA) context.SslStream.PrivateKeyCertSelectionDelegate(
                new SX509.X509Certificate(context.ServerSettings.Certificates[0].RawData),
                null);

            var rsaParams = rsa.ExportParameters(false);

            // Write Modulus
            WriteInt24(rsaParams.Modulus.Length);
            Write(rsaParams.Modulus, 0, rsaParams.Modulus.Length);

            // Write exponent
            WriteInt24(rsaParams.Exponent.Length);
            Write(rsaParams.Exponent, 0, rsaParams.Exponent.Length);

            // Write signed params
            var signature = createSignature(rsa, ToArray());
            WriteInt24(signature.Length);
            Write(signature);
        }

        #endregion
    }
}