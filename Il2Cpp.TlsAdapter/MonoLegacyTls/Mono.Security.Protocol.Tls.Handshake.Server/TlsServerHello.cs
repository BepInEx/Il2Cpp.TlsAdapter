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

namespace Mono.Security.Protocol.Tls.Handshake.Server
{
    internal class TlsServerHello : HandshakeMessage
    {
        #region Constructors

        public TlsServerHello(Context context)
            : base(context, HandshakeType.ServerHello)
        {
        }

        #endregion

        #region Methods

        public override void Update()
        {
            base.Update();

            var random = new TlsStream();

            // Compute Server Random
            random.Write(unixTime);
            random.Write(this.random);

            Context.ServerRandom = random.ToArray();

            // Compute ClientRandom + ServerRandom
            random.Reset();
            random.Write(Context.ClientRandom);
            random.Write(Context.ServerRandom);

            Context.RandomCS = random.ToArray();

            // Server Random + Client Random
            random.Reset();
            random.Write(Context.ServerRandom);
            random.Write(Context.ClientRandom);

            Context.RandomSC = random.ToArray();

            random.Reset();
        }

        #endregion

        #region Private Fields

        private int unixTime;
        private byte[] random;

        #endregion

        #region Protected Methods

        protected override void ProcessAsSsl3()
        {
            ProcessAsTls1();
        }

        protected override void ProcessAsTls1()
        {
            // Write protocol version
            Write(Context.Protocol);

            // Write Unix time
            unixTime = Context.GetUnixTime();
            Write(unixTime);

            // Write Random bytes
            random = Context.GetSecureRandomBytes(28);
            Write(random);

            if (Context.SessionId == null)
            {
                WriteByte(0);
            }
            else
            {
                // Write Session ID length
                WriteByte((byte) Context.SessionId.Length);

                // Write Session ID
                Write(Context.SessionId);
            }

            // Write selected cipher suite
            Write(Context.Negotiating.Cipher.Code);

            // Write selected compression method
            WriteByte((byte) Context.CompressionMethod);
        }

        #endregion
    }
}