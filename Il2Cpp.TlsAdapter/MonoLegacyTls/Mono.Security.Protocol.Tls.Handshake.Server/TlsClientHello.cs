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

using System.Collections.Generic;

namespace Mono.Security.Protocol.Tls.Handshake.Server
{
    internal class TlsClientHello : HandshakeMessage
    {
        #region Constructors

        public TlsClientHello(Context context, byte[] buffer)
            : base(context, HandshakeType.ClientHello, buffer)
        {
        }

        #endregion

        #region Methods

        public override void Update()
        {
            base.Update();

            selectCipherSuite();
            selectCompressionMethod();

            Context.SessionId = sessionId;
            Context.ClientRandom = random;
            Context.ProtocolNegotiated = true;
        }

        #endregion

        #region Private Fields

        private byte[] random;
        private byte[] sessionId;
        private short[] cipherSuites;
        private byte[] compressionMethods;

        #endregion

        #region Protected Methods

        protected override void ProcessAsSsl3()
        {
            ProcessAsTls1();
        }

        protected override void ProcessAsTls1()
        {
            // Client Version
            processProtocol(ReadInt16());

            // Random bytes - Unix time + Radom bytes [28]
            random = ReadBytes(32);

            // Session id
            // Send the session ID empty
            sessionId = ReadBytes(ReadByte());

            // Read Supported Cipher Suites count
            cipherSuites = new short[ReadInt16() / 2];

            // Read Cipher Suites
            for (var i = 0; i < cipherSuites.Length; i++) cipherSuites[i] = ReadInt16();

            // Compression methods length
            compressionMethods = new byte[ReadByte()];

            for (var i = 0; i < compressionMethods.Length; i++) compressionMethods[i] = ReadByte();
        }

        #endregion

        #region Private Methods

        private void processProtocol(short protocol)
        {
            // a server MUST reply with the hight version supported (`true` for fallback)
            // so a TLS 1.2 client (like Google Chrome) will be returned that the server uses TLS 1.0
            // instead of an alert about the protocol
            var clientProtocol = Context.DecodeProtocolCode(protocol, true);

            if ((clientProtocol & Context.SecurityProtocolFlags) == clientProtocol ||
                (Context.SecurityProtocolFlags & SecurityProtocolType.Default) == SecurityProtocolType.Default)
            {
                Context.SecurityProtocol = clientProtocol;
                Context.SupportedCiphers = CipherSuiteFactory.GetSupportedCiphers(true, clientProtocol);
            }
            else
            {
                throw new TlsException(AlertDescription.ProtocolVersion,
                    "Incorrect protocol version received from server");
            }
        }

        private void selectCipherSuite()
        {
            var index = 0;

            for (var i = 0; i < cipherSuites.Length; i++)
                if ((index = Context.SupportedCiphers.IndexOf(cipherSuites[i])) != -1)
                {
                    Context.Negotiating.Cipher = ((IList<CipherSuite>) Context.SupportedCiphers)[index];
                    break;
                }

            if (Context.Negotiating.Cipher == null)
                throw new TlsException(AlertDescription.InsuficientSecurity, "Insuficient Security");
        }

        private void selectCompressionMethod()
        {
            Context.CompressionMethod = SecurityCompressionType.None;
        }

        #endregion
    }
}