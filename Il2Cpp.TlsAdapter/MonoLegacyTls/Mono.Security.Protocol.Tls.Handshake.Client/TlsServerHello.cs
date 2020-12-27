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

using System;

namespace Mono.Security.Protocol.Tls.Handshake.Client
{
    internal class TlsServerHello : HandshakeMessage
    {
        #region Constructors

        public TlsServerHello(Context context, byte[] buffer)
            : base(context, HandshakeType.ServerHello, buffer)
        {
        }

        #endregion

        #region Methods

        public override void Update()
        {
            base.Update();

            Context.SessionId = sessionId;
            Context.ServerRandom = random;
            Context.Negotiating.Cipher = cipherSuite;
            Context.CompressionMethod = compressionMethod;
            Context.ProtocolNegotiated = true;

            DebugHelper.WriteLine("Selected Cipher Suite {0}", cipherSuite.Name);
            DebugHelper.WriteLine("Client random", Context.ClientRandom);
            DebugHelper.WriteLine("Server random", Context.ServerRandom);

            // Compute ClientRandom + ServerRandom
            var clen = Context.ClientRandom.Length;
            var slen = Context.ServerRandom.Length;
            var rlen = clen + slen;
            var cs = new byte[rlen];
            Buffer.BlockCopy(Context.ClientRandom, 0, cs, 0, clen);
            Buffer.BlockCopy(Context.ServerRandom, 0, cs, clen, slen);
            Context.RandomCS = cs;

            // Server Random + Client Random
            var sc = new byte[rlen];
            Buffer.BlockCopy(Context.ServerRandom, 0, sc, 0, slen);
            Buffer.BlockCopy(Context.ClientRandom, 0, sc, slen, clen);
            Context.RandomSC = sc;
        }

        #endregion

        #region Private Methods

        private void processProtocol(short protocol)
        {
            var serverProtocol = Context.DecodeProtocolCode(protocol);

            if ((serverProtocol & Context.SecurityProtocolFlags) == serverProtocol ||
                (Context.SecurityProtocolFlags & SecurityProtocolType.Default) == SecurityProtocolType.Default)
            {
                Context.SecurityProtocol = serverProtocol;
                Context.SupportedCiphers = CipherSuiteFactory.GetSupportedCiphers(false, serverProtocol);

                DebugHelper.WriteLine("Selected protocol {0}", serverProtocol);
            }
            else
            {
                throw new TlsException(
                    AlertDescription.ProtocolVersion,
                    "Incorrect protocol version received from server");
            }
        }

        #endregion

        #region Fields

        private SecurityCompressionType compressionMethod;
        private byte[] random;
        private byte[] sessionId;
        private CipherSuite cipherSuite;

        #endregion

        #region Protected Methods

        protected override void ProcessAsSsl3()
        {
            ProcessAsTls1();
        }

        protected override void ProcessAsTls1()
        {
            // Read protocol version
            processProtocol(ReadInt16());

            // Read random  - Unix time + Random bytes
            random = ReadBytes(32);

            // Read Session id
            int length = ReadByte();
            if (length > 0)
            {
                sessionId = ReadBytes(length);
                ClientSessionCache.Add(Context.ClientSettings.TargetHost, sessionId);
                Context.AbbreviatedHandshake = Compare(sessionId, Context.SessionId);
            }
            else
            {
                Context.AbbreviatedHandshake = false;
            }

            // Read cipher suite
            var cipherCode = ReadInt16();
            if (Context.SupportedCiphers.IndexOf(cipherCode) == -1)
                // The server has sent an invalid ciphersuite
                throw new TlsException(AlertDescription.InsuficientSecurity,
                    "Invalid cipher suite received from server");
            cipherSuite = Context.SupportedCiphers[cipherCode];

            // Read compression methods ( always 0 )
            compressionMethod = (SecurityCompressionType) ReadByte();
        }

        #endregion
    }
}