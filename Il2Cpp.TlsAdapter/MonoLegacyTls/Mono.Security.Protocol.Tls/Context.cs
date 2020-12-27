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
using System.Security.Cryptography;
using Mono.Security.Protocol.Tls.Handshake;

namespace Mono.Security.Protocol.Tls
{
    internal abstract class Context
    {
        #region Constructors

        public Context(SecurityProtocolType securityProtocolType)
        {
            SecurityProtocol = securityProtocolType;
            CompressionMethod = SecurityCompressionType.None;
            ServerSettings = new TlsServerSettings();
            ClientSettings = new TlsClientSettings();
            HandshakeMessages = new TlsStream();
            SessionId = null;
            HandshakeState = HandshakeState.None;
            random = RandomNumberGenerator.Create();
        }

        #endregion

        #region Internal Constants

        internal const short MAX_FRAGMENT_SIZE = 16384; // 2^14
        internal const short TLS1_PROTOCOL_CODE = (0x03 << 8) | 0x01;
        internal const short SSL3_PROTOCOL_CODE = (0x03 << 8) | 0x00;
        internal const long UNIX_BASE_TICKS = 621355968000000000;

        #endregion

        #region Fields

        // Protocol version

        // Sesison ID

        // Compression method

        // Information sent and request by the server in the Handshake protocol

        // Client configuration

        // Cipher suite information
        private SecurityParameters current;
        private SecurityParameters negotiating;

        // Last handshake message received

        // Handshake negotiation state

        // Misc

        // Sequence numbers

        // Random data

        // Key information

        // Handshake hashes

        // Secure Random generator		
        private readonly RandomNumberGenerator random;

        // Record protocol

        #endregion

        #region Properties

        public bool AbbreviatedHandshake { get; set; }

        public bool ProtocolNegotiated { get; set; }

        public bool ChangeCipherSpecDone { get; set; }

        public SecurityProtocolType SecurityProtocol
        {
            get
            {
                if ((SecurityProtocolFlags & SecurityProtocolType.Tls) == SecurityProtocolType.Tls ||
                    (SecurityProtocolFlags & SecurityProtocolType.Default) == SecurityProtocolType.Default)
                    return SecurityProtocolType.Tls;

                if ((SecurityProtocolFlags & SecurityProtocolType.Ssl3) == SecurityProtocolType.Ssl3)
                    return SecurityProtocolType.Ssl3;

                throw new NotSupportedException("Unsupported security protocol type");
            }

            set => SecurityProtocolFlags = value;
        }

        public SecurityProtocolType SecurityProtocolFlags { get; private set; }

        public short Protocol
        {
            get
            {
                switch (SecurityProtocol)
                {
                    case SecurityProtocolType.Tls:
                    case SecurityProtocolType.Default:
                        return TLS1_PROTOCOL_CODE;

                    case SecurityProtocolType.Ssl3:
                        return SSL3_PROTOCOL_CODE;

                    case SecurityProtocolType.Ssl2:
                    default:
                        throw new NotSupportedException("Unsupported security protocol type");
                }
            }
        }

        public byte[] SessionId { get; set; }

        public SecurityCompressionType CompressionMethod { get; set; }

        public TlsServerSettings ServerSettings { get; private set; }

        public TlsClientSettings ClientSettings { get; private set; }

        public HandshakeType LastHandshakeMsg { get; set; }

        public HandshakeState HandshakeState { get; set; }

        public bool ReceivedConnectionEnd { get; set; }

        public bool SentConnectionEnd { get; set; }

        public CipherSuiteCollection SupportedCiphers { get; set; }

        public TlsStream HandshakeMessages { get; private set; }

        public ulong WriteSequenceNumber { get; set; }

        public ulong ReadSequenceNumber { get; set; }

        public byte[] ClientRandom { get; set; }

        public byte[] ServerRandom { get; set; }

        public byte[] RandomCS { get; set; }

        public byte[] RandomSC { get; set; }

        public byte[] MasterSecret { get; set; }

        public byte[] ClientWriteKey { get; set; }

        public byte[] ServerWriteKey { get; set; }

        public byte[] ClientWriteIV { get; set; }

        public byte[] ServerWriteIV { get; set; }

        public RecordProtocol RecordProtocol { get; set; }

        #endregion

        #region Methods

        public int GetUnixTime()
        {
            var now = DateTime.UtcNow;

            return (int) ((now.Ticks - UNIX_BASE_TICKS) / TimeSpan.TicksPerSecond);
        }

        public byte[] GetSecureRandomBytes(int count)
        {
            var secureBytes = new byte[count];

            random.GetNonZeroBytes(secureBytes);

            return secureBytes;
        }

        public virtual void Clear()
        {
            CompressionMethod = SecurityCompressionType.None;
            ServerSettings = new TlsServerSettings();
            ClientSettings = new TlsClientSettings();
            HandshakeMessages = new TlsStream();
            SessionId = null;
            HandshakeState = HandshakeState.None;

            ClearKeyInfo();
        }

        public virtual void ClearKeyInfo()
        {
            // Clear Master Secret
            if (MasterSecret != null)
            {
                Array.Clear(MasterSecret, 0, MasterSecret.Length);
                MasterSecret = null;
            }

            // Clear client and server random
            if (ClientRandom != null)
            {
                Array.Clear(ClientRandom, 0, ClientRandom.Length);
                ClientRandom = null;
            }

            if (ServerRandom != null)
            {
                Array.Clear(ServerRandom, 0, ServerRandom.Length);
                ServerRandom = null;
            }

            if (RandomCS != null)
            {
                Array.Clear(RandomCS, 0, RandomCS.Length);
                RandomCS = null;
            }

            if (RandomSC != null)
            {
                Array.Clear(RandomSC, 0, RandomSC.Length);
                RandomSC = null;
            }

            // Clear client keys
            if (ClientWriteKey != null)
            {
                Array.Clear(ClientWriteKey, 0, ClientWriteKey.Length);
                ClientWriteKey = null;
            }

            if (ClientWriteIV != null)
            {
                Array.Clear(ClientWriteIV, 0, ClientWriteIV.Length);
                ClientWriteIV = null;
            }

            // Clear server keys
            if (ServerWriteKey != null)
            {
                Array.Clear(ServerWriteKey, 0, ServerWriteKey.Length);
                ServerWriteKey = null;
            }

            if (ServerWriteIV != null)
            {
                Array.Clear(ServerWriteIV, 0, ServerWriteIV.Length);
                ServerWriteIV = null;
            }

            // Reset handshake messages
            HandshakeMessages.Reset();

            // Clear MAC keys if protocol is different than Ssl3
            // SSLv3 needs them inside Mono.Security.Protocol.Tls.SslCipherSuite.Compute[Client|Server]RecordMAC
            if (SecurityProtocolFlags != SecurityProtocolType.Ssl3)
            {
//				this.clientWriteMAC = null;
//				this.serverWriteMAC = null;
            }
        }

        public SecurityProtocolType DecodeProtocolCode(short code, bool allowFallback = false)
        {
            switch (code)
            {
                case TLS1_PROTOCOL_CODE:
                    return SecurityProtocolType.Tls;

                case SSL3_PROTOCOL_CODE:
                    return SecurityProtocolType.Ssl3;

                default:
                    // if allowed we'll continue using TLS (1.0) even if the other side is capable of using a newer
                    // version of the TLS protocol
                    if (allowFallback && code > TLS1_PROTOCOL_CODE)
                        return SecurityProtocolType.Tls;
                    throw new NotSupportedException("Unsupported security protocol type");
            }
        }

        public void ChangeProtocol(short protocol)
        {
            var protocolType = DecodeProtocolCode(protocol);

            if ((protocolType & SecurityProtocolFlags) == protocolType ||
                (SecurityProtocolFlags & SecurityProtocolType.Default) == SecurityProtocolType.Default)
            {
                SecurityProtocol = protocolType;
                SupportedCiphers = CipherSuiteFactory.GetSupportedCiphers(this is ServerContext, protocolType);
            }
            else
            {
                throw new TlsException(AlertDescription.ProtocolVersion,
                    "Incorrect protocol version received from server");
            }
        }


        public SecurityParameters Current
        {
            get
            {
                if (current == null)
                    current = new SecurityParameters();
                if (current.Cipher != null)
                    current.Cipher.Context = this;
                return current;
            }
        }

        public SecurityParameters Negotiating
        {
            get
            {
                if (negotiating == null)
                    negotiating = new SecurityParameters();
                if (negotiating.Cipher != null)
                    negotiating.Cipher.Context = this;
                return negotiating;
            }
        }

        public SecurityParameters Read { get; private set; }

        public SecurityParameters Write { get; private set; }

        public void StartSwitchingSecurityParameters(bool client)
        {
            if (client)
            {
                // everything we write from now on is encrypted
                Write = negotiating;
                // but we still read with the older cipher until we 
                // receive the ChangeCipherSpec message
                Read = current;
            }
            else
            {
                // everything we read from now on is encrypted
                Read = negotiating;
                // but we still write with the older cipher until we 
                // receive the ChangeCipherSpec message
                Write = current;
            }

            current = negotiating;
        }

        public void EndSwitchingSecurityParameters(bool client)
        {
            SecurityParameters temp;
            if (client)
            {
                temp = Read;
                // we now read with the new, negotiated, security parameters
                Read = current;
            }
            else
            {
                temp = Write;
                // we now write with the new, negotiated, security parameters
                Write = current;
            }

            // so we clear the old one (last reference)
            if (temp != null)
                temp.Clear();
            negotiating = temp;
            // and are now ready for a future renegotiation
        }

        #endregion
    }
}