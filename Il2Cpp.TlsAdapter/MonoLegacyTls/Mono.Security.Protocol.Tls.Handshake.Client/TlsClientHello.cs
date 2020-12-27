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

using System.Collections.Generic;
using System.Net;
using System.Text;

namespace Mono.Security.Protocol.Tls.Handshake.Client
{
    internal class TlsClientHello : HandshakeMessage
    {
        #region Fields

        private byte[] random;

        #endregion

        #region Constructors

        public TlsClientHello(Context context)
            : base(context, HandshakeType.ClientHello)
        {
        }

        #endregion

        #region Methods

        public override void Update()
        {
            var context = (ClientContext) Context;

            base.Update();

            context.ClientRandom = random;
            context.ClientHelloProtocol = Context.Protocol;

            random = null;
        }

        #endregion

        #region Protected Methods

        protected override void ProcessAsSsl3()
        {
            // Client Version
            Write(Context.Protocol);

            // Random bytes - Unix time + Radom bytes [28]
            var clientRandom = new TlsStream();
            clientRandom.Write(Context.GetUnixTime());
            clientRandom.Write(Context.GetSecureRandomBytes(28));
            random = clientRandom.ToArray();
            clientRandom.Reset();

            Write(random);

            // Session id
            // Check if we have a cache session we could reuse
            Context.SessionId = ClientSessionCache.FromHost(Context.ClientSettings.TargetHost);
            if (Context.SessionId != null)
            {
                Write((byte) Context.SessionId.Length);
                if (Context.SessionId.Length > 0) Write(Context.SessionId);
            }
            else
            {
                Write((byte) 0);
            }

            // Write length of Cipher suites			
            Write((short) (Context.SupportedCiphers.Count * 2));

            // Write Supported Cipher suites
            for (var i = 0; i < Context.SupportedCiphers.Count; i++)
                Write(((IList<CipherSuite>) Context.SupportedCiphers)[i].Code);

            // Compression methods length
            Write((byte) 1);

            // Compression methods ( 0 = none )
            Write((byte) Context.CompressionMethod);
        }

        protected override void ProcessAsTls1()
        {
            ProcessAsSsl3();

            // If applicable add the "server_name" extension to the hello message
            // http://www.ietf.org/rfc/rfc3546.txt
            var host = Context.ClientSettings.TargetHost;
            // Our TargetHost might be an address (not a host *name*) - see bug #8553
            // RFC3546 -> Literal IPv4 and IPv6 addresses are not permitted in "HostName".
            IPAddress addr;
            if (IPAddress.TryParse(host, out addr))
                return;

            var extensions = new TlsStream();
            var server_name = Encoding.UTF8.GetBytes(host);
            extensions.Write((short) 0x0000); // ExtensionType: server_name (0)
            extensions.Write((short) (server_name.Length + 5)); // ServerNameList (length)
            extensions.Write((short) (server_name.Length + 3)); // ServerName (length)
            extensions.Write((byte) 0x00); // NameType: host_name (0)
            extensions.Write((short) server_name.Length); // HostName (length)
            extensions.Write(server_name); // HostName (UTF8)
            Write((short) extensions.Length);
            Write(extensions.ToArray());
        }

        #endregion
    }
}