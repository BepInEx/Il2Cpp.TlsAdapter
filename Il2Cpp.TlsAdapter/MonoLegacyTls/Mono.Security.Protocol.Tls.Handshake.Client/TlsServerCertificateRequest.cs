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

using System.Text;

namespace Mono.Security.Protocol.Tls.Handshake.Client
{
    internal class TlsServerCertificateRequest : HandshakeMessage
    {
        #region Constructors

        public TlsServerCertificateRequest(Context context, byte[] buffer)
            : base(context, HandshakeType.CertificateRequest, buffer)
        {
        }

        #endregion

        #region Methods

        public override void Update()
        {
            base.Update();

            Context.ServerSettings.CertificateTypes = certificateTypes;
            Context.ServerSettings.DistinguisedNames = distinguisedNames;
            Context.ServerSettings.CertificateRequest = true;
        }

        #endregion

        #region Fields

        private ClientCertificateType[] certificateTypes;
        private string[] distinguisedNames;

        #endregion

        #region Protected Methods

        protected override void ProcessAsSsl3()
        {
            ProcessAsTls1();
        }

        protected override void ProcessAsTls1()
        {
            // Read requested certificate types
            int typesCount = ReadByte();

            certificateTypes = new ClientCertificateType[typesCount];

            for (var i = 0; i < typesCount; i++) certificateTypes[i] = (ClientCertificateType) ReadByte();

            /*
             * Read requested certificate authorities (Distinguised Names)
             * 
             * Name ::= SEQUENCE OF RelativeDistinguishedName
             * 
             * RelativeDistinguishedName ::= SET OF AttributeValueAssertion
             * 
             * AttributeValueAssertion ::= SEQUENCE {
             * attributeType OBJECT IDENTIFIER
             * attributeValue ANY }
             */
            if (ReadInt16() != 0)
            {
                var rdn = new ASN1(ReadBytes(ReadInt16()));

                distinguisedNames = new string[rdn.Count];

                for (var i = 0; i < rdn.Count; i++)
                {
                    // element[0] = attributeType
                    // element[1] = attributeValue
                    var element = new ASN1(rdn[i].Value);

                    distinguisedNames[i] = Encoding.UTF8.GetString(element[1].Value);
                }
            }
        }

        #endregion
    }
}