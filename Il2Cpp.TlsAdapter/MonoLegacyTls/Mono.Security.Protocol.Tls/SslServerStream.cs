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
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mono.Security.Protocol.Tls.Handshake;
using MonoSecurity::Mono.Security.Interface;

namespace Mono.Security.Protocol.Tls
{
#if INSIDE_SYSTEM
	internal
#else
    public
#endif
        class SslServerStream : SslStreamBase
    {
        #region Properties

        public X509Certificate ClientCertificate
        {
            get
            {
                if (context.HandshakeState == HandshakeState.Finished) return context.ClientSettings.ClientCertificate;

                return null;
            }
        }

        #endregion

        public event CertificateValidationCallback2 ClientCertValidation2;

        #region Finalizer

        ~SslServerStream()
        {
            Dispose(false);
        }

        #endregion

        #region IDisposable Methods

        public override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing)
            {
                ClientCertValidation = null;
                PrivateKeySelection = null;
            }
        }

        #endregion

        #region Internal Events

        internal event CertificateValidationCallback ClientCertValidation;
        internal event PrivateKeySelectionCallback PrivateKeySelection;

        #endregion

        #region Callback Properties

        public CertificateValidationCallback ClientCertValidationDelegate
        {
            get => ClientCertValidation;
            set => ClientCertValidation = value;
        }

        public PrivateKeySelectionCallback PrivateKeyCertSelectionDelegate
        {
            get => PrivateKeySelection;
            set => PrivateKeySelection = value;
        }

        #endregion

        #region Constructors

        public SslServerStream(
            Stream stream,
            X509Certificate serverCertificate) : this(
            stream,
            serverCertificate,
            false,
            false,
            SecurityProtocolType.Default)
        {
        }

        public SslServerStream(
            Stream stream,
            X509Certificate serverCertificate,
            bool clientCertificateRequired,
            bool ownsStream) : this(
            stream,
            serverCertificate,
            clientCertificateRequired,
            ownsStream,
            SecurityProtocolType.Default)
        {
        }

        public SslServerStream(
            Stream stream,
            X509Certificate serverCertificate,
            bool clientCertificateRequired,
            bool requestClientCertificate,
            bool ownsStream)
            : this(stream, serverCertificate, clientCertificateRequired, requestClientCertificate, ownsStream,
                SecurityProtocolType.Default)
        {
        }

        public SslServerStream(
            Stream stream,
            X509Certificate serverCertificate,
            bool clientCertificateRequired,
            bool ownsStream,
            SecurityProtocolType securityProtocolType)
            : this(stream, serverCertificate, clientCertificateRequired, false, ownsStream, securityProtocolType)
        {
        }

        public SslServerStream(
            Stream stream,
            X509Certificate serverCertificate,
            bool clientCertificateRequired,
            bool requestClientCertificate,
            bool ownsStream,
            SecurityProtocolType securityProtocolType)
            : base(stream, ownsStream)
        {
            context = new ServerContext(
                this,
                securityProtocolType,
                serverCertificate,
                clientCertificateRequired,
                requestClientCertificate);

            protocol = new ServerRecordProtocol(innerStream, (ServerContext) context);
        }

        #endregion

        #region Handsake Methods

        /*
            Client											Server

            ClientHello                 -------->
                                                            ServerHello
                                                            Certificate*
                                                            ServerKeyExchange*
                                                            CertificateRequest*
                                        <--------			ServerHelloDone
            Certificate*
            ClientKeyExchange
            CertificateVerify*
            [ChangeCipherSpec]
            Finished                    -------->
                                                            [ChangeCipherSpec]
                                        <--------           Finished
            Application Data            <------->			Application Data

                    Fig. 1 - Message flow for a full handshake		
        */

        internal override IAsyncResult BeginNegotiateHandshake(AsyncCallback callback, object state)
        {
            // Reset the context if needed
            if (context.HandshakeState != HandshakeState.None) context.Clear();

            // Obtain supported cipher suites
            context.SupportedCiphers = CipherSuiteFactory.GetSupportedCiphers(true, context.SecurityProtocol);

            // Set handshake state
            context.HandshakeState = HandshakeState.Started;

            // Receive Client Hello message
            return protocol.BeginReceiveRecord(innerStream, callback, state);
        }

        internal override void EndNegotiateHandshake(IAsyncResult asyncResult)
        {
            // Receive Client Hello message and ignore it
            protocol.EndReceiveRecord(asyncResult);

            // If received message is not an ClientHello send a
            // Fatal Alert
            if (context.LastHandshakeMsg != HandshakeType.ClientHello)
                protocol.SendAlert(AlertDescription.UnexpectedMessage);

            // Send ServerHello message
            protocol.SendRecord(HandshakeType.ServerHello);

            // Send ServerCertificate message
            protocol.SendRecord(HandshakeType.Certificate);

            // If the client certificate is required send the CertificateRequest message
            if (((ServerContext) context).ClientCertificateRequired ||
                ((ServerContext) context).RequestClientCertificate)
                protocol.SendRecord(HandshakeType.CertificateRequest);

            // Send ServerHelloDone message
            protocol.SendRecord(HandshakeType.ServerHelloDone);

            // Receive client response, until the Client Finished message
            // is received. IE can be interrupted at this stage and never
            // complete the handshake
            while (context.LastHandshakeMsg != HandshakeType.Finished)
            {
                var record = protocol.ReceiveRecord(innerStream);
                if (record == null || record.Length == 0)
                    throw new TlsException(
                        AlertDescription.HandshakeFailiure,
                        "The client stopped the handshake.");
            }

            // Send ChangeCipherSpec and ServerFinished messages
            protocol.SendChangeCipherSpec();
            protocol.SendRecord(HandshakeType.Finished);

            // The handshake is finished
            context.HandshakeState = HandshakeState.Finished;

            // Reset Handshake messages information
            context.HandshakeMessages.Reset();

            // Clear Key Info
            context.ClearKeyInfo();
        }

        #endregion

        #region Event Methods

        internal override X509Certificate OnLocalCertificateSelection(X509CertificateCollection clientCertificates,
            X509Certificate serverCertificate, string targetHost, X509CertificateCollection serverRequestedCertificates)
        {
            throw new NotSupportedException();
        }

        internal override bool OnRemoteCertificateValidation(X509Certificate certificate, int[] errors)
        {
            if (ClientCertValidation != null) return ClientCertValidation(certificate, errors);

            return errors != null && errors.Length == 0;
        }

        internal override bool HaveRemoteValidation2Callback => ClientCertValidation2 != null;

        internal override ValidationResult OnRemoteCertificateValidation2(
            MonoSecurity::Mono.Security.X509.X509CertificateCollection collection)
        {
            var cb = ClientCertValidation2;
            if (cb != null)
                return cb(collection);
            return null;
        }

        internal bool RaiseClientCertificateValidation(
            X509Certificate certificate,
            int[] certificateErrors)
        {
            return RaiseRemoteCertificateValidation(certificate, certificateErrors);
        }

        internal override AsymmetricAlgorithm OnLocalPrivateKeySelection(X509Certificate certificate, string targetHost)
        {
            if (PrivateKeySelection != null) return PrivateKeySelection(certificate, targetHost);

            return null;
        }

        internal AsymmetricAlgorithm RaisePrivateKeySelection(
            X509Certificate certificate,
            string targetHost)
        {
            return RaiseLocalPrivateKeySelection(certificate, targetHost);
        }

        #endregion
    }
}