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
using System.Threading;
using Mono.Security.Protocol.Tls.Handshake;
using MonoSecurity::Mono.Security.Interface;
using X509CertificateCollection = MonoSecurity::Mono.Security.X509.X509CertificateCollection;

namespace Mono.Security.Protocol.Tls
{
    #region Delegates

#if INSIDE_SYSTEM
	internal
#else
    public
#endif
        delegate bool CertificateValidationCallback(
            X509Certificate certificate,
            int[] certificateErrors);

#if INSIDE_SYSTEM
	internal
#else
    public
#endif
        delegate ValidationResult CertificateValidationCallback2(X509CertificateCollection collection);

#if INSIDE_SYSTEM
	internal
#else
    public
#endif
        delegate X509Certificate CertificateSelectionCallback(
            System.Security.Cryptography.X509Certificates.X509CertificateCollection clientCertificates,
            X509Certificate serverCertificate,
            string targetHost,
            System.Security.Cryptography.X509Certificates.X509CertificateCollection serverRequestedCertificates);

#if INSIDE_SYSTEM
	internal
#else
    public
#endif
        delegate AsymmetricAlgorithm PrivateKeySelectionCallback(
            X509Certificate certificate,
            string targetHost);

    #endregion

#if INSIDE_SYSTEM
	internal
#else
    public
#endif
        class SslClientStream : SslStreamBase
    {
        public event CertificateValidationCallback2 ServerCertValidation2;

        #region Finalizer

        ~SslClientStream()
        {
            base.Dispose(false);
        }

        #endregion

        #region IDisposable Methods

        public override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing)
            {
                ServerCertValidation = null;
                ClientCertSelection = null;
                PrivateKeySelection = null;
                ServerCertValidation2 = null;
            }
        }

        #endregion

        #region Internal Events

        internal event CertificateValidationCallback ServerCertValidation;
        internal event CertificateSelectionCallback ClientCertSelection;
        internal event PrivateKeySelectionCallback PrivateKeySelection;

        #endregion

        #region Properties

        // required by HttpsClientStream for proxy support
        internal Stream InputBuffer => inputBuffer;

        public System.Security.Cryptography.X509Certificates.X509CertificateCollection ClientCertificates =>
            context.ClientSettings.Certificates;

        public X509Certificate SelectedClientCertificate => context.ClientSettings.ClientCertificate;

        #endregion

        #region Callback Properties

        public CertificateValidationCallback ServerCertValidationDelegate
        {
            get => ServerCertValidation;
            set => ServerCertValidation = value;
        }

        public CertificateSelectionCallback ClientCertSelectionDelegate
        {
            get => ClientCertSelection;
            set => ClientCertSelection = value;
        }

        public PrivateKeySelectionCallback PrivateKeyCertSelectionDelegate
        {
            get => PrivateKeySelection;
            set => PrivateKeySelection = value;
        }

        #endregion

        #region Constructors

        public SslClientStream(
            Stream stream,
            string targetHost,
            bool ownsStream)
            : this(
                stream, targetHost, ownsStream,
                SecurityProtocolType.Default, null)
        {
        }

        public SslClientStream(
            Stream stream,
            string targetHost,
            X509Certificate clientCertificate)
            : this(
                stream, targetHost, false, SecurityProtocolType.Default,
                new System.Security.Cryptography.X509Certificates.X509CertificateCollection(new[] {clientCertificate}))
        {
        }

        public SslClientStream(
            Stream stream,
            string targetHost,
            System.Security.Cryptography.X509Certificates.X509CertificateCollection clientCertificates) :
            this(
                stream, targetHost, false, SecurityProtocolType.Default,
                clientCertificates)
        {
        }

        public SslClientStream(
            Stream stream,
            string targetHost,
            bool ownsStream,
            SecurityProtocolType securityProtocolType)
            : this(
                stream, targetHost, ownsStream, securityProtocolType,
                new System.Security.Cryptography.X509Certificates.X509CertificateCollection())
        {
        }

        public SslClientStream(
            Stream stream,
            string targetHost,
            bool ownsStream,
            SecurityProtocolType securityProtocolType,
            System.Security.Cryptography.X509Certificates.X509CertificateCollection clientCertificates) :
            base(stream, ownsStream)
        {
            if (targetHost == null || targetHost.Length == 0)
                throw new ArgumentNullException("targetHost is null or an empty string.");

            context = new ClientContext(
                this,
                securityProtocolType,
                targetHost,
                clientCertificates);

            protocol = new ClientRecordProtocol(innerStream, (ClientContext) context);
        }

        #endregion

        #region Handshake Methods

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

        private void SafeEndReceiveRecord(IAsyncResult ar, bool ignoreEmpty = false)
        {
            var record = protocol.EndReceiveRecord(ar);
            if (!ignoreEmpty && (record == null || record.Length == 0))
                throw new TlsException(
                    AlertDescription.HandshakeFailiure,
                    "The server stopped the handshake.");
        }

        private enum NegotiateState
        {
            SentClientHello,
            ReceiveClientHelloResponse,
            SentCipherSpec,
            ReceiveCipherSpecResponse,
            SentKeyExchange,
            ReceiveFinishResponse,
            SentFinished
        }

        private class NegotiateAsyncResult : IAsyncResult
        {
            private readonly AsyncCallback _userCallback;
            private readonly object locker = new object();
            private bool completed;
            private ManualResetEvent handle;

            public NegotiateAsyncResult(AsyncCallback userCallback, object userState, NegotiateState state)
            {
                _userCallback = userCallback;
                AsyncState = userState;
                State = state;
            }

            public NegotiateState State { get; set; }

            public Exception AsyncException { get; private set; }

            public bool CompletedWithError
            {
                get
                {
                    if (!IsCompleted)
                        return false; // Perhaps throw InvalidOperationExcetion?

                    return null != AsyncException;
                }
            }

            public object AsyncState { get; }

            public WaitHandle AsyncWaitHandle
            {
                get
                {
                    lock (locker)
                    {
                        if (handle == null)
                            handle = new ManualResetEvent(completed);
                    }

                    return handle;
                }
            }

            public bool CompletedSynchronously => false;

            public bool IsCompleted
            {
                get
                {
                    lock (locker)
                    {
                        return completed;
                    }
                }
            }

            public void SetComplete(Exception ex)
            {
                lock (locker)
                {
                    if (completed)
                        return;

                    completed = true;
                    if (handle != null)
                        handle.Set();

                    if (_userCallback != null)
                        _userCallback.BeginInvoke(this, null, null);

                    AsyncException = ex;
                }
            }

            public void SetComplete()
            {
                SetComplete(null);
            }
        }

        internal override IAsyncResult BeginNegotiateHandshake(AsyncCallback callback, object state)
        {
            if (context.HandshakeState != HandshakeState.None) context.Clear();

            // Obtain supported cipher suites
            context.SupportedCiphers = CipherSuiteFactory.GetSupportedCiphers(false, context.SecurityProtocol);

            // Set handshake state
            context.HandshakeState = HandshakeState.Started;

            var result = new NegotiateAsyncResult(callback, state, NegotiateState.SentClientHello);

            // Begin sending the client hello
            protocol.BeginSendRecord(HandshakeType.ClientHello, NegotiateAsyncWorker, result);

            return result;
        }

        internal override void EndNegotiateHandshake(IAsyncResult result)
        {
            var negotiate = result as NegotiateAsyncResult;

            if (negotiate == null)
                throw new ArgumentNullException();
            if (!negotiate.IsCompleted)
                negotiate.AsyncWaitHandle.WaitOne();
            if (negotiate.CompletedWithError)
                throw negotiate.AsyncException;
        }

        private void NegotiateAsyncWorker(IAsyncResult result)
        {
            var negotiate = result.AsyncState as NegotiateAsyncResult;

            try
            {
                switch (negotiate.State)
                {
                    case NegotiateState.SentClientHello:
                        protocol.EndSendRecord(result);

                        // we are now ready to ready the receive the hello response.
                        negotiate.State = NegotiateState.ReceiveClientHelloResponse;

                        // Start reading the client hello response
                        protocol.BeginReceiveRecord(innerStream, NegotiateAsyncWorker, negotiate);
                        break;

                    case NegotiateState.ReceiveClientHelloResponse:
                        SafeEndReceiveRecord(result, true);

                        if (context.LastHandshakeMsg != HandshakeType.ServerHelloDone &&
                            (!context.AbbreviatedHandshake || context.LastHandshakeMsg != HandshakeType.ServerHello))
                        {
                            // Read next record (skip empty, e.g. warnings alerts)
                            protocol.BeginReceiveRecord(innerStream, NegotiateAsyncWorker, negotiate);
                            break;
                        }

                        // special case for abbreviated handshake where no ServerHelloDone is sent from the server
                        if (context.AbbreviatedHandshake)
                        {
                            ClientSessionCache.SetContextFromCache(context);
                            context.Negotiating.Cipher.ComputeKeys();
                            context.Negotiating.Cipher.InitializeCipher();

                            negotiate.State = NegotiateState.SentCipherSpec;

                            // Send Change Cipher Spec message with the current cipher
                            // or as plain text if this is the initial negotiation
                            protocol.BeginSendChangeCipherSpec(NegotiateAsyncWorker, negotiate);
                        }
                        else
                        {
                            // Send client certificate if requested
                            // even if the server ask for it it _may_ still be optional
                            var clientCertificate = context.ServerSettings.CertificateRequest;

                            using (var memstream = new MemoryStream())
                            {
                                // NOTE: sadly SSL3 and TLS1 differs in how they handle this and
                                // the current design doesn't allow a very cute way to handle 
                                // SSL3 alert warning for NoCertificate (41).
                                if (context.SecurityProtocol == SecurityProtocolType.Ssl3)
                                    clientCertificate = context.ClientSettings.Certificates != null &&
                                                        context.ClientSettings.Certificates.Count > 0;
                                // this works well with OpenSSL (but only for SSL3)

                                byte[] record = null;

                                if (clientCertificate)
                                {
                                    record = protocol.EncodeHandshakeRecord(HandshakeType.Certificate);
                                    memstream.Write(record, 0, record.Length);
                                }

                                // Send Client Key Exchange
                                record = protocol.EncodeHandshakeRecord(HandshakeType.ClientKeyExchange);
                                memstream.Write(record, 0, record.Length);

                                // Now initialize session cipher with the generated keys
                                context.Negotiating.Cipher.InitializeCipher();

                                // Send certificate verify if requested (optional)
                                if (clientCertificate && context.ClientSettings.ClientCertificate != null)
                                {
                                    record = protocol.EncodeHandshakeRecord(HandshakeType.CertificateVerify);
                                    memstream.Write(record, 0, record.Length);
                                }

                                // send the chnage cipher spec.
                                protocol.SendChangeCipherSpec(memstream);

                                // Send Finished message
                                record = protocol.EncodeHandshakeRecord(HandshakeType.Finished);
                                memstream.Write(record, 0, record.Length);

                                negotiate.State = NegotiateState.SentKeyExchange;

                                // send all the records.
                                innerStream.BeginWrite(memstream.GetBuffer(), 0, (int) memstream.Length,
                                    NegotiateAsyncWorker, negotiate);
                            }
                        }

                        break;

                    case NegotiateState.SentKeyExchange:
                        innerStream.EndWrite(result);

                        negotiate.State = NegotiateState.ReceiveFinishResponse;

                        protocol.BeginReceiveRecord(innerStream, NegotiateAsyncWorker, negotiate);

                        break;

                    case NegotiateState.ReceiveFinishResponse:
                        SafeEndReceiveRecord(result);

                        // Read record until server finished is received
                        if (context.HandshakeState != HandshakeState.Finished)
                        {
                            // If all goes well this will process messages:
                            // 		Change Cipher Spec
                            //		Server finished
                            protocol.BeginReceiveRecord(innerStream, NegotiateAsyncWorker, negotiate);
                        }
                        else
                        {
                            // Reset Handshake messages information
                            context.HandshakeMessages.Reset();

                            // Clear Key Info
                            context.ClearKeyInfo();

                            negotiate.SetComplete();
                        }

                        break;


                    case NegotiateState.SentCipherSpec:
                        protocol.EndSendChangeCipherSpec(result);

                        negotiate.State = NegotiateState.ReceiveCipherSpecResponse;

                        // Start reading the cipher spec response
                        protocol.BeginReceiveRecord(innerStream, NegotiateAsyncWorker, negotiate);
                        break;

                    case NegotiateState.ReceiveCipherSpecResponse:
                        SafeEndReceiveRecord(result, true);

                        if (context.HandshakeState != HandshakeState.Finished)
                        {
                            protocol.BeginReceiveRecord(innerStream, NegotiateAsyncWorker, negotiate);
                        }
                        else
                        {
                            negotiate.State = NegotiateState.SentFinished;
                            protocol.BeginSendRecord(HandshakeType.Finished, NegotiateAsyncWorker, negotiate);
                        }

                        break;

                    case NegotiateState.SentFinished:
                        protocol.EndSendRecord(result);

                        // Reset Handshake messages information
                        context.HandshakeMessages.Reset();

                        // Clear Key Info
                        context.ClearKeyInfo();

                        negotiate.SetComplete();

                        break;
                }
            }
            catch (TlsException ex)
            {
                try
                {
                    Exception e = ex;
                    protocol.SendAlert(ref e);
                }
                catch
                {
                }

                negotiate.SetComplete(new IOException("The authentication or decryption has failed.", ex));
            }
            catch (Exception ex)
            {
                try
                {
                    protocol.SendAlert(AlertDescription.InternalError);
                }
                catch
                {
                }

                negotiate.SetComplete(new IOException("The authentication or decryption has failed.", ex));
            }
        }

        #endregion

        #region Event Methods

        internal override X509Certificate OnLocalCertificateSelection(
            System.Security.Cryptography.X509Certificates.X509CertificateCollection clientCertificates,
            X509Certificate serverCertificate, string targetHost,
            System.Security.Cryptography.X509Certificates.X509CertificateCollection serverRequestedCertificates)
        {
            if (ClientCertSelection != null)
                return ClientCertSelection(
                    clientCertificates,
                    serverCertificate,
                    targetHost,
                    serverRequestedCertificates);

            return null;
        }

        internal override bool HaveRemoteValidation2Callback => ServerCertValidation2 != null;

        internal override ValidationResult OnRemoteCertificateValidation2(X509CertificateCollection collection)
        {
            var cb = ServerCertValidation2;
            if (cb != null)
                return cb(collection);
            return null;
        }

        internal override bool OnRemoteCertificateValidation(X509Certificate certificate, int[] errors)
        {
            if (ServerCertValidation != null) return ServerCertValidation(certificate, errors);

            return errors != null && errors.Length == 0;
        }

        internal virtual bool RaiseServerCertificateValidation(
            X509Certificate certificate,
            int[] certificateErrors)
        {
            return RaiseRemoteCertificateValidation(certificate, certificateErrors);
        }

        internal virtual ValidationResult RaiseServerCertificateValidation2(X509CertificateCollection collection)
        {
            return RaiseRemoteCertificateValidation2(collection);
        }

        internal X509Certificate RaiseClientCertificateSelection(
            System.Security.Cryptography.X509Certificates.X509CertificateCollection clientCertificates,
            X509Certificate serverCertificate,
            string targetHost,
            System.Security.Cryptography.X509Certificates.X509CertificateCollection serverRequestedCertificates)
        {
            return RaiseLocalCertificateSelection(clientCertificates, serverCertificate, targetHost,
                serverRequestedCertificates);
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