// Transport Security Layer (TLS)
// Copyright (c) 2003-2004 Carlos Guzman Alvarez
// Copyright (C) 2006-2007 Novell, Inc (http://www.novell.com)
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
using MonoSecurity::Mono.Security.Interface;

namespace Mono.Security.Protocol.Tls
{
#if INSIDE_SYSTEM
	internal
#else
    public
#endif
        abstract class SslStreamBase : Stream, IDisposable
    {
        #region Constructors

        protected SslStreamBase(
            Stream stream,
            bool ownsStream)
        {
            if (stream == null) throw new ArgumentNullException("stream is null.");
            if (!stream.CanRead || !stream.CanWrite)
                throw new ArgumentNullException("stream is not both readable and writable.");

            inputBuffer = new MemoryStream();
            innerStream = stream;
            this.ownsStream = ownsStream;
            negotiate = new object();
            read = new object();
            write = new object();
            negotiationComplete = new ManualResetEvent(false);
        }

        #endregion

        private delegate void AsyncHandshakeDelegate(InternalAsyncResult asyncResult, bool fromWrite);

        #region Internal Async Result/State Class

        private class InternalAsyncResult : IAsyncResult
        {
            private readonly AsyncCallback _userCallback;
            private readonly object locker = new object();
            private bool completed;
            private ManualResetEvent handle;

            public InternalAsyncResult(AsyncCallback userCallback, object userState, byte[] buffer, int offset,
                int count, bool fromWrite, bool proceedAfterHandshake)
            {
                _userCallback = userCallback;
                AsyncState = userState;
                Buffer = buffer;
                Offset = offset;
                Count = count;
                FromWrite = fromWrite;
                ProceedAfterHandshake = proceedAfterHandshake;
            }

            public bool ProceedAfterHandshake { get; }

            public bool FromWrite { get; }

            public byte[] Buffer { get; }

            public int Offset { get; }

            public int Count { get; }

            public int BytesRead { get; private set; }

            public Exception AsyncException { get; private set; }

            public bool CompletedWithError
            {
                get
                {
                    if (IsCompleted == false)
                        return false;
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

            private void SetComplete(Exception ex, int bytesRead)
            {
                lock (locker)
                {
                    if (completed)
                        return;

                    completed = true;
                    AsyncException = ex;
                    BytesRead = bytesRead;
                    if (handle != null)
                        handle.Set();
                }

                if (_userCallback != null)
                    _userCallback.BeginInvoke(this, null, null);
            }

            public void SetComplete(Exception ex)
            {
                SetComplete(ex, 0);
            }

            public void SetComplete(int bytesRead)
            {
                SetComplete(null, bytesRead);
            }

            public void SetComplete()
            {
                SetComplete(null, 0);
            }
        }

        #endregion

        #region Fields

        private static readonly ManualResetEvent record_processing = new ManualResetEvent(true);

        internal Stream innerStream;
        internal MemoryStream inputBuffer;
        internal Context context;
        internal RecordProtocol protocol;
        internal bool ownsStream;
        private volatile bool disposed;
        private readonly object negotiate;
        private readonly object read;
        private readonly object write;
        private readonly ManualResetEvent negotiationComplete;

        #endregion

        #region Handshakes

        private void AsyncHandshakeCallback(IAsyncResult asyncResult)
        {
            var internalResult = asyncResult.AsyncState as InternalAsyncResult;

            try
            {
                try
                {
                    EndNegotiateHandshake(asyncResult);
                }
                catch (Exception ex)
                {
                    protocol.SendAlert(ref ex);
                    throw new IOException("The authentication or decryption has failed.", ex);
                }

                if (internalResult.ProceedAfterHandshake)
                {
                    //kick off the read or write process (whichever called us) after the handshake is complete
                    if (internalResult.FromWrite)
                        InternalBeginWrite(internalResult);
                    else
                        InternalBeginRead(internalResult);
                    negotiationComplete.Set();
                }
                else
                {
                    negotiationComplete.Set();
                    internalResult.SetComplete();
                }
            }
            catch (Exception ex)
            {
                negotiationComplete.Set();
                internalResult.SetComplete(ex);
            }
        }

        internal bool MightNeedHandshake
        {
            get
            {
                if (context.HandshakeState == HandshakeState.Finished)
                    return false;
                lock (negotiate)
                {
                    return context.HandshakeState != HandshakeState.Finished;
                }
            }
        }

        internal void NegotiateHandshake()
        {
            if (MightNeedHandshake)
            {
                var ar = new InternalAsyncResult(null, null, null, 0, 0, false, false);

                //if something already started negotiation, wait for it.
                //otherwise end it ourselves.
                if (!BeginNegotiateHandshake(ar))
                    negotiationComplete.WaitOne();
                else
                    EndNegotiateHandshake(ar);
            }
        }

        public IAsyncResult BeginHandshake()
        {
            if (MightNeedHandshake)
            {
                var ar = new InternalAsyncResult(null, null, null, 0, 0, false, false);
                //if something already started negotiation, wait for it.
                //otherwise end it ourselves.
                BeginNegotiateHandshake(ar);
                return ar;
            }

            return null;
        }

        public void EndHandshake(IAsyncResult result)
        {
            EndNegotiateHandshake(result as InternalAsyncResult);
        }

        #endregion

        #region Abstracts/Virtuals

        internal abstract IAsyncResult BeginNegotiateHandshake(AsyncCallback callback, object state);
        internal abstract void EndNegotiateHandshake(IAsyncResult result);

        internal abstract X509Certificate OnLocalCertificateSelection(X509CertificateCollection clientCertificates,
            X509Certificate serverCertificate,
            string targetHost,
            X509CertificateCollection serverRequestedCertificates);

        internal abstract bool OnRemoteCertificateValidation(X509Certificate certificate, int[] errors);

        internal abstract ValidationResult OnRemoteCertificateValidation2(
            MonoSecurity::Mono.Security.X509.X509CertificateCollection collection);

        internal abstract bool HaveRemoteValidation2Callback { get; }

        internal abstract AsymmetricAlgorithm
            OnLocalPrivateKeySelection(X509Certificate certificate, string targetHost);

        #endregion

        #region Event Methods

        internal X509Certificate RaiseLocalCertificateSelection(X509CertificateCollection certificates,
            X509Certificate remoteCertificate,
            string targetHost,
            X509CertificateCollection requestedCertificates)
        {
            return OnLocalCertificateSelection(certificates, remoteCertificate, targetHost, requestedCertificates);
        }

        internal bool RaiseRemoteCertificateValidation(X509Certificate certificate, int[] errors)
        {
            return OnRemoteCertificateValidation(certificate, errors);
        }

        internal ValidationResult RaiseRemoteCertificateValidation2(
            MonoSecurity::Mono.Security.X509.X509CertificateCollection collection)
        {
            return OnRemoteCertificateValidation2(collection);
        }

        internal AsymmetricAlgorithm RaiseLocalPrivateKeySelection(
            X509Certificate certificate,
            string targetHost)
        {
            return OnLocalPrivateKeySelection(certificate, targetHost);
        }

        #endregion

        #region Security Properties

        public bool CheckCertRevocationStatus { get; set; }

        public CipherAlgorithmType CipherAlgorithm
        {
            get
            {
                if (context.HandshakeState == HandshakeState.Finished)
                    return context.Current.Cipher.CipherAlgorithmType;

                return CipherAlgorithmType.None;
            }
        }

        public int CipherStrength
        {
            get
            {
                if (context.HandshakeState == HandshakeState.Finished) return context.Current.Cipher.EffectiveKeyBits;

                return 0;
            }
        }

        public HashAlgorithmType HashAlgorithm
        {
            get
            {
                if (context.HandshakeState == HandshakeState.Finished) return context.Current.Cipher.HashAlgorithmType;

                return HashAlgorithmType.None;
            }
        }

        public int HashStrength
        {
            get
            {
                if (context.HandshakeState == HandshakeState.Finished) return context.Current.Cipher.HashSize * 8;

                return 0;
            }
        }

        public int KeyExchangeStrength
        {
            get
            {
                if (context.HandshakeState == HandshakeState.Finished)
                    return context.ServerSettings.Certificates[0].RSA.KeySize;

                return 0;
            }
        }

        public ExchangeAlgorithmType KeyExchangeAlgorithm
        {
            get
            {
                if (context.HandshakeState == HandshakeState.Finished)
                    return context.Current.Cipher.ExchangeAlgorithmType;

                return ExchangeAlgorithmType.None;
            }
        }

        public SecurityProtocolType SecurityProtocol
        {
            get
            {
                if (context.HandshakeState == HandshakeState.Finished) return context.SecurityProtocol;

                return 0;
            }
        }

        public X509Certificate ServerCertificate
        {
            get
            {
                if (context.HandshakeState == HandshakeState.Finished)
                    if (context.ServerSettings.Certificates != null &&
                        context.ServerSettings.Certificates.Count > 0)
                        return new X509Certificate(context.ServerSettings.Certificates[0].RawData);

                return null;
            }
        }

        // this is used by Mono's certmgr tool to download certificates
        internal MonoSecurity::Mono.Security.X509.X509CertificateCollection ServerCertificates =>
            context.ServerSettings.Certificates;

        #endregion

        #region Stream Overrides and Async Stream Operations

        private bool BeginNegotiateHandshake(InternalAsyncResult asyncResult)
        {
            try
            {
                lock (negotiate)
                {
                    if (context.HandshakeState == HandshakeState.None)
                    {
                        BeginNegotiateHandshake(AsyncHandshakeCallback, asyncResult);

                        return true;
                    }

                    return false;
                }
            }
            catch (Exception ex)
            {
                negotiationComplete.Set();
                protocol.SendAlert(ref ex);

                throw new IOException("The authentication or decryption has failed.", ex);
            }
        }

        private void EndNegotiateHandshake(InternalAsyncResult asyncResult)
        {
            if (asyncResult.IsCompleted == false)
                asyncResult.AsyncWaitHandle.WaitOne();

            if (asyncResult.CompletedWithError) throw asyncResult.AsyncException;
        }

        public override IAsyncResult BeginRead(
            byte[] buffer,
            int offset,
            int count,
            AsyncCallback callback,
            object state)
        {
            checkDisposed();

            if (buffer == null) throw new ArgumentNullException("buffer is a null reference.");
            if (offset < 0) throw new ArgumentOutOfRangeException("offset is less than 0.");
            if (offset > buffer.Length)
                throw new ArgumentOutOfRangeException("offset is greater than the length of buffer.");
            if (count < 0) throw new ArgumentOutOfRangeException("count is less than 0.");
            if (count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(
                    "count is less than the length of buffer minus the value of the offset parameter.");

            var asyncResult = new InternalAsyncResult(callback, state, buffer, offset, count, false, true);

            if (MightNeedHandshake)
            {
                if (!BeginNegotiateHandshake(asyncResult))
                {
                    //we made it down here so the handshake was not started.
                    //another thread must have started it in the mean time.
                    //wait for it to complete and then perform our original operation
                    negotiationComplete.WaitOne();

                    InternalBeginRead(asyncResult);
                }
            }
            else
            {
                InternalBeginRead(asyncResult);
            }

            return asyncResult;
        }

        // bigger than max record length for SSL/TLS
        private readonly byte[] recbuf = new byte[16384];

        private void InternalBeginRead(InternalAsyncResult asyncResult)
        {
            try
            {
                var preReadSize = 0;

                lock (read)
                {
                    // If actual buffer is fully read, reset it
                    var shouldReset = inputBuffer.Position == inputBuffer.Length && inputBuffer.Length > 0;

                    // If the buffer isn't fully read, but does have data, we need to immediately
                    // read the info from the buffer and let the user know that they have more data.
                    var shouldReadImmediately = inputBuffer.Length > 0 && asyncResult.Count > 0;

                    if (shouldReset)
                        resetBuffer();
                    else if (shouldReadImmediately)
                        preReadSize = inputBuffer.Read(asyncResult.Buffer, asyncResult.Offset, asyncResult.Count);
                }

                // This is explicitly done outside the synclock to avoid 
                // any potential deadlocks in the delegate call.
                if (0 < preReadSize)
                    asyncResult.SetComplete(preReadSize);
                else if (recordStream.Position < recordStream.Length)
                    InternalReadCallback_inner(asyncResult, recbuf, new object[] {recbuf, asyncResult}, false, 0);
                else if (!context.ReceivedConnectionEnd)
                    // this will read data from the network until we have (at least) one
                    // record to send back to the caller
                    innerStream.BeginRead(recbuf, 0, recbuf.Length,
                        InternalReadCallback, new object[] {recbuf, asyncResult});
                else
                    // We're done with the connection so we need to let the caller know with 0 bytes read
                    asyncResult.SetComplete(0);
            }
            catch (Exception ex)
            {
                protocol.SendAlert(ref ex);
                throw new IOException("The authentication or decryption has failed.", ex);
            }
        }


        private readonly MemoryStream recordStream = new MemoryStream();

        // read encrypted data until we have enough to decrypt (at least) one
        // record and return are the records (may be more than one) we have
        private void InternalReadCallback(IAsyncResult result)
        {
            var state = (object[]) result.AsyncState;
            var recbuf = (byte[]) state[0];
            var internalResult = (InternalAsyncResult) state[1];

            try
            {
                checkDisposed();

                var n = innerStream.EndRead(result);
                if (n > 0)
                {
                    // Add the just received data to the waiting data
                    recordStream.Write(recbuf, 0, n);
                }
                else
                {
                    // 0 length data means this read operation is done (lost connection in the case of a network stream).
                    internalResult.SetComplete(0);
                    return;
                }

                InternalReadCallback_inner(internalResult, recbuf, state, true, n);
            }
            catch (Exception ex)
            {
                internalResult.SetComplete(ex);
            }
        }

        // read encrypted data until we have enough to decrypt (at least) one
        // record and return are the records (may be more than one) we have
        private void InternalReadCallback_inner(InternalAsyncResult internalResult, byte[] recbuf, object[] state,
            bool didRead, int n)
        {
            if (disposed)
                return;

            try
            {
                var dataToReturn = false;
                var pos = recordStream.Position;

                recordStream.Position = 0;
                byte[] record = null;

                // don't try to decode record unless we have at least 5 bytes
                // i.e. type (1), protocol (2) and length (2)
                if (recordStream.Length >= 5) record = protocol.ReceiveRecord(recordStream);

                // a record of 0 length is valid (and there may be more record after it)
                while (record != null)
                {
                    // we probably received more stuff after the record, and we must keep it!
                    var remainder = recordStream.Length - recordStream.Position;
                    byte[] outofrecord = null;
                    if (remainder > 0)
                    {
                        outofrecord = new byte[remainder];
                        recordStream.Read(outofrecord, 0, outofrecord.Length);
                    }

                    lock (read)
                    {
                        var position = inputBuffer.Position;

                        if (record.Length > 0)
                        {
                            // Write new data to the inputBuffer
                            inputBuffer.Seek(0, SeekOrigin.End);
                            inputBuffer.Write(record, 0, record.Length);

                            // Restore buffer position
                            inputBuffer.Seek(position, SeekOrigin.Begin);
                            dataToReturn = true;
                        }
                    }

                    recordStream.SetLength(0);
                    record = null;

                    if (remainder > 0)
                    {
                        recordStream.Write(outofrecord, 0, outofrecord.Length);
                        // type (1), protocol (2) and length (2)
                        if (recordStream.Length >= 5)
                        {
                            // try to see if another record is available
                            recordStream.Position = 0;
                            record = protocol.ReceiveRecord(recordStream);
                            if (record == null)
                                pos = recordStream.Length;
                        }
                        else
                        {
                            pos = remainder;
                        }
                    }
                    else
                    {
                        pos = 0;
                    }
                }

                if (!dataToReturn && (!didRead || n > 0))
                {
                    if (context.ReceivedConnectionEnd)
                    {
                        internalResult.SetComplete(0);
                    }
                    else
                    {
                        // there is no record to return to caller and (possibly) more data waiting
                        // so continue reading from network (and appending to stream)
                        recordStream.Position = recordStream.Length;
                        innerStream.BeginRead(recbuf, 0, recbuf.Length,
                            InternalReadCallback, state);
                    }
                }
                else
                {
                    // we have record(s) to return -or- no more available to read from network
                    // reset position for further reading
                    recordStream.Position = pos;

                    var bytesRead = 0;
                    lock (read)
                    {
                        bytesRead = inputBuffer.Read(internalResult.Buffer, internalResult.Offset,
                            internalResult.Count);
                    }

                    internalResult.SetComplete(bytesRead);
                }
            }
            catch (Exception ex)
            {
                internalResult.SetComplete(ex);
            }
        }

        private void InternalBeginWrite(InternalAsyncResult asyncResult)
        {
            try
            {
                // Send the buffer as a TLS record

                lock (write)
                {
                    var record = protocol.EncodeRecord(
                        ContentType.ApplicationData, asyncResult.Buffer, asyncResult.Offset, asyncResult.Count);

                    innerStream.BeginWrite(
                        record, 0, record.Length, InternalWriteCallback, asyncResult);
                }
            }
            catch (Exception ex)
            {
                protocol.SendAlert(ref ex);
                Close();

                throw new IOException("The authentication or decryption has failed.", ex);
            }
        }

        private void InternalWriteCallback(IAsyncResult ar)
        {
            var internalResult = (InternalAsyncResult) ar.AsyncState;

            try
            {
                checkDisposed();
                innerStream.EndWrite(ar);
                internalResult.SetComplete();
            }
            catch (Exception ex)
            {
                internalResult.SetComplete(ex);
            }
        }

        public override IAsyncResult BeginWrite(
            byte[] buffer,
            int offset,
            int count,
            AsyncCallback callback,
            object state)
        {
            checkDisposed();

            if (buffer == null) throw new ArgumentNullException("buffer is a null reference.");
            if (offset < 0) throw new ArgumentOutOfRangeException("offset is less than 0.");
            if (offset > buffer.Length)
                throw new ArgumentOutOfRangeException("offset is greater than the length of buffer.");
            if (count < 0) throw new ArgumentOutOfRangeException("count is less than 0.");
            if (count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(
                    "count is less than the length of buffer minus the value of the offset parameter.");


            var asyncResult = new InternalAsyncResult(callback, state, buffer, offset, count, true, true);

            if (MightNeedHandshake)
            {
                if (!BeginNegotiateHandshake(asyncResult))
                {
                    //we made it down here so the handshake was not started.
                    //another thread must have started it in the mean time.
                    //wait for it to complete and then perform our original operation
                    negotiationComplete.WaitOne();

                    InternalBeginWrite(asyncResult);
                }
            }
            else
            {
                InternalBeginWrite(asyncResult);
            }

            return asyncResult;
        }

        public override int EndRead(IAsyncResult asyncResult)
        {
            checkDisposed();

            var internalResult = asyncResult as InternalAsyncResult;
            if (internalResult == null)
                throw new ArgumentNullException("asyncResult is null or was not obtained by calling BeginRead.");

            // Always wait until the read is complete
            if (!asyncResult.IsCompleted)
                if (!asyncResult.AsyncWaitHandle.WaitOne())
                    throw new TlsException(AlertDescription.InternalError, "Couldn't complete EndRead");

            if (internalResult.CompletedWithError) throw internalResult.AsyncException;

            return internalResult.BytesRead;
        }

        public override void EndWrite(IAsyncResult asyncResult)
        {
            checkDisposed();

            var internalResult = asyncResult as InternalAsyncResult;
            if (internalResult == null)
                throw new ArgumentNullException("asyncResult is null or was not obtained by calling BeginWrite.");


            if (!asyncResult.IsCompleted)
                if (!internalResult.AsyncWaitHandle.WaitOne())
                    throw new TlsException(AlertDescription.InternalError, "Couldn't complete EndWrite");

            if (internalResult.CompletedWithError) throw internalResult.AsyncException;
        }

        public override void Close()
        {
            base.Close();
        }

        public override void Flush()
        {
            checkDisposed();

            innerStream.Flush();
        }

        public int Read(byte[] buffer)
        {
            return Read(buffer, 0, buffer.Length);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            checkDisposed();

            if (buffer == null) throw new ArgumentNullException("buffer");
            if (offset < 0) throw new ArgumentOutOfRangeException("offset is less than 0.");
            if (offset > buffer.Length)
                throw new ArgumentOutOfRangeException("offset is greater than the length of buffer.");
            if (count < 0) throw new ArgumentOutOfRangeException("count is less than 0.");
            if (count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(
                    "count is less than the length of buffer minus the value of the offset parameter.");

            if (context.HandshakeState != HandshakeState.Finished) NegotiateHandshake(); // Handshake negotiation

            lock (read)
            {
                try
                {
                    record_processing.Reset();
                    // do we already have some decrypted data ?
                    if (inputBuffer.Position > 0)
                    {
                        // or maybe we used all the buffer before ?
                        if (inputBuffer.Position == inputBuffer.Length)
                        {
                            inputBuffer.SetLength(0);
                        }
                        else
                        {
                            var n = inputBuffer.Read(buffer, offset, count);
                            if (n > 0)
                            {
                                record_processing.Set();
                                return n;
                            }
                        }
                    }

                    var needMoreData = false;
                    while (true)
                    {
                        // we first try to process the read with the data we already have
                        if (recordStream.Position == 0 || needMoreData)
                        {
                            needMoreData = false;
                            // if we loop, then it either means we need more data
                            var recbuf = new byte[16384];
                            var n = 0;
                            if (count == 1)
                            {
                                var value = innerStream.ReadByte();
                                if (value >= 0)
                                {
                                    recbuf[0] = (byte) value;
                                    n = 1;
                                }
                            }
                            else
                            {
                                n = innerStream.Read(recbuf, 0, recbuf.Length);
                            }

                            if (n > 0)
                            {
                                // Add the new received data to the waiting data
                                if (recordStream.Length > 0 && recordStream.Position != recordStream.Length)
                                    recordStream.Seek(0, SeekOrigin.End);
                                recordStream.Write(recbuf, 0, n);
                            }
                            else
                            {
                                // or that the read operation is done (lost connection in the case of a network stream).
                                record_processing.Set();
                                return 0;
                            }
                        }

                        var dataToReturn = false;

                        recordStream.Position = 0;
                        byte[] record = null;

                        // don't try to decode record unless we have at least 5 bytes
                        // i.e. type (1), protocol (2) and length (2)
                        if (recordStream.Length >= 5)
                        {
                            record = protocol.ReceiveRecord(recordStream);
                            needMoreData = record == null;
                        }

                        // a record of 0 length is valid (and there may be more record after it)
                        while (record != null)
                        {
                            // we probably received more stuff after the record, and we must keep it!
                            var remainder = recordStream.Length - recordStream.Position;
                            byte[] outofrecord = null;
                            if (remainder > 0)
                            {
                                outofrecord = new byte[remainder];
                                recordStream.Read(outofrecord, 0, outofrecord.Length);
                            }

                            var position = inputBuffer.Position;

                            if (record.Length > 0)
                            {
                                // Write new data to the inputBuffer
                                inputBuffer.Seek(0, SeekOrigin.End);
                                inputBuffer.Write(record, 0, record.Length);

                                // Restore buffer position
                                inputBuffer.Seek(position, SeekOrigin.Begin);
                                dataToReturn = true;
                            }

                            recordStream.SetLength(0);
                            record = null;

                            if (remainder > 0)
                            {
                                recordStream.Write(outofrecord, 0, outofrecord.Length);
                                recordStream.Position = 0;
                            }

                            if (dataToReturn)
                            {
                                // we have record(s) to return -or- no more available to read from network
                                // reset position for further reading
                                var i = inputBuffer.Read(buffer, offset, count);
                                record_processing.Set();
                                return i;
                            }
                        }
                    }
                }
                catch (TlsException ex)
                {
                    throw new IOException("The authentication or decryption has failed.", ex);
                }
                catch (Exception ex)
                {
                    throw new IOException("IO exception during read.", ex);
                }
            }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public void Write(byte[] buffer)
        {
            Write(buffer, 0, buffer.Length);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            checkDisposed();

            if (buffer == null) throw new ArgumentNullException("buffer");
            if (offset < 0) throw new ArgumentOutOfRangeException("offset is less than 0.");
            if (offset > buffer.Length)
                throw new ArgumentOutOfRangeException("offset is greater than the length of buffer.");
            if (count < 0) throw new ArgumentOutOfRangeException("count is less than 0.");
            if (count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(
                    "count is less than the length of buffer minus the value of the offset parameter.");

            if (context.HandshakeState != HandshakeState.Finished) NegotiateHandshake();

            lock (write)
            {
                try
                {
                    // Send the buffer as a TLS record
                    var record = protocol.EncodeRecord(ContentType.ApplicationData, buffer, offset, count);
                    innerStream.Write(record, 0, record.Length);
                }
                catch (Exception ex)
                {
                    protocol.SendAlert(ref ex);
                    Close();
                    throw new IOException("The authentication or decryption has failed.", ex);
                }
            }
        }

        public override bool CanRead => innerStream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => innerStream.CanWrite;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        #endregion

        #region IDisposable Members and Finalizer

        ~SslStreamBase()
        {
            Dispose(false);
        }

        public override void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    if (innerStream != null)
                    {
                        if (context.HandshakeState == HandshakeState.Finished &&
                            !context.SentConnectionEnd)
                            // Write close notify
                            try
                            {
                                protocol.SendAlert(AlertDescription.CloseNotify);
                            }
                            catch
                            {
                            }

                        if (ownsStream)
                            // Close inner stream
                            innerStream.Close();
                    }

                    ownsStream = false;
                    innerStream = null;
                }

                disposed = true;
                base.Dispose(disposing);
            }
        }

        #endregion

        #region Misc Methods

        private void resetBuffer()
        {
            inputBuffer.SetLength(0);
            inputBuffer.Position = 0;
        }

        internal void checkDisposed()
        {
            if (disposed) throw new ObjectDisposedException("The Stream is closed.");
        }

        #endregion
    }
}