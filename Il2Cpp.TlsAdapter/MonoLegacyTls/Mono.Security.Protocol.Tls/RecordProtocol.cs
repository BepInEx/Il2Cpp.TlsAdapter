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

using System;
using System.IO;
using System.Threading;
using Mono.Security.Protocol.Tls.Handshake;

namespace Mono.Security.Protocol.Tls
{
    internal abstract class RecordProtocol
    {
        #region Constructors

        public RecordProtocol(Stream innerStream, Context context)
        {
            this.innerStream = innerStream;
            this.context = context;
            this.context.RecordProtocol = this;
        }

        #endregion

        #region Properties

        public Context Context
        {
            get => context;
            set => context = value;
        }

        #endregion

        #region Receive Record Async Result

        private class ReceiveRecordAsyncResult : IAsyncResult
        {
            private readonly AsyncCallback _userCallback;
            private readonly object locker = new object();
            private bool completed;
            private ManualResetEvent handle;

            public ReceiveRecordAsyncResult(AsyncCallback userCallback, object userState, byte[] initialBuffer,
                Stream record)
            {
                _userCallback = userCallback;
                AsyncState = userState;
                InitialBuffer = initialBuffer;
                Record = record;
            }

            public Stream Record { get; }

            public byte[] ResultingBuffer { get; private set; }

            public byte[] InitialBuffer { get; }

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

            private void SetComplete(Exception ex, byte[] resultingBuffer)
            {
                lock (locker)
                {
                    if (completed)
                        return;

                    completed = true;
                    AsyncException = ex;
                    ResultingBuffer = resultingBuffer;
                    if (handle != null)
                        handle.Set();

                    if (_userCallback != null)
                        _userCallback.BeginInvoke(this, null, null);
                }
            }

            public void SetComplete(Exception ex)
            {
                SetComplete(ex, null);
            }

            public void SetComplete(byte[] resultingBuffer)
            {
                SetComplete(null, resultingBuffer);
            }

            public void SetComplete()
            {
                SetComplete(null, null);
            }
        }

        #endregion

        #region Receive Record Async Result

        private class SendRecordAsyncResult : IAsyncResult
        {
            private readonly AsyncCallback _userCallback;
            private readonly object locker = new object();
            private bool completed;
            private ManualResetEvent handle;

            public SendRecordAsyncResult(AsyncCallback userCallback, object userState, HandshakeMessage message)
            {
                _userCallback = userCallback;
                AsyncState = userState;
                Message = message;
            }

            public HandshakeMessage Message { get; }

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

        #endregion

        #region Fields

        private static readonly ManualResetEvent record_processing = new ManualResetEvent(true);

        protected Stream innerStream;
        protected Context context;

        #endregion

        #region Abstract Methods

        public virtual void SendRecord(HandshakeType type)
        {
            var ar = BeginSendRecord(type, null, null);

            EndSendRecord(ar);
        }

        protected abstract void ProcessHandshakeMessage(TlsStream handMsg);

        protected virtual void ProcessChangeCipherSpec()
        {
            var ctx = Context;

            // Reset sequence numbers
            ctx.ReadSequenceNumber = 0;

            if (ctx is ClientContext)
                ctx.EndSwitchingSecurityParameters(true);
            else
                ctx.StartSwitchingSecurityParameters(false);

            ctx.ChangeCipherSpecDone = true;
        }

        public virtual HandshakeMessage GetMessage(HandshakeType type)
        {
            throw new NotSupportedException();
        }

        #endregion

        #region Reveive Record Methods

        public IAsyncResult BeginReceiveRecord(Stream record, AsyncCallback callback, object state)
        {
            if (context.ReceivedConnectionEnd)
                throw new TlsException(
                    AlertDescription.InternalError,
                    "The session is finished and it's no longer valid.");

            record_processing.Reset();
            var recordTypeBuffer = new byte[1];

            var internalResult = new ReceiveRecordAsyncResult(callback, state, recordTypeBuffer, record);

            record.BeginRead(internalResult.InitialBuffer, 0, internalResult.InitialBuffer.Length,
                InternalReceiveRecordCallback, internalResult);

            return internalResult;
        }

        private void InternalReceiveRecordCallback(IAsyncResult asyncResult)
        {
            var internalResult = asyncResult.AsyncState as ReceiveRecordAsyncResult;
            var record = internalResult.Record;

            try
            {
                var bytesRead = internalResult.Record.EndRead(asyncResult);

                //We're at the end of the stream. Time to bail.
                if (bytesRead == 0)
                {
                    internalResult.SetComplete((byte[]) null);
                    return;
                }

                // Try to read the Record Content Type
                int type = internalResult.InitialBuffer[0];

                var contentType = (ContentType) type;
                var buffer = ReadRecordBuffer(type, record);
                if (buffer == null)
                {
                    // record incomplete (at the moment)
                    internalResult.SetComplete((byte[]) null);
                    return;
                }

                // Decrypt message contents if needed
                if (contentType == ContentType.Alert && buffer.Length == 2)
                {
                }
                else if (Context.Read != null && Context.Read.Cipher != null)
                {
                    buffer = decryptRecordFragment(contentType, buffer);
                    DebugHelper.WriteLine("Decrypted record data", buffer);
                }

                // Process record
                switch (contentType)
                {
                    case ContentType.Alert:
                        ProcessAlert((AlertLevel) buffer[0], (AlertDescription) buffer[1]);
                        if (record.CanSeek)
                            // don't reprocess that memory block
                            record.SetLength(0);
                        buffer = null;
                        break;

                    case ContentType.ChangeCipherSpec:
                        ProcessChangeCipherSpec();
                        break;

                    case ContentType.ApplicationData:
                        break;

                    case ContentType.Handshake:
                        var message = new TlsStream(buffer);
                        while (!message.EOF) ProcessHandshakeMessage(message);
                        break;

                    case (ContentType) 0x80:
                        context.HandshakeMessages.Write(buffer);
                        break;

                    default:
                        throw new TlsException(
                            AlertDescription.UnexpectedMessage,
                            "Unknown record received from server.");
                }

                internalResult.SetComplete(buffer);
            }
            catch (Exception ex)
            {
                internalResult.SetComplete(ex);
            }
        }

        public byte[] EndReceiveRecord(IAsyncResult asyncResult)
        {
            var internalResult = asyncResult as ReceiveRecordAsyncResult;

            if (null == internalResult)
                throw new ArgumentException(
                    "Either the provided async result is null or was not created by this RecordProtocol.");

            if (!internalResult.IsCompleted)
                internalResult.AsyncWaitHandle.WaitOne();

            if (internalResult.CompletedWithError)
                throw internalResult.AsyncException;

            var result = internalResult.ResultingBuffer;
            record_processing.Set();
            return result;
        }

        public byte[] ReceiveRecord(Stream record)
        {
            if (context.ReceivedConnectionEnd)
                throw new TlsException(
                    AlertDescription.InternalError,
                    "The session is finished and it's no longer valid.");

            record_processing.Reset();
            var recordTypeBuffer = new byte[1];

            var bytesRead = record.Read(recordTypeBuffer, 0, recordTypeBuffer.Length);

            //We're at the end of the stream. Time to bail.
            if (bytesRead == 0) return null;

            // Try to read the Record Content Type
            int type = recordTypeBuffer[0];

            var contentType = (ContentType) type;
            var buffer = ReadRecordBuffer(type, record);
            if (buffer == null)
                // record incomplete (at the moment)
                return null;

            // Decrypt message contents if needed
            if (contentType == ContentType.Alert && buffer.Length == 2)
            {
            }
            else if (Context.Read != null && Context.Read.Cipher != null)
            {
                buffer = decryptRecordFragment(contentType, buffer);
                DebugHelper.WriteLine("Decrypted record data", buffer);
            }

            // Process record
            switch (contentType)
            {
                case ContentType.Alert:
                    ProcessAlert((AlertLevel) buffer[0], (AlertDescription) buffer[1]);
                    if (record.CanSeek)
                        // don't reprocess that memory block
                        record.SetLength(0);
                    buffer = null;
                    break;

                case ContentType.ChangeCipherSpec:
                    ProcessChangeCipherSpec();
                    break;

                case ContentType.ApplicationData:
                    break;

                case ContentType.Handshake:
                    var message = new TlsStream(buffer);
                    while (!message.EOF) ProcessHandshakeMessage(message);
                    break;

                case (ContentType) 0x80:
                    context.HandshakeMessages.Write(buffer);
                    break;

                default:
                    throw new TlsException(
                        AlertDescription.UnexpectedMessage,
                        "Unknown record received from server.");
            }

            record_processing.Set();
            return buffer;
        }

        private byte[] ReadRecordBuffer(int contentType, Stream record)
        {
            if (!Enum.IsDefined(typeof(ContentType), (ContentType) contentType))
                throw new TlsException(AlertDescription.DecodeError);

            var header = new byte[4];
            if (record.Read(header, 0, 4) != 4)
                throw new TlsException("buffer underrun");

            var protocol = (short) ((header[0] << 8) | header[1]);
            var length = (short) ((header[2] << 8) | header[3]);

            // process further only if the whole record is available
            // note: the first 5 bytes aren't part of the length
            if (record.CanSeek && length + 5 > record.Length) return null;

            // Read Record data
            var totalReceived = 0;
            var buffer = new byte[length];
            while (totalReceived != length)
            {
                var justReceived = record.Read(buffer, totalReceived, buffer.Length - totalReceived);

                //Make sure we get some data so we don't end up in an infinite loop here before shutdown.
                if (0 == justReceived)
                    throw new TlsException(AlertDescription.CloseNotify,
                        "Received 0 bytes from stream. It must be closed.");

                totalReceived += justReceived;
            }

            // Check that the message has a valid protocol version
            if (protocol != context.Protocol && context.ProtocolNegotiated)
                throw new TlsException(
                    AlertDescription.ProtocolVersion, "Invalid protocol version on message received");

            DebugHelper.WriteLine("Record data", buffer);

            return buffer;
        }

        private void ProcessAlert(AlertLevel alertLevel, AlertDescription alertDesc)
        {
            switch (alertLevel)
            {
                case AlertLevel.Fatal:
                    throw new TlsException(alertLevel, alertDesc);

                case AlertLevel.Warning:
                default:
                    switch (alertDesc)
                    {
                        case AlertDescription.CloseNotify:
                            context.ReceivedConnectionEnd = true;
                            break;
                    }

                    break;
            }
        }

        #endregion

        #region Send Alert Methods

        internal void SendAlert(ref Exception ex)
        {
            var tlsEx = ex as TlsException;
            var alert = tlsEx != null ? tlsEx.Alert : new Alert(AlertDescription.InternalError);

            try
            {
                SendAlert(alert);
            }
            catch (Exception alertEx)
            {
                ex = new IOException(
                    string.Format("Error while sending TLS Alert ({0}:{1}): {2}", alert.Level, alert.Description, ex),
                    alertEx);
            }
        }

        public void SendAlert(AlertDescription description)
        {
            SendAlert(new Alert(description));
        }

        public void SendAlert(AlertLevel level, AlertDescription description)
        {
            SendAlert(new Alert(level, description));
        }

        public void SendAlert(Alert alert)
        {
            AlertLevel level;
            AlertDescription description;
            bool close;

            if (alert == null)
            {
                DebugHelper.WriteLine(">>>> Write Alert NULL");
                level = AlertLevel.Fatal;
                description = AlertDescription.InternalError;
                close = true;
            }
            else
            {
                DebugHelper.WriteLine(">>>> Write Alert ({0}|{1})", alert.Description, alert.Message);
                level = alert.Level;
                description = alert.Description;
                close = alert.IsCloseNotify;
            }

            // Write record
            SendRecord(ContentType.Alert, new byte[2] {(byte) level, (byte) description});

            if (close) context.SentConnectionEnd = true;
        }

        #endregion

        #region Send Record Methods

        public void SendChangeCipherSpec()
        {
            DebugHelper.WriteLine(">>>> Write Change Cipher Spec");

            // Send Change Cipher Spec message with the current cipher
            // or as plain text if this is the initial negotiation
            SendRecord(ContentType.ChangeCipherSpec, new byte[] {1});

            var ctx = context;

            // Reset sequence numbers
            ctx.WriteSequenceNumber = 0;

            // all further data sent will be encrypted with the negotiated
            // security parameters (now the current parameters)
            if (ctx is ClientContext)
                ctx.StartSwitchingSecurityParameters(true);
            else
                ctx.EndSwitchingSecurityParameters(false);
        }

        public void SendChangeCipherSpec(Stream recordStream)
        {
            DebugHelper.WriteLine(">>>> Write Change Cipher Spec");

            var record = EncodeRecord(ContentType.ChangeCipherSpec, new byte[] {1});

            // Send Change Cipher Spec message with the current cipher
            // or as plain text if this is the initial negotiation
            recordStream.Write(record, 0, record.Length);

            var ctx = context;

            // Reset sequence numbers
            ctx.WriteSequenceNumber = 0;

            // all further data sent will be encrypted with the negotiated
            // security parameters (now the current parameters)
            if (ctx is ClientContext)
                ctx.StartSwitchingSecurityParameters(true);
            else
                ctx.EndSwitchingSecurityParameters(false);
        }

        public IAsyncResult BeginSendChangeCipherSpec(AsyncCallback callback, object state)
        {
            DebugHelper.WriteLine(">>>> Write Change Cipher Spec");

            // Send Change Cipher Spec message with the current cipher
            // or as plain text if this is the initial negotiation
            return BeginSendRecord(ContentType.ChangeCipherSpec, new byte[] {1}, callback, state);
        }

        public void EndSendChangeCipherSpec(IAsyncResult asyncResult)
        {
            EndSendRecord(asyncResult);

            var ctx = context;

            // Reset sequence numbers
            ctx.WriteSequenceNumber = 0;

            // all further data sent will be encrypted with the negotiated
            // security parameters (now the current parameters)
            if (ctx is ClientContext)
                ctx.StartSwitchingSecurityParameters(true);
            else
                ctx.EndSwitchingSecurityParameters(false);
        }

        public IAsyncResult BeginSendRecord(HandshakeType handshakeType, AsyncCallback callback, object state)
        {
            var msg = GetMessage(handshakeType);

            msg.Process();

            DebugHelper.WriteLine(">>>> Write handshake record ({0}|{1})", context.Protocol, msg.ContentType);

            var internalResult = new SendRecordAsyncResult(callback, state, msg);

            BeginSendRecord(msg.ContentType, msg.EncodeMessage(), InternalSendRecordCallback, internalResult);

            return internalResult;
        }

        private void InternalSendRecordCallback(IAsyncResult ar)
        {
            var internalResult = ar.AsyncState as SendRecordAsyncResult;

            try
            {
                EndSendRecord(ar);

                // Update session
                internalResult.Message.Update();

                // Reset message contents
                internalResult.Message.Reset();

                internalResult.SetComplete();
            }
            catch (Exception ex)
            {
                internalResult.SetComplete(ex);
            }
        }

        public IAsyncResult BeginSendRecord(ContentType contentType, byte[] recordData, AsyncCallback callback,
            object state)
        {
            if (context.SentConnectionEnd)
                throw new TlsException(
                    AlertDescription.InternalError,
                    "The session is finished and it's no longer valid.");

            var record = EncodeRecord(contentType, recordData);

            return innerStream.BeginWrite(record, 0, record.Length, callback, state);
        }

        public void EndSendRecord(IAsyncResult asyncResult)
        {
            if (asyncResult is SendRecordAsyncResult)
            {
                var internalResult = asyncResult as SendRecordAsyncResult;
                if (!internalResult.IsCompleted)
                    internalResult.AsyncWaitHandle.WaitOne();
                if (internalResult.CompletedWithError)
                    throw internalResult.AsyncException;
            }
            else
            {
                innerStream.EndWrite(asyncResult);
            }
        }

        public void SendRecord(ContentType contentType, byte[] recordData)
        {
            var ar = BeginSendRecord(contentType, recordData, null, null);

            EndSendRecord(ar);
        }

        public byte[] EncodeRecord(ContentType contentType, byte[] recordData)
        {
            return EncodeRecord(
                contentType,
                recordData,
                0,
                recordData.Length);
        }

        public byte[] EncodeRecord(
            ContentType contentType,
            byte[] recordData,
            int offset,
            int count)
        {
            if (context.SentConnectionEnd)
                throw new TlsException(
                    AlertDescription.InternalError,
                    "The session is finished and it's no longer valid.");

            var record = new TlsStream();

            var position = offset;

            while (position < offset + count)
            {
                short fragmentLength = 0;
                byte[] fragment;

                if (count + offset - position > Context.MAX_FRAGMENT_SIZE)
                    fragmentLength = Context.MAX_FRAGMENT_SIZE;
                else
                    fragmentLength = (short) (count + offset - position);

                // Fill the fragment data
                fragment = new byte[fragmentLength];
                Buffer.BlockCopy(recordData, position, fragment, 0, fragmentLength);

                if (Context.Write != null && Context.Write.Cipher != null)
                    // Encrypt fragment
                    fragment = encryptRecordFragment(contentType, fragment);

                // Write tls message
                record.Write((byte) contentType);
                record.Write(context.Protocol);
                record.Write((short) fragment.Length);
                record.Write(fragment);

                DebugHelper.WriteLine("Record data", fragment);

                // Update buffer position
                position += fragmentLength;
            }

            return record.ToArray();
        }

        public byte[] EncodeHandshakeRecord(HandshakeType handshakeType)
        {
            var msg = GetMessage(handshakeType);

            msg.Process();

            var bytes = EncodeRecord(msg.ContentType, msg.EncodeMessage());

            msg.Update();

            msg.Reset();

            return bytes;
        }

        #endregion

        #region Cryptography Methods

        private byte[] encryptRecordFragment(
            ContentType contentType,
            byte[] fragment)
        {
            byte[] mac = null;

            // Calculate message MAC
            if (Context is ClientContext)
                mac = context.Write.Cipher.ComputeClientRecordMAC(contentType, fragment);
            else
                mac = context.Write.Cipher.ComputeServerRecordMAC(contentType, fragment);

            DebugHelper.WriteLine(">>>> Record MAC", mac);

            // Encrypt the message
            var ecr = context.Write.Cipher.EncryptRecord(fragment, mac);

            // Update sequence number
            context.WriteSequenceNumber++;

            return ecr;
        }

        private byte[] decryptRecordFragment(
            ContentType contentType,
            byte[] fragment)
        {
            byte[] dcrFragment = null;
            byte[] dcrMAC = null;

            try
            {
                context.Read.Cipher.DecryptRecord(fragment, out dcrFragment, out dcrMAC);
            }
            catch
            {
                if (context is ServerContext) Context.RecordProtocol.SendAlert(AlertDescription.DecryptionFailed);
                throw;
            }

            // Generate record MAC
            byte[] mac = null;

            if (Context is ClientContext)
                mac = context.Read.Cipher.ComputeServerRecordMAC(contentType, dcrFragment);
            else
                mac = context.Read.Cipher.ComputeClientRecordMAC(contentType, dcrFragment);

            DebugHelper.WriteLine(">>>> Record MAC", mac);

            // Check record MAC
            if (!Compare(mac, dcrMAC)) throw new TlsException(AlertDescription.BadRecordMAC, "Bad record MAC");

            // Update sequence number
            context.ReadSequenceNumber++;

            return dcrFragment;
        }

        private bool Compare(byte[] array1, byte[] array2)
        {
            if (array1 == null)
                return array2 == null;
            if (array2 == null)
                return false;
            if (array1.Length != array2.Length)
                return false;
            for (var i = 0; i < array1.Length; i++)
                if (array1[i] != array2[i])
                    return false;
            return true;
        }

        #endregion
    }
}