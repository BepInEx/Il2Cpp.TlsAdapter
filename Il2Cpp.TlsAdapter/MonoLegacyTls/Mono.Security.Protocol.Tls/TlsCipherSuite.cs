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

using System.Security.Cryptography;

namespace Mono.Security.Protocol.Tls
{
    internal class TlsCipherSuite : CipherSuite
    {
        private const int MacHeaderLength = 13;
        private readonly object headerLock = new object();
        private byte[] header;

        #region Constructors

        public TlsCipherSuite(
            short code, string name, CipherAlgorithmType cipherAlgorithmType,
            HashAlgorithmType hashAlgorithmType, ExchangeAlgorithmType exchangeAlgorithmType,
            bool exportable, bool blockMode, byte keyMaterialSize,
            byte expandedKeyMaterialSize, short effectiveKeyBytes,
            byte ivSize, byte blockSize)
            : base(code, name, cipherAlgorithmType, hashAlgorithmType,
                exchangeAlgorithmType, exportable, blockMode, keyMaterialSize,
                expandedKeyMaterialSize, effectiveKeyBytes, ivSize, blockSize)
        {
        }

        #endregion

        #region MAC Generation Methods

        public override byte[] ComputeServerRecordMAC(ContentType contentType, byte[] fragment)
        {
            lock (headerLock)
            {
                if (header == null)
                    header = new byte [MacHeaderLength];

                var seqnum = Context is ClientContext ? Context.ReadSequenceNumber : Context.WriteSequenceNumber;
                Write(header, 0, seqnum);
                header[8] = (byte) contentType;
                Write(header, 9, Context.Protocol);
                Write(header, 11, (short) fragment.Length);

                HashAlgorithm mac = ServerHMAC;
                mac.TransformBlock(header, 0, header.Length, header, 0);
                mac.TransformBlock(fragment, 0, fragment.Length, fragment, 0);
                // hack, else the method will allocate a new buffer of the same length (negative half the optimization)
                mac.TransformFinalBlock(EmptyArray, 0, 0);
                return mac.Hash;
            }
        }

        public override byte[] ComputeClientRecordMAC(ContentType contentType, byte[] fragment)
        {
            lock (headerLock)
            {
                if (header == null)
                    header = new byte [MacHeaderLength];

                var seqnum = Context is ClientContext ? Context.WriteSequenceNumber : Context.ReadSequenceNumber;
                Write(header, 0, seqnum);
                header[8] = (byte) contentType;
                Write(header, 9, Context.Protocol);
                Write(header, 11, (short) fragment.Length);

                HashAlgorithm mac = ClientHMAC;
                mac.TransformBlock(header, 0, header.Length, header, 0);
                mac.TransformBlock(fragment, 0, fragment.Length, fragment, 0);
                // hack, else the method will allocate a new buffer of the same length (negative half the optimization)
                mac.TransformFinalBlock(EmptyArray, 0, 0);
                return mac.Hash;
            }
        }

        #endregion

        #region Key Generation Methods

        public override void ComputeMasterSecret(byte[] preMasterSecret)
        {
            // Create master secret
            Context.MasterSecret = new byte[preMasterSecret.Length];
            Context.MasterSecret = PRF(
                preMasterSecret, "master secret", Context.RandomCS, 48);

            DebugHelper.WriteLine(">>>> MasterSecret", Context.MasterSecret);
        }

        public override void ComputeKeys()
        {
            // Create keyblock
            var keyBlock = new TlsStream(
                PRF(
                    Context.MasterSecret,
                    "key expansion",
                    Context.RandomSC,
                    KeyBlockSize));

            Context.Negotiating.ClientWriteMAC = keyBlock.ReadBytes(HashSize);
            Context.Negotiating.ServerWriteMAC = keyBlock.ReadBytes(HashSize);
            Context.ClientWriteKey = keyBlock.ReadBytes(KeyMaterialSize);
            Context.ServerWriteKey = keyBlock.ReadBytes(KeyMaterialSize);

            if (IvSize != 0)
            {
                Context.ClientWriteIV = keyBlock.ReadBytes(IvSize);
                Context.ServerWriteIV = keyBlock.ReadBytes(IvSize);
            }
            else
            {
                Context.ClientWriteIV = EmptyArray;
                Context.ServerWriteIV = EmptyArray;
            }

            DebugHelper.WriteLine(">>>> KeyBlock", keyBlock.ToArray());
            DebugHelper.WriteLine(">>>> ClientWriteKey", Context.ClientWriteKey);
            DebugHelper.WriteLine(">>>> ClientWriteIV", Context.ClientWriteIV);
            DebugHelper.WriteLine(">>>> ClientWriteMAC", Context.Negotiating.ClientWriteMAC);
            DebugHelper.WriteLine(">>>> ServerWriteKey", Context.ServerWriteKey);
            DebugHelper.WriteLine(">>>> ServerWriteIV", Context.ServerWriteIV);
            DebugHelper.WriteLine(">>>> ServerWriteMAC", Context.Negotiating.ServerWriteMAC);

            ClientSessionCache.SetContextInCache(Context);
            // Clear no more needed data
            keyBlock.Reset();
        }

        #endregion
    }
}