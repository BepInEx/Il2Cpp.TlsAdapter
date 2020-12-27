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
using System.Text;

namespace Mono.Security.Protocol.Tls
{
    internal class SslCipherSuite : CipherSuite
    {
        #region Constructors

        public SslCipherSuite(
            short code, string name, CipherAlgorithmType cipherAlgorithmType,
            HashAlgorithmType hashAlgorithmType, ExchangeAlgorithmType exchangeAlgorithmType,
            bool exportable, bool blockMode, byte keyMaterialSize,
            byte expandedKeyMaterialSize, short effectiveKeyBytes,
            byte ivSize, byte blockSize) :
            base(code, name, cipherAlgorithmType, hashAlgorithmType,
                exchangeAlgorithmType, exportable, blockMode, keyMaterialSize,
                expandedKeyMaterialSize, effectiveKeyBytes, ivSize, blockSize)

        {
            var padLength = hashAlgorithmType == HashAlgorithmType.Md5 ? 48 : 40;

            // Fill pad arrays
            pad1 = new byte[padLength];
            pad2 = new byte[padLength];

            /* Pad the key for inner and outer digest */
            for (var i = 0; i < padLength; ++i)
            {
                pad1[i] = 0x36;
                pad2[i] = 0x5C;
            }
        }

        #endregion

        #region Private Methods

        private byte[] prf(byte[] secret, string label, byte[] random)
        {
            HashAlgorithm md5 = MD5.Create();
            HashAlgorithm sha = SHA1.Create();

            // Compute SHA hash
            var block = new TlsStream();
            block.Write(Encoding.ASCII.GetBytes(label));
            block.Write(secret);
            block.Write(random);

            var shaHash = sha.ComputeHash(block.ToArray(), 0, (int) block.Length);

            block.Reset();

            // Compute MD5 hash
            block.Write(secret);
            block.Write(shaHash);

            var result = md5.ComputeHash(block.ToArray(), 0, (int) block.Length);

            // Free resources
            block.Reset();

            return result;
        }

        #endregion

        #region Fields

        private readonly byte[] pad1;
        private readonly byte[] pad2;

        private const int MacHeaderLength = 11;
        private byte[] header;

        #endregion

        #region MAC Generation Methods

        public override byte[] ComputeServerRecordMAC(ContentType contentType, byte[] fragment)
        {
            var hash = CreateHashAlgorithm();

            var smac = Context.Read.ServerWriteMAC;
            hash.TransformBlock(smac, 0, smac.Length, smac, 0);
            hash.TransformBlock(pad1, 0, pad1.Length, pad1, 0);

            if (header == null)
                header = new byte [MacHeaderLength];

            var seqnum = Context is ClientContext ? Context.ReadSequenceNumber : Context.WriteSequenceNumber;
            Write(header, 0, seqnum);
            header[8] = (byte) contentType;
            Write(header, 9, (short) fragment.Length);
            hash.TransformBlock(header, 0, header.Length, header, 0);
            hash.TransformBlock(fragment, 0, fragment.Length, fragment, 0);
            // hack, else the method will allocate a new buffer of the same length (negative half the optimization)
            hash.TransformFinalBlock(EmptyArray, 0, 0);

            var blockHash = hash.Hash;

            hash.Initialize();

            hash.TransformBlock(smac, 0, smac.Length, smac, 0);
            hash.TransformBlock(pad2, 0, pad2.Length, pad2, 0);
            hash.TransformBlock(blockHash, 0, blockHash.Length, blockHash, 0);
            // hack again
            hash.TransformFinalBlock(EmptyArray, 0, 0);

            return hash.Hash;
        }

        public override byte[] ComputeClientRecordMAC(ContentType contentType, byte[] fragment)
        {
            var hash = CreateHashAlgorithm();

            var cmac = Context.Current.ClientWriteMAC;
            hash.TransformBlock(cmac, 0, cmac.Length, cmac, 0);
            hash.TransformBlock(pad1, 0, pad1.Length, pad1, 0);

            if (header == null)
                header = new byte [MacHeaderLength];

            var seqnum = Context is ClientContext ? Context.WriteSequenceNumber : Context.ReadSequenceNumber;
            Write(header, 0, seqnum);
            header[8] = (byte) contentType;
            Write(header, 9, (short) fragment.Length);
            hash.TransformBlock(header, 0, header.Length, header, 0);
            hash.TransformBlock(fragment, 0, fragment.Length, fragment, 0);
            // hack, else the method will allocate a new buffer of the same length (negative half the optimization)
            hash.TransformFinalBlock(EmptyArray, 0, 0);

            var blockHash = hash.Hash;

            hash.Initialize();

            hash.TransformBlock(cmac, 0, cmac.Length, cmac, 0);
            hash.TransformBlock(pad2, 0, pad2.Length, pad2, 0);
            hash.TransformBlock(blockHash, 0, blockHash.Length, blockHash, 0);
            // hack again
            hash.TransformFinalBlock(EmptyArray, 0, 0);

            return hash.Hash;
        }

        #endregion

        #region Key Generation Methods

        public override void ComputeMasterSecret(byte[] preMasterSecret)
        {
            var masterSecret = new TlsStream();

            masterSecret.Write(prf(preMasterSecret, "A", Context.RandomCS));
            masterSecret.Write(prf(preMasterSecret, "BB", Context.RandomCS));
            masterSecret.Write(prf(preMasterSecret, "CCC", Context.RandomCS));

            Context.MasterSecret = masterSecret.ToArray();

            DebugHelper.WriteLine(">>>> MasterSecret", Context.MasterSecret);
        }

        public override void ComputeKeys()
        {
            // Compute KeyBlock
            var tmp = new TlsStream();

            var labelChar = 'A';
            var count = 1;

            while (tmp.Length < KeyBlockSize)
            {
                var label = string.Empty;

                for (var i = 0; i < count; i++) label += labelChar.ToString();

                var block = prf(Context.MasterSecret, label, Context.RandomSC);

                var size = tmp.Length + block.Length > KeyBlockSize ? KeyBlockSize - (int) tmp.Length : block.Length;

                tmp.Write(block, 0, size);

                labelChar++;
                count++;
            }

            // Create keyblock
            var keyBlock = new TlsStream(tmp.ToArray());

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
            tmp.Reset();
        }

        #endregion
    }
}