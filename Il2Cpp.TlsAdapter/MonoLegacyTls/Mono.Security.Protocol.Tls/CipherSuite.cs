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

extern alias MonoSecurity;
using System;
using System.Security.Cryptography;
using System.Text;
using HMAC = MonoSecurity::Mono.Security.Cryptography.HMAC;
using M = Mono.Security.Cryptography;

namespace Mono.Security.Protocol.Tls
{
    internal abstract class CipherSuite
    {
        #region Static Fields

        public static byte[] EmptyArray = new byte[0];

        #endregion

        #region Constructors

        public CipherSuite(
            short code, string name, CipherAlgorithmType cipherAlgorithmType,
            HashAlgorithmType hashAlgorithmType, ExchangeAlgorithmType exchangeAlgorithmType,
            bool exportable, bool blockMode, byte keyMaterialSize,
            byte expandedKeyMaterialSize, short effectiveKeyBits,
            byte ivSize, byte blockSize)
        {
            Code = code;
            Name = name;
            CipherAlgorithmType = cipherAlgorithmType;
            HashAlgorithmType = hashAlgorithmType;
            ExchangeAlgorithmType = exchangeAlgorithmType;
            IsExportable = exportable;
            if (blockMode) CipherMode = CipherMode.CBC;
            KeyMaterialSize = keyMaterialSize;
            ExpandedKeyMaterialSize = expandedKeyMaterialSize;
            EffectiveKeyBits = effectiveKeyBits;
            IvSize = ivSize;
            this.blockSize = blockSize;
            KeyBlockSize = (KeyMaterialSize + HashSize + IvSize) << 1;
        }

        #endregion

        #region Fields

        private readonly byte blockSize;
        private SymmetricAlgorithm encryptionAlgorithm;
        private SymmetricAlgorithm decryptionAlgorithm;

        #endregion

        #region Protected Properties

        protected ICryptoTransform EncryptionCipher { get; private set; }

        protected ICryptoTransform DecryptionCipher { get; private set; }

        protected KeyedHashAlgorithm ClientHMAC { get; private set; }

        protected KeyedHashAlgorithm ServerHMAC { get; private set; }

        #endregion

        #region Properties

        public CipherAlgorithmType CipherAlgorithmType { get; }

        public string HashAlgorithmName
        {
            get
            {
                switch (HashAlgorithmType)
                {
                    case HashAlgorithmType.Md5:
                        return "MD5";

                    case HashAlgorithmType.Sha1:
                        return "SHA1";

                    default:
                        return "None";
                }
            }
        }

        internal HashAlgorithm CreateHashAlgorithm()
        {
            switch (HashAlgorithmType)
            {
                case HashAlgorithmType.Md5:
                    return MD5.Create();
                case HashAlgorithmType.Sha1:
                    return SHA1.Create();
                default:
                    return null;
            }
        }

        public HashAlgorithmType HashAlgorithmType { get; }

        public int HashSize
        {
            get
            {
                switch (HashAlgorithmType)
                {
                    case HashAlgorithmType.Md5:
                        return 16;

                    case HashAlgorithmType.Sha1:
                        return 20;

                    default:
                        return 0;
                }
            }
        }

        public ExchangeAlgorithmType ExchangeAlgorithmType { get; }

        public CipherMode CipherMode { get; }

        public short Code { get; }

        public string Name { get; }

        public bool IsExportable { get; }

        public byte KeyMaterialSize { get; }

        public int KeyBlockSize { get; }

        public byte ExpandedKeyMaterialSize { get; }

        public short EffectiveKeyBits { get; }

        public byte IvSize { get; }

        /*
        public byte	BlockSize
        {
            get { return this.blockSize; }
        }
        */

        public Context Context { get; set; }

        #endregion

        #region Methods

        internal void Write(byte[] array, int offset, short value)
        {
            if (offset > array.Length - 2)
                throw new ArgumentException("offset");

            array[offset] = (byte) (value >> 8);
            array[offset + 1] = (byte) value;
        }

        internal void Write(byte[] array, int offset, ulong value)
        {
            if (offset > array.Length - 8)
                throw new ArgumentException("offset");

            array[offset] = (byte) (value >> 56);
            array[offset + 1] = (byte) (value >> 48);
            array[offset + 2] = (byte) (value >> 40);
            array[offset + 3] = (byte) (value >> 32);
            array[offset + 4] = (byte) (value >> 24);
            array[offset + 5] = (byte) (value >> 16);
            array[offset + 6] = (byte) (value >> 8);
            array[offset + 7] = (byte) value;
        }

        public void InitializeCipher()
        {
            createEncryptionCipher();
            createDecryptionCipher();
        }

        public byte[] EncryptRecord(byte[] fragment, byte[] mac)
        {
            // Encryption ( fragment + mac [+ padding + padding_length] )
            var length = fragment.Length + mac.Length;
            var padlen = 0;
            if (CipherMode == CipherMode.CBC)
            {
                // Calculate padding_length
                length++; // keep an extra byte
                padlen = blockSize - length % blockSize;
                if (padlen == blockSize) padlen = 0;
                length += padlen;
            }

            var plain = new byte [length];
            Buffer.BlockCopy(fragment, 0, plain, 0, fragment.Length);
            Buffer.BlockCopy(mac, 0, plain, fragment.Length, mac.Length);
            if (padlen > 0)
            {
                var start = fragment.Length + mac.Length;
                for (var i = start; i < start + padlen + 1; i++) plain[i] = (byte) padlen;
            }

            EncryptionCipher.TransformBlock(plain, 0, plain.Length, plain, 0);
            return plain;
        }

        public void DecryptRecord(byte[] fragment, out byte[] dcrFragment, out byte[] dcrMAC)
        {
            var fragmentSize = 0;
            var paddingLength = 0;

            // Decrypt message fragment ( fragment + mac [+ padding + padding_length] )
            DecryptionCipher.TransformBlock(fragment, 0, fragment.Length, fragment, 0);
            // optimization: decrypt "in place", worst case: padding will reduce the size of the data
            // this will cut in half the memory allocations (dcrFragment and dcrMAC remains)

            // Calculate fragment size
            if (CipherMode == CipherMode.CBC)
            {
                // Calculate padding_length
                paddingLength = fragment[fragment.Length - 1];
                fragmentSize = fragment.Length - (paddingLength + 1) - HashSize;
            }
            else
            {
                fragmentSize = fragment.Length - HashSize;
            }

            dcrFragment = new byte[fragmentSize];
            dcrMAC = new byte[HashSize];

            Buffer.BlockCopy(fragment, 0, dcrFragment, 0, dcrFragment.Length);
            Buffer.BlockCopy(fragment, dcrFragment.Length, dcrMAC, 0, dcrMAC.Length);
        }

        #endregion

        #region Abstract Methods

        public abstract byte[] ComputeClientRecordMAC(ContentType contentType, byte[] fragment);

        public abstract byte[] ComputeServerRecordMAC(ContentType contentType, byte[] fragment);

        public abstract void ComputeMasterSecret(byte[] preMasterSecret);

        public abstract void ComputeKeys();

        #endregion

        #region Key Generation Methods

        public byte[] CreatePremasterSecret()
        {
            var context = (ClientContext) Context;

            // Generate random bytes (total size)
            var preMasterSecret = Context.GetSecureRandomBytes(48);
            // and replace the first two bytes with the protocol version
            // (maximum support version not actual)
            preMasterSecret[0] = (byte) (context.ClientHelloProtocol >> 8);
            preMasterSecret[1] = (byte) context.ClientHelloProtocol;

            return preMasterSecret;
        }

        public byte[] PRF(byte[] secret, string label, byte[] data, int length)
        {
            /* Secret Length calc exmplain from the RFC2246. Section 5
             * 
             * S1 and S2 are the two halves of the secret and each is the same
             * length. S1 is taken from the first half of the secret, S2 from the
             * second half. Their length is created by rounding up the length of the
             * overall secret divided by two; thus, if the original secret is an odd
             * number of bytes long, the last byte of S1 will be the same as the
             * first byte of S2.
             */

            // split secret in 2
            var secretLen = secret.Length >> 1;
            // rounding up
            if ((secret.Length & 0x1) == 0x1)
                secretLen++;

            // Seed
            var seedStream = new TlsStream();
            seedStream.Write(Encoding.ASCII.GetBytes(label));
            seedStream.Write(data);
            var seed = seedStream.ToArray();
            seedStream.Reset();

            // Secret 1
            var secret1 = new byte[secretLen];
            Buffer.BlockCopy(secret, 0, secret1, 0, secretLen);

            // Secret2
            var secret2 = new byte[secretLen];
            Buffer.BlockCopy(secret, secret.Length - secretLen, secret2, 0, secretLen);

            // Secret 1 processing
            var p_md5 = Expand(MD5.Create(), secret1, seed, length);

            // Secret 2 processing
            var p_sha = Expand(SHA1.Create(), secret2, seed, length);

            // Perfor XOR of both results
            var masterSecret = new byte[length];
            for (var i = 0; i < masterSecret.Length; i++) masterSecret[i] = (byte) (p_md5[i] ^ p_sha[i]);

            return masterSecret;
        }

        public byte[] Expand(HashAlgorithm hash, byte[] secret, byte[] seed, int length)
        {
            var hashLength = hash.HashSize / 8;
            var iterations = length / hashLength;
            if (length % hashLength > 0) iterations++;

            var hmac = new HMAC(hash, secret);
            var resMacs = new TlsStream();

            var hmacs = new byte[iterations + 1][];
            hmacs[0] = seed;
            for (var i = 1; i <= iterations; i++)
            {
                var hcseed = new TlsStream();
                hmac.TransformFinalBlock(hmacs[i - 1], 0, hmacs[i - 1].Length);
                hmacs[i] = hmac.Hash;
                hcseed.Write(hmacs[i]);
                hcseed.Write(seed);
                hmac.TransformFinalBlock(hcseed.ToArray(), 0, (int) hcseed.Length);
                resMacs.Write(hmac.Hash);
                hcseed.Reset();
            }

            var res = new byte[length];

            Buffer.BlockCopy(resMacs.ToArray(), 0, res, 0, res.Length);

            resMacs.Reset();

            return res;
        }

        #endregion

        #region Private Methods

        private void createEncryptionCipher()
        {
            // Create and configure the symmetric algorithm
            switch (CipherAlgorithmType)
            {
                case CipherAlgorithmType.Des:
                    encryptionAlgorithm = DES.Create();
                    break;

                case CipherAlgorithmType.Rc2:
                    encryptionAlgorithm = RC2.Create();
                    break;

                case CipherAlgorithmType.Rc4:
                    encryptionAlgorithm = new M.ARC4Managed();
                    break;

                case CipherAlgorithmType.TripleDes:
                    encryptionAlgorithm = TripleDES.Create();
                    break;

                case CipherAlgorithmType.Rijndael:
                    // only AES is really used - and we can use CommonCrypto for iOS and OSX this way
                    encryptionAlgorithm = Aes.Create();
                    break;
            }

            // If it's a block cipher
            if (CipherMode == CipherMode.CBC)
            {
                // Configure encrypt algorithm
                encryptionAlgorithm.Mode = CipherMode;
                encryptionAlgorithm.Padding = PaddingMode.None;
                encryptionAlgorithm.KeySize = ExpandedKeyMaterialSize * 8;
                encryptionAlgorithm.BlockSize = blockSize * 8;
            }

            // Set the key and IV for the algorithm
            if (Context is ClientContext)
            {
                encryptionAlgorithm.Key = Context.ClientWriteKey;
                encryptionAlgorithm.IV = Context.ClientWriteIV;
            }
            else
            {
                encryptionAlgorithm.Key = Context.ServerWriteKey;
                encryptionAlgorithm.IV = Context.ServerWriteIV;
            }

            // Create encryption cipher
            EncryptionCipher = encryptionAlgorithm.CreateEncryptor();

            // Create the HMAC algorithm
            if (Context is ClientContext)
                ClientHMAC = new HMAC(
                    CreateHashAlgorithm(),
                    Context.Negotiating.ClientWriteMAC);
            else
                ServerHMAC = new HMAC(
                    CreateHashAlgorithm(),
                    Context.Negotiating.ServerWriteMAC);
        }

        private void createDecryptionCipher()
        {
            // Create and configure the symmetric algorithm
            switch (CipherAlgorithmType)
            {
                case CipherAlgorithmType.Des:
                    decryptionAlgorithm = DES.Create();
                    break;

                case CipherAlgorithmType.Rc2:
                    decryptionAlgorithm = RC2.Create();
                    break;

                case CipherAlgorithmType.Rc4:
                    decryptionAlgorithm = new M.ARC4Managed();
                    break;

                case CipherAlgorithmType.TripleDes:
                    decryptionAlgorithm = TripleDES.Create();
                    break;

                case CipherAlgorithmType.Rijndael:
                    // only AES is really used - and we can use CommonCrypto for iOS and OSX this way
                    decryptionAlgorithm = Aes.Create();
                    break;
            }

            // If it's a block cipher
            if (CipherMode == CipherMode.CBC)
            {
                // Configure encrypt algorithm
                decryptionAlgorithm.Mode = CipherMode;
                decryptionAlgorithm.Padding = PaddingMode.None;
                decryptionAlgorithm.KeySize = ExpandedKeyMaterialSize * 8;
                decryptionAlgorithm.BlockSize = blockSize * 8;
            }

            // Set the key and IV for the algorithm
            if (Context is ClientContext)
            {
                decryptionAlgorithm.Key = Context.ServerWriteKey;
                decryptionAlgorithm.IV = Context.ServerWriteIV;
            }
            else
            {
                decryptionAlgorithm.Key = Context.ClientWriteKey;
                decryptionAlgorithm.IV = Context.ClientWriteIV;
            }

            // Create decryption cipher			
            DecryptionCipher = decryptionAlgorithm.CreateDecryptor();

            // Create the HMAC
            if (Context is ClientContext)
                ServerHMAC = new HMAC(
                    CreateHashAlgorithm(),
                    Context.Negotiating.ServerWriteMAC);
            else
                ClientHMAC = new HMAC(
                    CreateHashAlgorithm(),
                    Context.Negotiating.ClientWriteMAC);
        }

        #endregion
    }
}