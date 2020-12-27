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

using System;
using System.Security.Cryptography;

namespace Mono.Security.Protocol.Tls
{
    internal class SslHandshakeHash : HashAlgorithm
    {
        #region Constructors

        public SslHandshakeHash(byte[] secret)
        {
            // Create md5 and sha1 hashes
            md5 = MD5.Create();
            sha = SHA1.Create();

            // Set HashSizeValue
            HashSizeValue = md5.HashSize + sha.HashSize;

            // Update secret
            this.secret = secret;

            Initialize();
        }

        #endregion

        #region Private Methods

        private void initializePad()
        {
            // Fill md5 arrays
            innerPadMD5 = new byte[48];
            outerPadMD5 = new byte[48];

            /* Pad the key for inner and outer digest */
            for (var i = 0; i < 48; ++i)
            {
                innerPadMD5[i] = 0x36;
                outerPadMD5[i] = 0x5C;
            }

            // Fill sha arrays
            innerPadSHA = new byte[40];
            outerPadSHA = new byte[40];

            /* Pad the key for inner and outer digest */
            for (var i = 0; i < 40; ++i)
            {
                innerPadSHA[i] = 0x36;
                outerPadSHA[i] = 0x5C;
            }
        }

        #endregion

        #region Fields

        private readonly HashAlgorithm md5;
        private readonly HashAlgorithm sha;
        private bool hashing;
        private readonly byte[] secret;
        private byte[] innerPadMD5;
        private byte[] outerPadMD5;
        private byte[] innerPadSHA;
        private byte[] outerPadSHA;

        #endregion

        #region Methods

        public override void Initialize()
        {
            md5.Initialize();
            sha.Initialize();
            initializePad();
            hashing = false;
        }

        public override byte[] HashFinal()
        {
            if (!hashing) hashing = true;

            // Finalize the md5 hash
            md5.TransformBlock(secret, 0, secret.Length, secret, 0);
            md5.TransformFinalBlock(innerPadMD5, 0, innerPadMD5.Length);

            var firstResultMD5 = md5.Hash;

            md5.Initialize();
            md5.TransformBlock(secret, 0, secret.Length, secret, 0);
            md5.TransformBlock(outerPadMD5, 0, outerPadMD5.Length, outerPadMD5, 0);
            md5.TransformFinalBlock(firstResultMD5, 0, firstResultMD5.Length);

            // Finalize the sha1 hash
            sha.TransformBlock(secret, 0, secret.Length, secret, 0);
            sha.TransformFinalBlock(innerPadSHA, 0, innerPadSHA.Length);

            var firstResultSHA = sha.Hash;

            sha.Initialize();
            sha.TransformBlock(secret, 0, secret.Length, secret, 0);
            sha.TransformBlock(outerPadSHA, 0, outerPadSHA.Length, outerPadSHA, 0);
            sha.TransformFinalBlock(firstResultSHA, 0, firstResultSHA.Length);

            Initialize();

            var result = new byte[36];

            Buffer.BlockCopy(md5.Hash, 0, result, 0, 16);
            Buffer.BlockCopy(sha.Hash, 0, result, 16, 20);

            return result;
        }

        public override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (!hashing) hashing = true;

            md5.TransformBlock(array, ibStart, cbSize, array, ibStart);
            sha.TransformBlock(array, ibStart, cbSize, array, ibStart);
        }

        public byte[] CreateSignature(RSA rsa)
        {
            if (rsa == null) throw new CryptographicUnexpectedOperationException("missing key");

            var f = new RSASslSignatureFormatter(rsa);
            f.SetHashAlgorithm("MD5SHA1");

            return f.CreateSignature(Hash);
        }

        public bool VerifySignature(RSA rsa, byte[] rgbSignature)
        {
            if (rsa == null) throw new CryptographicUnexpectedOperationException("missing key");
            if (rgbSignature == null) throw new ArgumentNullException("rgbSignature");

            var d = new RSASslSignatureDeformatter(rsa);
            d.SetHashAlgorithm("MD5SHA1");

            return d.VerifySignature(Hash, rgbSignature);
        }

        #endregion
    }
}