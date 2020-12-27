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
/* Transport Security Layer (TLS)
 * Copyright (c) 2003-2004 Carlos Guzman Alvarez
 * 
 * Permission is hereby granted, free of charge, to any person 
 * obtaining a copy of this software and associated documentation 
 * files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, 
 * publish, distribute, sublicense, and/or sell copies of the Software, 
 * and to permit persons to whom the Software is furnished to do so, 
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included 
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE.
 */

using System;
using System.Security.Cryptography;

namespace Mono.Security.Protocol.Tls
{
    internal class MD5SHA1 : HashAlgorithm
    {
        #region Constructors

        public MD5SHA1()
        {
            md5 = MD5.Create();
            sha = SHA1.Create();

            // Set HashSizeValue
            HashSizeValue = md5.HashSize + sha.HashSize;
        }

        #endregion

        #region Fields

        private readonly HashAlgorithm md5;
        private readonly HashAlgorithm sha;
        private bool hashing;

        #endregion

        #region Methods

        public override void Initialize()
        {
            md5.Initialize();
            sha.Initialize();
            hashing = false;
        }

        public override byte[] HashFinal()
        {
            if (!hashing) hashing = true;
            // Finalize the original hash
            md5.TransformFinalBlock(new byte[0], 0, 0);
            sha.TransformFinalBlock(new byte[0], 0, 0);

            var hash = new byte[36];

            Buffer.BlockCopy(md5.Hash, 0, hash, 0, 16);
            Buffer.BlockCopy(sha.Hash, 0, hash, 16, 20);

            return hash;
        }

        public override void HashCore(
            byte[] array,
            int ibStart,
            int cbSize)
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