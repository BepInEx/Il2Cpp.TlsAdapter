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

using System;
using System.IO;

namespace Mono.Security.Protocol.Tls
{
    internal class TlsStream : Stream
    {
        #region Properties

        public bool EOF
        {
            get
            {
                if (Position < Length)
                    return false;
                return true;
            }
        }

        #endregion

        #region Fields

        private readonly bool canRead;
        private readonly bool canWrite;
        private readonly MemoryStream buffer;
        private byte[] temp;
        private const int temp_size = 4;

        #endregion

        #region Stream Properties

        public override bool CanWrite => canWrite;

        public override bool CanRead => canRead;

        public override bool CanSeek => buffer.CanSeek;

        public override long Position
        {
            get => buffer.Position;
            set => buffer.Position = value;
        }

        public override long Length => buffer.Length;

        #endregion

        #region Constructors

        public TlsStream()
        {
            buffer = new MemoryStream(0);
            canRead = false;
            canWrite = true;
        }

        public TlsStream(byte[] data)
        {
            if (data != null)
                buffer = new MemoryStream(data);
            else
                buffer = new MemoryStream();
            canRead = true;
            canWrite = false;
        }

        #endregion

        #region Specific Read Methods

        // hack for reducing memory allocations
        // returned value is valid only for the length asked *and*
        // cannot be directly returned outside the class
        // note: Mono's Stream.ReadByte does a 1 byte array allocation
        private byte[] ReadSmallValue(int length)
        {
            if (length > temp_size)
                throw new ArgumentException("8 bytes maximum");
            if (temp == null)
                temp = new byte[temp_size];

            if (Read(temp, 0, length) != length)
                throw new TlsException("buffer underrun");
            return temp;
        }

        public new byte ReadByte()
        {
            var result = ReadSmallValue(1);
            return result[0];
        }

        public short ReadInt16()
        {
            var result = ReadSmallValue(2);
            return (short) ((result[0] << 8) | result[1]);
        }

        public int ReadInt24()
        {
            var result = ReadSmallValue(3);
            return (result[0] << 16) | (result[1] << 8) | result[2];
        }

        public int ReadInt32()
        {
            var result = ReadSmallValue(4);
            return (result[0] << 24) | (result[1] << 16) | (result[2] << 8) | result[3];
        }

        public byte[] ReadBytes(int count)
        {
            var bytes = new byte[count];
            if (Read(bytes, 0, count) != count)
                throw new TlsException("buffer underrun");

            return bytes;
        }

        #endregion

        #region Specific Write Methods

        // note: Mono's Stream.WriteByte does a 1 byte array allocation
        public void Write(byte value)
        {
            if (temp == null)
                temp = new byte[temp_size];
            temp[0] = value;
            Write(temp, 0, 1);
        }

        public void Write(short value)
        {
            if (temp == null)
                temp = new byte[temp_size];
            temp[0] = (byte) (value >> 8);
            temp[1] = (byte) value;
            Write(temp, 0, 2);
        }

        public void WriteInt24(int value)
        {
            if (temp == null)
                temp = new byte[temp_size];
            temp[0] = (byte) (value >> 16);
            temp[1] = (byte) (value >> 8);
            temp[2] = (byte) value;
            Write(temp, 0, 3);
        }

        public void Write(int value)
        {
            if (temp == null)
                temp = new byte[temp_size];
            temp[0] = (byte) (value >> 24);
            temp[1] = (byte) (value >> 16);
            temp[2] = (byte) (value >> 8);
            temp[3] = (byte) value;
            Write(temp, 0, 4);
        }

        public void Write(ulong value)
        {
            Write((int) (value >> 32));
            Write((int) value);
        }

        public void Write(byte[] buffer)
        {
            Write(buffer, 0, buffer.Length);
        }

        #endregion

        #region Methods

        public void Reset()
        {
            buffer.SetLength(0);
            buffer.Position = 0;
        }

        public byte[] ToArray()
        {
            return buffer.ToArray();
        }

        #endregion

        #region Stream Methods

        public override void Flush()
        {
            buffer.Flush();
        }

        public override void SetLength(long length)
        {
            buffer.SetLength(length);
        }

        public override long Seek(long offset, SeekOrigin loc)
        {
            return buffer.Seek(offset, loc);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (canRead) return this.buffer.Read(buffer, offset, count);
            throw new InvalidOperationException("Read operations are not allowed by this stream");
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (canWrite)
                this.buffer.Write(buffer, offset, count);
            else
                throw new InvalidOperationException("Write operations are not allowed by this stream");
        }

        #endregion
    }
}