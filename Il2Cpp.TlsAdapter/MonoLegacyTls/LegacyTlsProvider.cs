//
// LegacyTlsProvider.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2015 Xamarin, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

extern alias MonoSecurity;

using System;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using Il2Cpp.TlsAdapter.MonoLegacyTls;
using MonoSecurity::Mono.Security.Interface;

namespace Mono.Net.Security
{
	/*
	 * Strictly private - do not use outside the Mono.Net.Security directory.
	 */
	class LegacyTlsProvider : MobileTlsProvider
	{
		public override Guid ID {
			get { return Guid.Empty; } // TODO: Fix
		}

		public override string Name {
			get { return "legacy"; }
		}

		public override bool SupportsSslStream {
			get { return true; }
		}

		public override bool SupportsConnectionInfo {
			get { return false; }
		}

		public override bool SupportsMonoExtensions {
			get { return false; }
		}

		public override bool SupportsCleanShutdown {
			get { return false; }
		}

		public override SslProtocols SupportedProtocols {
			get { return SslProtocols.Tls; }
		}

		public override MobileAuthenticatedStream CreateSslStream(SslStream sslStream, Stream innerStream, bool leaveInnerStreamOpen,
			MonoTlsSettings settings)
		{
			return new LegacySslStream(innerStream, leaveInnerStreamOpen, sslStream, settings, this);
		}

		public override bool ValidateCertificate(ChainValidationHelper validator, string targetHost, bool serverMode,
			X509CertificateCollection certificates, bool wantsChain, ref X509Chain chain, ref SslPolicyErrors errors,
			ref int status11)
		{
			if (wantsChain)
				chain = SystemCertificateValidator.CreateX509Chain (certificates);
			var result = SystemCertificateValidator.Evaluate (validator.Settings, targetHost, certificates, chain, ref errors, ref status11);
			return result;
		}
	}
}
