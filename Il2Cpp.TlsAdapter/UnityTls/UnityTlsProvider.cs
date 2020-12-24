// Taken from https://github.com/Unity-Technologies/mono/tree/24ce88f8a387f93884225c5b31ac42655a9df344/mcs/class/System/Mono.UnityTls

using System;
using System.Text;
using System.IO;

using Mono.Security.Interface;
using Mono.Net.Security;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using size_t = System.IntPtr;

namespace Mono.Unity
{
	unsafe internal class UnityTlsProvider : MobileTlsProvider
	{
		public override string Name {
			get { return "unitytls"; }
		}

		public override Guid ID => Guid.Empty; // TODO: Change to unique ID
		public override bool SupportsSslStream => true;
		public override bool SupportsMonoExtensions => true;
		public override bool SupportsConnectionInfo => true;
		public override SslProtocols SupportedProtocols => SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls;
		public override bool SupportsCleanShutdown => true;

		public override MobileAuthenticatedStream CreateSslStream(SslStream sslStream, Stream innerStream, bool leaveInnerStreamOpen,
			MonoTlsSettings settings)
		{
			return new UnityTlsStream(innerStream, leaveInnerStreamOpen, sslStream, settings, this);
		}

		public override bool ValidateCertificate(ChainValidationHelper validator, string targetHost, bool serverMode,
			X509CertificateCollection certificates, bool wantsChain, ref X509Chain chain, ref SslPolicyErrors errors,
			ref int status11)
		{
			var errorState = UnityTls.NativeInterface.unitytls_errorstate_create ();
		
			var unityTlsChainImpl = chain.Impl as X509ChainImplUnityTls;
			if (unityTlsChainImpl == null)
			{
				if (certificates == null || certificates.Count == 0) {
					errors |= SslPolicyErrors.RemoteCertificateNotAvailable;
					return false;
				}
		
				if (wantsChain)
					chain = SystemCertificateValidator.CreateX509Chain (certificates);
			}
			else
			{
				var cert = UnityTls.NativeInterface.unitytls_x509list_get_x509 (unityTlsChainImpl.NativeCertificateChain, (size_t)0, &errorState);
				if (cert.handle == UnityTls.NativeInterface.UNITYTLS_INVALID_HANDLE) {
					errors |= SslPolicyErrors.RemoteCertificateNotAvailable;
					return false;
				}
			}
		
			// fixup targetHost name by removing port
			if (!string.IsNullOrEmpty (targetHost)) {
				var pos = targetHost.IndexOf (':');
				if (pos > 0)
					targetHost = targetHost.Substring (0, pos);
			}
		
			// convert cert to native or extract from unityTlsChainImpl.
			var result = UnityTls.unitytls_x509verify_result.UNITYTLS_X509VERIFY_NOT_DONE;
			UnityTls.unitytls_x509list* certificatesNative = null;
			try
			{
				// Things the validator provides that we might want to make use of here:
				//validator.Settings.CheckCertificateName				// not used by mono?
				//validator.Settings.CheckCertificateRevocationStatus	// not used by mono?
				//validator.Settings.CertificateValidationTime
				//validator.Settings.CertificateSearchPaths				// currently only used by MonoBtlsProvider
		
				UnityTls.unitytls_x509list_ref certificatesNativeRef;
				if (unityTlsChainImpl == null)
				{
					certificatesNative = UnityTls.NativeInterface.unitytls_x509list_create (&errorState);
					CertHelper.AddCertificatesToNativeChain (certificatesNative, certificates, &errorState);
					certificatesNativeRef = UnityTls.NativeInterface.unitytls_x509list_get_ref (certificatesNative, &errorState);
				}
				else
					certificatesNativeRef = unityTlsChainImpl.NativeCertificateChain;
				
				var targetHostUtf8 = Encoding.UTF8.GetBytes (targetHost);
		
				if (validator.Settings.TrustAnchors != null) {
					UnityTls.unitytls_x509list* trustCAnative = null;
					try
					{
						trustCAnative = UnityTls.NativeInterface.unitytls_x509list_create (&errorState);
						CertHelper.AddCertificatesToNativeChain (trustCAnative, validator.Settings.TrustAnchors, &errorState);
						var trustCAnativeRef = UnityTls.NativeInterface.unitytls_x509list_get_ref (trustCAnative, &errorState);
		
						fixed (byte* targetHostUtf8Ptr = targetHostUtf8) {
							result = UnityTls.NativeInterface.unitytls_x509verify_explicit_ca (certificatesNativeRef, trustCAnativeRef, targetHostUtf8Ptr, (size_t)targetHostUtf8.Length, null, null, &errorState);
						}
					}
					finally {
						UnityTls.NativeInterface.unitytls_x509list_free (trustCAnative);
					}
				} else {
					fixed (byte* targetHostUtf8Ptr = targetHostUtf8) {
						result = UnityTls.NativeInterface.unitytls_x509verify_default_ca (certificatesNativeRef, targetHostUtf8Ptr, (size_t)targetHostUtf8.Length, null, null, &errorState);
					}
				}
			}
			finally	{
				UnityTls.NativeInterface.unitytls_x509list_free (certificatesNative);
			}
		
			errors = UnityTlsConversions.VerifyResultToPolicyErrror(result);
			// There should be a status per certificate, but once again we're following closely the BTLS implementation
			// https://github.com/mono/mono/blob/1553889bc54f87060158febca7e6b8b9910975f8/mcs/class/System/Mono.Btls/MonoBtlsProvider.cs#L180
			// which also provides only a single status for the entire chain.
			// It is notoriously tricky to implement in OpenSSL to get a status for all invididual certificates without finishing the handshake in the process.
			// This is partially the reason why unitytls_x509verify_X doesn't expose it (TODO!) and likely the reason Mono's BTLS impl ignores this.
			unityTlsChainImpl?.AddStatus(UnityTlsConversions.VerifyResultToChainStatus(result));
			return result == UnityTls.unitytls_x509verify_result.UNITYTLS_X509VERIFY_SUCCESS && 
					errorState.code == UnityTls.unitytls_error_code.UNITYTLS_SUCCESS;
		}
	}
}
