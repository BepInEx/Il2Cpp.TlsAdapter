// Taken from https://github.com/Unity-Technologies/mono/tree/24ce88f8a387f93884225c5b31ac42655a9df344/mcs/class/System/Mono.UnityTls

using System.Security.Cryptography.X509Certificates;

using size_t = System.IntPtr;

namespace Mono.Unity
{
	internal unsafe static class CertHelper
	{
		public static void AddCertificatesToNativeChain (UnityTls.unitytls_x509list* nativeCertificateChain, X509CertificateCollection certificates, UnityTls.unitytls_errorstate* errorState)
		{
			foreach (var certificate in certificates) {
				AddCertificateToNativeChain (nativeCertificateChain, certificate, errorState);
			}
		}

		public static void AddCertificateToNativeChain (UnityTls.unitytls_x509list* nativeCertificateChain, X509Certificate certificate, UnityTls.unitytls_errorstate* errorState)
		{
			byte[] certDer = certificate.GetRawCertData ();
			fixed(byte* certDerPtr = certDer) {
				UnityTls.NativeInterface.unitytls_x509list_append_der (nativeCertificateChain, certDerPtr, (size_t)certDer.Length, errorState);
			}

			var certificateImpl2 = certificate.Impl as X509Certificate2Impl;
			if (certificate is X509Certificate2 cert2 && cert2.Impl != null) {
				var intermediates = certificateImpl2.IntermediateCertificates;
				if (intermediates != null && intermediates.Count > 0) {
					for (int i=0; i<intermediates.Count; ++i) {
						AddCertificateToNativeChain (nativeCertificateChain, new X509Certificate (intermediates[i]), errorState);
					}
				}
			}
		}
	}
}
