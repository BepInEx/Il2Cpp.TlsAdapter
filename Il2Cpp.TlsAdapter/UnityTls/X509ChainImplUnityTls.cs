// Adapted from https://github.com/Unity-Technologies/mono/tree/24ce88f8a387f93884225c5b31ac42655a9df344/mcs/class/System/Mono.UnityTls

using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using size_t = System.IntPtr;

// ReSharper disable CheckNamespace
namespace Mono.Unity
{
    // Follows mostly X509ChainImplBtls
    internal class X509ChainImplUnityTls : X509ChainImpl
    {
        private List<X509ChainStatus> chainStatusList;
        private X509ChainElementCollection elements;
        private UnityTls.unitytls_x509list_ref nativeCertificateChain;

        internal X509ChainImplUnityTls(UnityTls.unitytls_x509list_ref nativeCertificateChain)
        {
            elements = null;
            this.nativeCertificateChain = nativeCertificateChain;
        }

        public override bool IsValid =>
            nativeCertificateChain.handle != UnityTls.NativeInterface.UNITYTLS_INVALID_HANDLE;

        public override size_t Handle => new size_t((long) nativeCertificateChain.handle);

        internal UnityTls.unitytls_x509list_ref NativeCertificateChain => nativeCertificateChain;

        public override X509ChainElementCollection ChainElements
        {
            get
            {
                ThrowIfContextInvalid();
                if (elements != null)
                    return elements;

                unsafe
                {
                    elements = new X509ChainElementCollection();
                    var errorState = UnityTls.NativeInterface.unitytls_errorstate_create();
                    var cert = UnityTls.NativeInterface.unitytls_x509list_get_x509(nativeCertificateChain, (size_t) 0,
                        &errorState);
                    for (var i = 0; cert.handle != UnityTls.NativeInterface.UNITYTLS_INVALID_HANDLE; ++i)
                    {
                        var certBufferSize =
                            UnityTls.NativeInterface.unitytls_x509_export_der(cert, null, (size_t) 0, &errorState);
                        var certBuffer =
                            new byte[(int) certBufferSize]; // Need to reallocate every time since X509Certificate constructor takes no length but only a byte array.
                        fixed (byte* certBufferPtr = certBuffer)
                        {
                            UnityTls.NativeInterface.unitytls_x509_export_der(cert, certBufferPtr, certBufferSize,
                                &errorState);
                        }

                        elements.Add(new X509Certificate2(certBuffer));

                        cert = UnityTls.NativeInterface.unitytls_x509list_get_x509(nativeCertificateChain, (size_t) i,
                            &errorState);
                    }
                }

                return elements;
            }
        }

        public override X509ChainPolicy ChainPolicy { get; set; } = new X509ChainPolicy();

        public override X509ChainStatus[] ChainStatus => chainStatusList?.ToArray() ?? new X509ChainStatus[0];

        public override void AddStatus(X509ChainStatusFlags errorCode)
        {
            if (chainStatusList == null)
                chainStatusList = new List<X509ChainStatus>();
            chainStatusList.Add(new X509ChainStatus(errorCode));
        }

        public override bool Build(X509Certificate2 certificate)
        {
            return false;
        }

        public override void Reset()
        {
            if (elements != null)
            {
                nativeCertificateChain.handle = UnityTls.NativeInterface.UNITYTLS_INVALID_HANDLE;
                elements.Clear();
                elements = null;
            }
        }

        public override void Dispose(bool disposing)
        {
            Reset();
            base.Dispose(disposing);
        }
    }
}