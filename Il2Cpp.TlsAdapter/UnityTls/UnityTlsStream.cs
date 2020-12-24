// Adapted from https://github.com/Unity-Technologies/mono/tree/24ce88f8a387f93884225c5b31ac42655a9df344/mcs/class/System/Mono.UnityTls

using System.IO;
using System.Net.Security;
using Mono.Net.Security;
using Mono.Security.Interface;

// ReSharper disable CheckNamespace
namespace Mono.Unity
{
    internal class UnityTlsStream : MobileAuthenticatedStream
    {
        public UnityTlsStream(Stream innerStream, bool leaveInnerStreamOpen, SslStream owner,
            MonoTlsSettings settings, MobileTlsProvider provider)
            : base(innerStream, leaveInnerStreamOpen, owner, settings, provider)
        {
        }

        public override MobileTlsContext CreateContext(MonoSslAuthenticationOptions options)
        {
            return new UnityTlsContext(
                this, options);
        }
    }
}