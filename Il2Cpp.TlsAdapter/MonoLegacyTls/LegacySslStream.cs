extern alias MonoSecurity;
using System.IO;
using System.Net.Security;
using Mono.Net.Security;
using MonoSecurity::Mono.Security.Interface;

namespace Il2Cpp.TlsAdapter.MonoLegacyTls
{
    public class LegacySslStream : MobileAuthenticatedStream
    {
        public LegacySslStream(Stream innerStream, bool leaveInnerStreamOpen, SslStream owner, MonoTlsSettings settings, MobileTlsProvider provider) : base(innerStream, leaveInnerStreamOpen, owner, settings, provider)
        {
        }

        public override MobileTlsContext CreateContext(MonoSslAuthenticationOptions options)
        {
            return new LegacySslStreamContext(this, options);
        }
    }
}