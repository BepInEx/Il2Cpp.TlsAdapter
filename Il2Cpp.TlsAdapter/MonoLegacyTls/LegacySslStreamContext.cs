extern alias MonoSecurity;
using System;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Mono.Net.Security;
using Mono.Security.Protocol.Tls;
using MonoSecurity::Mono.Security.Interface;
using CipherAlgorithmType = MonoSecurity::Mono.Security.Interface.CipherAlgorithmType;
using ExchangeAlgorithmType = MonoSecurity::Mono.Security.Interface.ExchangeAlgorithmType;
using HashAlgorithmType = MonoSecurity::Mono.Security.Interface.HashAlgorithmType;
using TlsCipherAlgorithmType = Mono.Security.Protocol.Tls.CipherAlgorithmType;
using TlsHashAlgorithmType = Mono.Security.Protocol.Tls.HashAlgorithmType;
using TlsExchangeAlgorithmType = Mono.Security.Protocol.Tls.ExchangeAlgorithmType;
using TlsSecurityProtocolType = Mono.Security.Protocol.Tls.SecurityProtocolType;

namespace Il2Cpp.TlsAdapter.MonoLegacyTls
{
    public class LegacySslStreamContext : MobileTlsContext
    {
        SslStreamBase sslStream;
        
        public LegacySslStreamContext(MobileAuthenticatedStream parent, MonoSslAuthenticationOptions options) : base(parent, options)
        {
        }

        public override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing)
            {
                sslStream?.Dispose();
                sslStream = null;
                connectionInfo = null;
            }
        }

        public override void StartHandshake()
        {
            if (IsAuthenticated)
                return;

            if (Options.ServerMode)
                AuthAsServer();
            else
                AuthAsClient();
            
            // Do some very dummy approach where we use old BeginAsync API but wrap it around
            // the Task async loop of MobileAuthenticatedStream which saves us the job of rewriting
            // all the old API at the cost of extra threading
            handshakeResult = sslStream.BeginHandshake();
        }

        private IAsyncResult handshakeResult;
        
        private void AuthAsServer()
        {
            var s = new SslServerStream(Parent.InnerStream, Options.ServerCertificate, false,
                Options.ClientCertificateRequired, !Parent.LeaveInnerStreamOpen,
                GetMonoSslProtocol(EnabledProtocols))
            {
                CheckCertRevocationStatus = Options.CertificateRevocationCheckMode != X509RevocationMode.NoCheck
            };
            
            // Due to the Mono.Security internal, it cannot reuse
            // the delegated argument, as Mono.Security creates 
            // another instance of X509Certificate which lacks 
            // private key but is filled the private key via this
            // delegate.
            s.PrivateKeyCertSelectionDelegate = delegate
            {
                // ... so, we cannot use the delegate argument.
                var cert2 = Options.ServerCertificate as X509Certificate2 ?? new X509Certificate2 (Options.ServerCertificate);
                return cert2.PrivateKey;
            };

            s.ClientCertValidationDelegate = delegate (X509Certificate cert, int[] certErrors) {
                var errors = certErrors.Length > 0 ? MonoSslPolicyErrors.RemoteCertificateChainErrors : MonoSslPolicyErrors.None;
                return certificateValidator.ValidateClientCertificate (cert, errors);
            };

            sslStream = s;
        }
        
        private void AuthAsClient()
        {
            var s = new SslClientStream(Parent.InnerStream, TargetHost, !Parent.LeaveInnerStreamOpen,
                GetMonoSslProtocol(EnabledProtocols), ClientCertificates)
            {
                CheckCertRevocationStatus = Options.CertificateRevocationCheckMode != X509RevocationMode.NoCheck
            };

            // Due to the Mono.Security internal, it cannot reuse
            // the delegated argument, as Mono.Security creates 
            // another instance of X509Certificate which lacks 
            // private key but is filled the private key via this
            // delegate.
            s.PrivateKeyCertSelectionDelegate = delegate (X509Certificate cert, string host) {
                string hash = cert.GetCertHashString ();
                // ... so, we cannot use the delegate argument.
                foreach (X509Certificate cc in ClientCertificates) {
                    if (cc.GetCertHashString () != hash)
                        continue;
                    X509Certificate2 cert2 = cc as X509Certificate2;
                    cert2 ??= new X509Certificate2 (cc);
                    return cert2.PrivateKey;
                }
                return null;
            };

            // Even if validation_callback is null this allows us to verify requests where the user
            // does not provide a verification callback but attempts to authenticate with the website
            // as a client (see https://bugzilla.xamarin.com/show_bug.cgi?id=18962 for an example)
            s.ServerCertValidation2 += (mcerts) => {
                X509CertificateCollection certs = null;
                if (mcerts != null)
                {
                    certs = new X509CertificateCollection ();
                    foreach (var t in mcerts)
                        certs.Add (new X509Certificate2 (t.RawData));
                }
                return certificateValidator.ValidateCertificate (TargetHost, false, certs);
            };
            s.ClientCertSelectionDelegate = OnCertificateSelection;

            sslStream = s;
        }
        
        X509Certificate OnCertificateSelection (X509CertificateCollection clientCerts, X509Certificate serverCert, string targetHost, X509CertificateCollection serverRequestedCerts)
        {
#pragma warning disable 618
            string [] acceptableIssuers = new string [serverRequestedCerts?.Count ?? 0];
            for (int i = 0; i < acceptableIssuers.Length; i++)
                if (serverRequestedCerts != null)
                    acceptableIssuers[i] = serverRequestedCerts[i].GetIssuerName();
            certificateValidator.SelectClientCertificate (targetHost, clientCerts, serverCert, acceptableIssuers, out var clientCertificate);
            return clientCertificate;
#pragma warning restore 618
        }
        
        TlsSecurityProtocolType GetMonoSslProtocol (SslProtocols ms)
        {
            switch (ms) {
                case SslProtocols.Ssl2:
                    return TlsSecurityProtocolType.Ssl2;
                case SslProtocols.Ssl3:
                    return TlsSecurityProtocolType.Ssl3;
                case SslProtocols.Tls:
                    return TlsSecurityProtocolType.Tls;
                default:
                    return TlsSecurityProtocolType.Default;
            }
        }

        public override bool ProcessHandshake()
        {
            if (!HasContext)
                return false;
            // Simply poll the context for when handshaking is done
            // TODO: Check if this could cause deadlocks
            return handshakeResult == null || handshakeResult.IsCompleted || sslStream.context.HandshakeState == HandshakeState.Finished;
        }

        public override void FinishHandshake()
        {
            sslStream.EndHandshake(handshakeResult);
            handshakeResult = null;
            
            // Once done, we can set up info values
            connectionInfo = new MonoTlsConnectionInfo();
            
            connectionInfo.HashAlgorithmType = sslStream.HashAlgorithm switch
            {
                TlsHashAlgorithmType.Md5 => HashAlgorithmType.Md5,
                TlsHashAlgorithmType.None => HashAlgorithmType.None,
                TlsHashAlgorithmType.Sha1 => HashAlgorithmType.Sha1,
                _ => throw new InvalidOperationException ("Not supported hash algorithm is in use. It is likely a bug in SslStream.")
            };
            
            connectionInfo.CipherSuiteCode = (CipherSuiteCode) sslStream.protocol.Context.Current.Cipher.Code;

            // Apparently it's possible to figure out the rest values from cipher suite code, but mono has no logic for that yet
            // On the other hand it seems like those values are not assigned either way (look at btls impl)
            // TODO: See if these values actually work and are valid
            
            connectionInfo.ExchangeAlgorithmType = sslStream.KeyExchangeAlgorithm switch
            {
                TlsExchangeAlgorithmType.DiffieHellman => ExchangeAlgorithmType.Dhe,
                TlsExchangeAlgorithmType.None => ExchangeAlgorithmType.None,
                TlsExchangeAlgorithmType.RsaSign => ExchangeAlgorithmType.Rsa,
                TlsExchangeAlgorithmType.RsaKeyX => ExchangeAlgorithmType.EcDhe,
                _ => throw new InvalidOperationException ("Not supported exchange algorithm is in use. It is likely a bug in SslStream.")
            };

            var protocols = sslStream.SecurityProtocol switch
            {
                TlsSecurityProtocolType.Default => SslProtocols.Default,
                TlsSecurityProtocolType.Ssl2 => SslProtocols.Ssl2,
                TlsSecurityProtocolType.Ssl3 => SslProtocols.Ssl3,
                TlsSecurityProtocolType.Tls => SslProtocols.Tls
            };
            connectionInfo.ProtocolVersion = (TlsProtocols) protocols;

            connectionInfo.CipherAlgorithmType = sslStream.CipherAlgorithm switch
            {
                TlsCipherAlgorithmType.None => CipherAlgorithmType.None,
                TlsCipherAlgorithmType.Rijndael => sslStream.CipherStrength switch
                {
                    128 => CipherAlgorithmType.Aes128,
                    256 => CipherAlgorithmType.Aes256,
                    _ => throw new InvalidOperationException(
                        $"Not supported cipher algorithm is in use ({sslStream.CipherAlgorithm}). It is likely a bug in SslStream."),
                },
                _ => throw new InvalidOperationException(
                    $"Not supported cipher algorithm is in use ({sslStream.CipherAlgorithm}). It is likely a bug in SslStream.")
            };
            
            connectionInfo.PeerDomainName = ServerName;
        }

        public override void Flush()
        {
            sslStream.Flush();
        }

        public override (int ret, bool wantMore) Read(byte[] buffer, int offset, int count)
        {
            // Ghetto trick: simply read all the data and block as needed.
            // TODO: Check if this causes extremely long blocking
            return (sslStream.Read(buffer, offset, count), false);
        }

        public override (int ret, bool wantMore) Write(byte[] buffer, int offset, int count)
        {
            // Ghetto trick: simply write all the data and block as needed.
            // TODO: Check if this causes extremely long blocking
            sslStream.Write(buffer, offset, count);
            return (count, false);
        }

        public override void Shutdown()
        {
            connectionInfo = null;
            sslStream.Dispose();
            sslStream = null;
        }

        public override bool PendingRenegotiation()
        {
            // NO-OP
            return false;
        }

        public override void Renegotiate()
        {
            // NO-OP
        }
        
        void CheckConnectionAuthenticated ()
        {
            if (!IsAuthenticated)
                throw new InvalidOperationException ("This operation is invalid until it is successfully authenticated");
        }
        
        public override bool HasContext => sslStream != null;
        public override bool IsAuthenticated => sslStream != null && connectionInfo != null;
        public override MonoTlsConnectionInfo ConnectionInfo => connectionInfo;
        public override bool IsRemoteCertificateAvailable { get; }

        public bool IsServer { 
            get { return sslStream is SslServerStream; }
        }
        
        private MonoTlsConnectionInfo connectionInfo;
        
        public override X509Certificate LocalClientCertificate
        {
            get
            {
                CheckConnectionAuthenticated();
                return IsServer ? sslStream.ServerCertificate : ((SslClientStream) sslStream).SelectedClientCertificate;
            }
        }

        public override X509Certificate2 RemoteCertificate
        {
            get {
                CheckConnectionAuthenticated ();
                var cert = !IsServer ? sslStream.ServerCertificate : ((SslServerStream) sslStream).ClientCertificate;
                if (cert is X509Certificate2 cert2)
                    return cert2;
                throw new NotSupportedException("Non-X509Certificate2 certificates are not supported!");
            }
        }

        public override TlsProtocols NegotiatedProtocol => ConnectionInfo.ProtocolVersion;
        public override bool CanRenegotiate => false;
    }
}