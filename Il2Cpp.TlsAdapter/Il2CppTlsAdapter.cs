using System;
using System.Collections.Generic;
using System.IO;
using HarmonyLib;
using Mono.Net.Security;
using Mono.Unity;

namespace Il2Cpp.TlsAdapter
{
    public class AdapterOptions
    {
        public IntPtr UnityTlsInterface { get; set; }
    }
    
    public static class Il2CppTlsAdapter
    {
        private static bool initialized;

        public static AdapterOptions Options { get; } = new AdapterOptions();

        public static void Initialize()
        {
            if (initialized)
                return;
            Harmony.CreateAndPatchAll(typeof(Il2CppTlsAdapter));
            initialized = true;
        }

        [HarmonyPatch(typeof(MonoTlsProviderFactory), "PopulateProviders")]
        [HarmonyPostfix]
        private static void PopulateProviders(
            ref Dictionary<string, Tuple<Guid, string>> ___providerRegistration)
        {
            ___providerRegistration[LegacyTlsProvider.ProviderName] = new Tuple<Guid, string>(LegacyTlsProvider.Guid,
                typeof(LegacyTlsProvider).AssemblyQualifiedName);
            ___providerRegistration[UnityTlsProvider.ProviderName] = new Tuple<Guid, string>(UnityTlsProvider.Guid,
                typeof(UnityTlsProvider).AssemblyQualifiedName);
        }

        [HarmonyPatch(typeof(MonoTlsProviderFactory), "CreateDefaultProviderImpl")]
        [HarmonyPrefix]
        private static bool CreateDefaultProviderImpl(ref MobileTlsProvider __result)
        {
            if (UnityTls.IsSupported)
                __result = new UnityTlsProvider();
            else if (MonoTlsProviderFactory.IsProviderSupported("btls") || MonoTlsProviderFactory.IsProviderSupported("apple"))
                return true;
            else
                __result = new LegacyTlsProvider();
            return false;
        }
    }
}