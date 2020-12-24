using System;
using System.Collections.Generic;
using System.IO;
using HarmonyLib;
using Mono.Net.Security;

namespace Il2Cpp.TlsAdapter
{
    public static class Il2CppTlsAdapter
    {
        private static bool initialized;

        public static void Initialize()
        {
            if (initialized)
                return;
            Harmony.CreateAndPatchAll(typeof(Il2CppTlsAdapter));
            initialized = true;
        }

        [HarmonyPatch(typeof(MonoTlsProviderFactory), "InitializeProviderRegistration")]
        [HarmonyPostfix]
        public static void InitializeProviderRegistration(
            ref Dictionary<string, Tuple<Guid, string>> ___providerRegistration, ref object ___locker)
        {
            lock (___locker)
            {
                foreach (var kv in ___providerRegistration)
                    File.AppendAllText("providers.log", $"Provider {kv.Key} => {kv.Value.Item2}\n");
            }
        }
    }
}