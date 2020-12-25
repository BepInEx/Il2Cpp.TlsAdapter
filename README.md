# Il2Cpp TLS Providers for Mono 6.12

Implements common Mono TLS providers for modding Unity games which use Il2Cpp runtime.  
This allows to use HTTPS the same way you'd do it in a normal Unity game using Mono runtime.

Currently, this repo implements the following TLS providers:

* UnityTls -- official Unity TLS provider adapted from [unity-mono repository](https://github.com/Unity-Technologies/mono/tree/24ce88f8a387f93884225c5b31ac42655a9df344/mcs/class/System/Mono.UnityTls)
* LegacyTls -- port of old mono SSL 1.0-3.0 and TLS 1.0 providers to new Mobile TLS API

All TLS providers were updated for use with Mono 6.12.

## How to use

### If you use BepInEx
You don't have to do anything: this adapter is automatically included and initialized by BepInEx core.  
You can use normal HTTP/HTTPS API like you are used to.

### If you don't use BepInEx
If you don't write BepInEx plugins, you have to bootstrap this adapter yourself.  
To do this:

1. Download latest version of the bootstrapper from releases.
2. Download latest version of [HarmonyX](https://github.com/BepInEx/HarmonyX) from releases.
3. In your main code, reference `Il2Cpp.TlsAdapter.dll` and include the following line **before using any HTTP/HTTPS requests**:
    ```csharp
    using Il2Cpp.TlsAdapter;
    Il2CppTlsAdapter.Initialize();
    ```
   This will initialize the adapter and automatically pick the best available TLS provider.

**WIP** The tool is not ready yet: for example UnityTls is not configurable and `Initialze` doesn't do much interesting at the moment.