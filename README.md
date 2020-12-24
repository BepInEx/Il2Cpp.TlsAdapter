# Il2Cpp TLS Providers for Mono 6.12

Implements common Mono TLS providers for modding Unity games which use Il2Cpp runtime.  
This allows to use HTTPS the same way you'd do it in a normal Unity game using Mono runtime.

Currently, this repo implements the following TLS providers:

* UnityTls -- official Unity TLS provider adapted from [unity-mono repository](https://github.com/Unity-Technologies/mono/tree/24ce88f8a387f93884225c5b31ac42655a9df344/mcs/class/System/Mono.UnityTls)

All TLS providers were updated for use with Mono 6.12.