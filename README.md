# SSLUnpinner

A LSPosed module to disable SSL Pinning on Android, featuring support for standard Java/Android SSL APIs and Flutter applications.

## Support Status
Verified working on:
- **Device**: Pixel 8
- **OS**: Android 16
- **Root**: KernelSU Next
- **Xposed Framework**: [JingMatrix/LSPosed v1.11.0](https://github.com/JingMatrix/LSPosed)

## Usage
1. Install the SSLUnpinner APK.
2. Open **LSPosed Manager**.
3. Enable the **SSLUnpinner** module.
4. Select the target applications you wish to apply the bypass to in the module scope.
5. Restart the target application.

## Features
- **Standard SSL Bypass**: Hooks common Java/Android SSL verification methods (TrustManager, HostnameVerifier, etc.) to accept all certificates.
- **Flutter Patching**: Supports runtime patching of `libflutter.so` to disable mandatory TLS verification.
  - Automatically intercepts Flutter library loading.
  - Scans for `ssl_verify_peer_cert` byte patterns across multiple architectures (ARM64, ARM32, x86, x64).
  - Creates a patched copy in the app's cache and loads it dynamically.

## Credits & Acknowledgments
- **Flutter Patching**: Byte patterns and logic adapted from [NVISOsecurity/disable-flutter-tls-verification](https://github.com/NVISOsecurity/disable-flutter-tls-verification).
- **Android Hooks**: Implementation inspired by popular Frida scripts:
  - [frida-multiple-unpinning (@akabe1)](https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/)
  - [frida-multiple-bypass (@fdciabdul)](https://codeshare.frida.re/@fdciabdul/frida-multiple-bypass/)
