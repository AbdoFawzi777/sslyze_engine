<div align="center">

# 🔒 SSLyze Engine for Dart & Flutter

**v2.0.0 — Sovereign On-Device Security Engine for Dart & Flutter**

[![Dart](https://img.shields.io/badge/Dart-3.x-0175C2?logo=dart)](https://dart.dev)
[![Flutter](https://img.shields.io/badge/Flutter-3.x-02569B?logo=flutter)](https://flutter.dev)
[![License](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.0.0-E05555)](https://github.com/AbdoFawzi777/sslyze_engine/releases)
[![RedOps Hub](https://img.shields.io/badge/Integrated_in-RedOps_Hub_v2.0-6C3AED)](https://github.com/AbdoFawzi777/redops-hub)

*Part of the RedOps Hub Sovereign Mobile Security Suite.*

</div>

---

## 📖 Overview

`sslyze_engine` is a production-grade, 100% on-device Dart/Flutter package designed for mobile security auditing, defensive telemetry extraction, and penetration testing automation.

> **🔒 Sovereignty Mandate:** All operations execute locally in memory and over direct socket/HTTP requests. Zero third-party telemetry, tracking, or cloud dependencies.

---

## ✨ Key Capabilities

- 📜 **Certificate Validation**: Extracts Subject, Issuer CA, Expiry Dates, Subject Alternative Names (SAN), and key algorithms.
- 🔐 **Protocol Version Verification**: Tests SSL 2.0/3.0, TLS 1.0, 1.1, 1.2, and modern TLS 1.3 handshakes.
- ⚠️ **Weak Cipher Suite Detection**: Flags obsolete RC4, DES, 3DES, EXPORT, and NULL cipher suites.

---

## 📦 Installation

Add `sslyze_engine` to your `pubspec.yaml`:

```yaml
dependencies:
  sslyze_engine:
    git:
      url: https://github.com/AbdoFawzi777/sslyze_engine.git
      ref: main
```

Or for local monorepo development:

```yaml
dependencies:
  sslyze_engine:
    path: packages/sslyze_engine
```

---

## 🚀 Quick Start & Usage

```dart
import 'package:sslyze_engine/sslyze_engine.dart';

void main() async {
  final engine = SslyzeEngine();
  await engine.initialize();

  final result = await engine.analyze('example.com', port: 443);
  print('TLS 1.3 Supported: ${result.supportsTls13}');
  print('Cert Expires: ${result.certExpiry}');
}
```

---

## 🛡️ Anti-Fake Telemetry Integration

`sslyze_engine` is built to interface directly with the **RedOps Hub Anti-Fake Verification Pipeline**. All returned data structures contain genuine socket/HTTP evidence objects, raw status headers, and timestamps, preventing synthetic or hallucinated results in downstream AI aggregators.

---

## 📄 License & Legal Notice

> **⚠️ Legal Notice:** This tool is designed exclusively for authorized penetration testing, security auditing, and educational research. Always obtain explicit written authorization before scanning target infrastructure.

Distributed under the **MIT License**. Copyright (c) 2026 **Eng. Abdallah Fawzi Ali Mahmoud**.

---

<div align="center">

Maintained by **[Abdallah Fawzi Ali Mahmoud](https://github.com/AbdoFawzi777)**  
[Official Platform](https://redops-hub.web.app/) · [RedOps Hub Monorepo](https://github.com/AbdoFawzi777/redops-hub)

</div>
