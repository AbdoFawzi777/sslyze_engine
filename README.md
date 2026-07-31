# SSLyze Engine (`sslyze_engine`)

> SSL/TLS Certificate & Cipher Suite Auditor  
> **Author & Original Architect:** [Abdallah Fawzi Ali Mahmoud](https://github.com/AbdoFawzi777)  
> **Part of the RedOps Hub Monorepo Suite**

---

## 📌 Overview
`sslyze_engine` is a production-grade, standalone Flutter package engineered for high-performance mobile security auditing. Built with pure Dart and native Flutter MethodChannels/Isolates, it delivers enterprise-level capability directly on Android & iOS devices without relying on external Linux command-line dependencies.

---

## 🚀 New Capabilities & Features (v2.0)
- **Cipher Suite Inspection:** Analyzes TLS 1.0, 1.1, 1.2, and 1.3 supported cipher suites and encryption strength.
- **Vulnerability Checks:** Identifies critical SSL vulnerabilities including Heartbleed, POODLE, FREAK, LOGJAM, and ROBOT.
- **Certificate Chain Validation:** Checks expiration dates, SANs, trust store validation, and self-signed status.
- **SNI & Multi-Domain Support:** Full support for Server Name Indication (SNI) and custom TLS ports.

---

## 🛠 Usage & Integration

Add `sslyze_engine` to your Flutter `pubspec.yaml`:

```yaml
dependencies:
  sslyze_engine:
    path: ../packages/sslyze_engine
```

### Basic Example

```dart
import 'package:sslyze_engine/sslyze_engine.dart';

void main() async {
  final engine = SSLyzeEngine();
  
  print('Starting SSLyze Engine audit...');
  final results = await engine.execute(
    target: '192.168.1.1',
  );
  
  print('Audit Complete!');
}
```

---

## 🔒 Security & Privacy
- **Zero Telemetry:** No analytics, tracking, or network calls home.
- **Encrypted Local Storage:** Integrates seamlessly with RedOps Hub AES-256 local database.
- **Thread Safety:** All heavy operations execute inside Dart Isolates to maintain 60fps UI rendering.

---

## 👤 Author & Copyright

**Abdallah Fawzi Ali Mahmoud**  
Lead Developer & Security Architect of RedOps Hub  
- **GitHub:** [@AbdoFawzi777](https://github.com/AbdoFawzi777)  
- **Telegram:** [@ABdo_FawZi1](https://telegram.me/ABdo_FawZi1)  
- **Website:** [RedOps Hub Platform](https://redops-hub.web.app)

*Copyright (c) 2026 Abdallah Fawzi Ali Mahmoud. All rights reserved.*
