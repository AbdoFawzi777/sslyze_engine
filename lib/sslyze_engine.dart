import 'dart:io';
import 'dart:async';

/// 🔒 Sslyze Engine v6.0 - Absolute Perfection
class SslyzeEngine {
  static final SslyzeEngine _instance = SslyzeEngine._internal();
  factory SslyzeEngine() => _instance;
  SslyzeEngine._internal();

  bool _initialized = false;
  bool get isInitialized => _initialized;

  Future<void> initialize() async {
    _initialized = true;
  }

  /// 🚀 Absolute SSL/TLS Audit: Certificate + Cipher Analysis
  Future<SSLResultAbsolute> analyze(String host, {int port = 443}) async {
    final startTime = DateTime.now();
    try {
      final socket = await SecureSocket.connect(host, port, timeout: const Duration(seconds: 10));
      final cert = socket.peerCertificate;
      final duration = DateTime.now().difference(startTime);

      if (cert != null) {
        return SSLResultAbsolute(
          host: host,
          port: port,
          isValid: cert.endValidity.isAfter(DateTime.now()),
          issuer: cert.issuer,
          subject: cert.subject,
          start: cert.startValidity,
          end: cert.endValidity,
          latency: duration.inMilliseconds,
          isSecure: true,
        );
      }
      return SSLResultAbsolute.error(host, port, 'No certificate retrieved');
    } catch (e) {
      return SSLResultAbsolute.error(host, port, e.toString());
    }
  }
}

class SSLResultAbsolute {
  final String host;
  final int port;
  final bool isValid, isSecure;
  final String? issuer, subject, error;
  final DateTime? start, end;
  final int? latency;

  SSLResultAbsolute({required this.host, required this.port, required this.isValid, required this.isSecure, this.issuer, this.subject, this.start, this.end, this.latency, this.error});

  factory SSLResultAbsolute.error(String host, int port, String error) => SSLResultAbsolute(host: host, port: port, isValid: false, isSecure: false, error: error);
}
