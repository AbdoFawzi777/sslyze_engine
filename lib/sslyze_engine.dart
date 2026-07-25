/// 🔒 Sslyze Engine - SSL/TLS scanning for Flutter
library sslyze_engine;

import 'dart:io';

class SslyzeEngine {
  static final SslyzeEngine _instance = SslyzeEngine._internal();
  factory SslyzeEngine() => _instance;
  SslyzeEngine._internal();

  bool _initialized = false;

  /// 🚀 تهيئة المحرك
  Future<void> initialize() async {
    _initialized = true;
  }

  /// 🔍 فحص SSL/TLS
  Future<SSLResult> analyze(String host, {int port = 443}) async {
    try {
      final startTime = DateTime.now();
      final socket = await SecureSocket.connect(host, port, timeout: Duration(seconds: 10));
      final connectionTime = DateTime.now().difference(startTime);
      final certificate = socket.peerCertificate;
      
      if (certificate != null) {
        return SSLResult(
          host: host,
          port: port,
          isValid: certificate.endValidity.isAfter(DateTime.now()),
          issuer: certificate.issuer,
          subject: certificate.subject,
          validFrom: certificate.startValidity,
          validTo: certificate.endValidity,
          connectionTime: connectionTime.inMilliseconds,
        );
      }
      return SSLResult.error(host, port, 'No certificate found');
    } catch (e) {
      return SSLResult.error(host, port, e.toString());
    }
  }

  /// 🔍 تنفيذ (للتوافق)
  Future<SSLResult> execute(String host, {Map<String, dynamic>? options}) async {
    return await analyze(host);
  }

  bool get isInitialized => _initialized;
}

class SSLResult {
  final String host;
  final int port;
  final bool isValid;
  final String? issuer;
  final String? subject;
  final DateTime? validFrom;
  final DateTime? validTo;
  final int? connectionTime;
  final String? error;
  
  // compatibility with original result class
  bool get success => !isValid ? false : true;

  SSLResult({
    required this.host,
    required this.port,
    required this.isValid,
    this.issuer,
    this.subject,
    this.validFrom,
    this.validTo,
    this.connectionTime,
    this.error,
  });

  factory SSLResult.error(String host, int port, String error) {
    return SSLResult(
      host: host,
      port: port,
      isValid: false,
      error: error,
    );
  }
}
