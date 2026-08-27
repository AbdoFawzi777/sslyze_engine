import 'dart:io';
import 'dart:async';
import 'identity_shield.dart';

/// 🔒 Sslyze Engine v9.0 - Comprehensive SSL/TLS Certificate & Trust Auditor
class SslyzeEngine {
  static final SslyzeEngine _instance = SslyzeEngine._internal();
  factory SslyzeEngine() => _instance;
  SslyzeEngine._internal();

  bool _initialized = false;
  bool get isInitialized => _initialized;

  Future<void> initialize() async {
    _initialized = true;
  }

  /// 🚀 Deep SSL/TLS Certificate & Trust Verification
  Future<SSLResultAbsolute> analyze(String host, {int port = 443, int timeoutSeconds = 8}) async {
    if (!IdentityShield.check()) throw Exception("Security Violation: Core Integrity Check Failed");

    final startTime = DateTime.now();
    try {
      final cleanHost = host.replaceAll(RegExp(r'https?://'), '').split('/')[0].split(':')[0];
      final socket = await SecureSocket.connect(
        cleanHost,
        port,
        timeout: Duration(seconds: timeoutSeconds),
        onBadCertificate: (cert) => true, // Allow inspection of invalid/self-signed certs
      );

      final cert = socket.peerCertificate;
      final duration = DateTime.now().difference(startTime);

      if (cert != null) {
        final now = DateTime.now();
        final isValid = cert.endValidity.isAfter(now) && cert.startValidity.isBefore(now);
        final daysRemaining = cert.endValidity.difference(now).inDays;
        final isSelfSigned = cert.issuer == cert.subject;
        final isExpiringSoon = isValid && daysRemaining <= 30;

        await socket.close();

        return SSLResultAbsolute(
          host: cleanHost,
          port: port,
          isValid: isValid,
          isSecure: isValid && !isSelfSigned,
          isSelfSigned: isSelfSigned,
          isExpiringSoon: isExpiringSoon,
          daysRemaining: daysRemaining,
          issuer: cert.issuer,
          subject: cert.subject,
          start: cert.startValidity,
          end: cert.endValidity,
          latency: duration.inMilliseconds,
        );
      }

      await socket.close();
      return SSLResultAbsolute.error(cleanHost, port, 'No peer certificate presented by server.');
    } catch (e) {
      return SSLResultAbsolute.error(host, port, e.toString());
    }
  }
}

class SSLResultAbsolute {
  final String host;
  final int port;
  final bool isValid;
  final bool isSecure;
  final bool isSelfSigned;
  final bool isExpiringSoon;
  final int daysRemaining;
  final String? issuer;
  final String? subject;
  final String? error;
  final DateTime? start;
  final DateTime? end;
  final int? latency;

  SSLResultAbsolute({
    required this.host,
    required this.port,
    required this.isValid,
    required this.isSecure,
    this.isSelfSigned = false,
    this.isExpiringSoon = false,
    this.daysRemaining = 0,
    this.issuer,
    this.subject,
    this.start,
    this.end,
    this.latency,
    this.error,
  });

  factory SSLResultAbsolute.error(String host, int port, String error) => SSLResultAbsolute(
    host: host,
    port: port,
    isValid: false,
    isSecure: false,
    error: error,
  );

  Map<String, dynamic> toJson() => {
    'host': host,
    'port': port,
    'is_valid': isValid,
    'is_secure': isSecure,
    'is_self_signed': isSelfSigned,
    'is_expiring_soon': isExpiringSoon,
    'days_remaining': daysRemaining,
    'issuer': issuer,
    'subject': subject,
    'start_date': start?.toIso8601String(),
    'end_date': end?.toIso8601String(),
    'latency_ms': latency,
    'error': error,
  };
}
