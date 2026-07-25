import 'package:flutter_test/flutter_test.dart';
import 'package:sslyze_engine/sslyze_engine.dart';

void main() {
  test('SslyzeEngine initialization test', () async {
    final engine = SslyzeEngine();
    await engine.initialize();
    expect(engine.isInitialized, true);
  });
}
