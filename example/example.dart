import 'package:sslyze_engine/sslyze_engine.dart';

void main() async {
  final engine = SslyzeEngine();
  await engine.initialize();
  print('SslyzeEngine is ready for tactical operations.');
}
