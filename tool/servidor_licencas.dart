import 'dart:async';
import 'dart:io';

// The same entry point builds both in the Flutter repo and the isolated server
// package inside Docker, whose package names differ.
// ignore: avoid_relative_lib_imports
import '../lib/services/license_server_core.dart';

/// Internet service entry point. Runs with the Dart SDK; no Flutter runtime.
Future<void> main() async {
  final environment = Platform.environment;
  final token = environment['LICENSE_ADMIN_TOKEN'] ?? '';
  final portText = environment['PORT'] ?? '8787';
  final port = int.tryParse(portText);
  if (token.length < 32 || token.trim() != token) {
    stderr.writeln(
        'Defina LICENSE_ADMIN_TOKEN com pelo menos 32 caracteres, sem espaços nas pontas.');
    exitCode = 64;
    return;
  }
  if (port == null || port < 1 || port > 65535) {
    stderr.writeln('PORT deve ser uma porta entre 1 e 65535.');
    exitCode = 64;
    return;
  }
  final dataFile =
      File(environment['LICENSE_DATA_FILE'] ?? 'data/lan_licenses.json');
  final server = await LicenseServerCore.create(dataFile,
      adminToken: token, trustProxy: environment['LICENSE_TRUST_PROXY'] == '1');
  await server.start(listenPort: port, enableDiscovery: false);
  if (!server.isRunning) {
    stderr.writeln(server.serverError ??
        'Não foi possível iniciar o servidor de licenças.');
    server.dispose();
    exitCode = 78;
    return;
  }
  stdout.writeln('Servidor de licenças ativo na porta ${server.boundPort}.');
  stdout.writeln(
      'Ativação e administração disponíveis. Use HTTPS no proxy de hospedagem.');
  final shutdown = Completer<void>();
  final signals = <StreamSubscription<ProcessSignal>>[];
  void requestShutdown(ProcessSignal _) {
    if (!shutdown.isCompleted) shutdown.complete();
  }

  signals.add(ProcessSignal.sigint.watch().listen(requestShutdown));
  if (!Platform.isWindows) {
    signals.add(ProcessSignal.sigterm.watch().listen(requestShutdown));
  }
  await shutdown.future;
  for (final signal in signals) {
    await signal.cancel();
  }
  await server.stop();
  server.dispose();
}
