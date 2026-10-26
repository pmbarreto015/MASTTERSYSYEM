import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';

class LanLicensedDevice {
  LanLicensedDevice({
    required this.machineCode,
    required this.machineName,
    required this.token,
    required this.activatedAt,
    required this.lastSeenAt,
    this.platform = 'windows',
  });

  final String machineCode;
  String machineName;
  final String token;
  final DateTime activatedAt;
  DateTime lastSeenAt;
  final String platform;

  factory LanLicensedDevice.fromJson(
    Map<String, dynamic> json, {
    DateTime? now,
  }) {
    final fallbackTime = (now ?? DateTime.now()).toUtc();
    return LanLicensedDevice(
      machineCode: json['machine_code']?.toString() ?? '',
      machineName: json['machine_name']?.toString() ?? '',
      token: json['token']?.toString() ?? '',
      activatedAt: DateTime.tryParse(json['activated_at']?.toString() ?? '') ??
          fallbackTime,
      lastSeenAt: DateTime.tryParse(json['last_seen_at']?.toString() ?? '') ??
          fallbackTime,
      platform: json['platform']?.toString() ?? 'windows',
    );
  }

  Map<String, dynamic> toJson() => {
        'machine_code': machineCode,
        'machine_name': machineName,
        'token': token,
        'activated_at': activatedAt.toIso8601String(),
        'last_seen_at': lastSeenAt.toIso8601String(),
        'platform': platform,
      };
}

class LanLicenseCustomer {
  LanLicenseCustomer({
    required this.id,
    required this.name,
    required this.login,
    required this.passwordSalt,
    required this.passwordHash,
    required this.maxDevices,
    required this.active,
    required this.createdAt,
    required this.devices,
    DateTime? expiresAt,
    this.allowedPlatform = 'both',
  }) : expiresAt = expiresAt?.toUtc();

  final String id;
  String name;
  final String login;
  final String passwordSalt;
  final String passwordHash;
  int maxDevices;
  bool active;
  final DateTime createdAt;
  final List<LanLicensedDevice> devices;
  DateTime? expiresAt;
  String allowedPlatform;

  bool isExpiredAt(DateTime now) =>
      expiresAt != null && !now.toUtc().isBefore(expiresAt!);

  bool get isExpired => isExpiredAt(DateTime.now());

  factory LanLicenseCustomer.fromJson(
    Map<String, dynamic> json, {
    DateTime? now,
  }) {
    final fallbackTime = (now ?? DateTime.now()).toUtc();
    return LanLicenseCustomer(
      id: json['id']?.toString() ?? '',
      name: json['name']?.toString() ?? '',
      login: json['login']?.toString() ?? '',
      passwordSalt: json['password_salt']?.toString() ?? '',
      passwordHash: json['password_hash']?.toString() ?? '',
      maxDevices: int.tryParse(json['max_devices']?.toString() ?? '') ?? 1,
      active: json['active'] != false,
      createdAt: DateTime.tryParse(json['created_at']?.toString() ?? '') ??
          fallbackTime,
      expiresAt: DateTime.tryParse(json['expires_at']?.toString() ?? ''),
      allowedPlatform: json['allowed_platform']?.toString() ?? 'both',
      devices: (json['devices'] as List? ?? const [])
          .map((item) => LanLicensedDevice.fromJson(
                Map<String, dynamic>.from(item as Map),
                now: fallbackTime,
              ))
          .toList(),
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'login': login,
        'password_salt': passwordSalt,
        'password_hash': passwordHash,
        'max_devices': maxDevices,
        'active': active,
        'created_at': createdAt.toIso8601String(),
        'expires_at': expiresAt?.toUtc().toIso8601String(),
        'allowed_platform': allowedPlatform,
        'devices': devices.map((device) => device.toJson()).toList(),
      };
}

class LicenseServerCore {
  LicenseServerCore._(
    this._dataFile, {
    DateTime Function()? now,
    this.onChanged,
    String? adminToken,
    this.requestBodyTimeout = const Duration(seconds: 10),
    this.maxRequestsPerMinute = 120,
    this.trustProxy = false,
  })  : _clock = now ?? DateTime.now,
        _adminToken = adminToken;

  static const int port = 8787;
  static const int discoveryPort = 8788;
  static const String provisionFileName = 'cliente_masttersystem.lic';
  static const String _storageSecret =
      'MastterSystem-LAN-License-Store-2026-7e51c94b';

  final File _dataFile;
  final void Function()? onChanged;
  final String? _adminToken;
  final Duration requestBodyTimeout;
  final int maxRequestsPerMinute;

  /// Enable only when every request passes through your trusted HTTPS proxy.
  final bool trustProxy;
  static const maxRequestBytes = 32 * 1024;
  static const _maxRateLimitEntries = 4096;
  final Map<String, _RequestWindow> _requestWindows = {};

  void _notify() => onChanged?.call();
  final DateTime Function() _clock;
  final List<LanLicenseCustomer> _customers = [];
  Future<void> _saveQueue = Future<void>.value();
  Future<void> _mutationQueue = Future<void>.value();
  HttpServer? _httpServer;
  RawDatagramSocket? _discoverySocket;
  String? serverError;
  String? _loadError;
  String? _saveError;
  static const _storageErrorMessage =
      'Não foi possível salvar o cadastro de licenças. Verifique o acesso à pasta do aplicativo e tente novamente.';

  List<LanLicenseCustomer> get customers => List.unmodifiable(_customers);
  bool get isRunning => _httpServer != null;
  int? get boundPort => _httpServer?.port;
  DateTime _now() => _clock().toUtc();

  static Future<LicenseServerCore> create(
    File dataFile, {
    DateTime Function()? now,
    void Function()? onChanged,
    String? adminToken,
    bool importProvision = false,
    Duration requestBodyTimeout = const Duration(seconds: 10),
    int maxRequestsPerMinute = 120,
    bool trustProxy = false,
  }) async {
    if (adminToken != null && adminToken.length < 32) {
      throw ArgumentError(
          'LICENSE_ADMIN_TOKEN deve possuir pelo menos 32 caracteres.');
    }
    if (maxRequestsPerMinute < 1) {
      throw ArgumentError('Limite de requisições inválido.');
    }
    final server = LicenseServerCore._(
      dataFile,
      now: now,
      onChanged: onChanged,
      adminToken: adminToken,
      requestBodyTimeout: requestBodyTimeout,
      maxRequestsPerMinute: maxRequestsPerMinute,
      trustProxy: trustProxy,
    );
    await server._load(importProvision: importProvision);
    return server;
  }

  Future<void> start({
    InternetAddress? bindAddress,
    int listenPort = port,
    bool enableDiscovery = true,
  }) async {
    if (isRunning) return;
    if (_loadError != null) {
      serverError = _loadError;
      _notify();
      return;
    }
    try {
      _httpServer = await HttpServer.bind(
        bindAddress ?? InternetAddress.anyIPv4,
        listenPort,
      );
      _httpServer!.idleTimeout = const Duration(seconds: 15);
      _httpServer!.listen(_handleRequest);
      if (enableDiscovery) await _startDiscovery();
      serverError = _saveError;
    } catch (error) {
      serverError =
          'Não foi possível iniciar a porta $listenPort. Feche outro servidor aberto e tente novamente.';
      await stop();
    }
    _notify();
  }

  Future<void> stop() async {
    _discoverySocket?.close();
    _discoverySocket = null;
    await _httpServer?.close(force: true);
    _httpServer = null;
    _notify();
  }

  Future<List<String>> localAddresses() async {
    final interfaces = await NetworkInterface.list(
      type: InternetAddressType.IPv4,
      includeLoopback: false,
    );
    return interfaces
        .expand((interface) => interface.addresses)
        .where((address) => !address.isLoopback)
        .map((address) => '${address.address}:${boundPort ?? port}')
        .toSet()
        .toList();
  }

  Future<String?> createCustomer({
    required String name,
    required String login,
    required String password,
    required int maxDevices,
    DateTime? expiresAt,
    String allowedPlatform = 'both',
  }) =>
      _withMutation(() async {
        if (_loadError != null) return _loadError;
        final normalizedLogin = login.trim().toLowerCase();
        if (name.trim().length < 2) return 'Informe o nome do cliente.';
        if (!RegExp(r'^[a-zA-Z0-9._-]{3,30}$').hasMatch(normalizedLogin)) {
          return 'O login deve ter de 3 a 30 letras ou números.';
        }
        if (password.length < 6) {
          return 'A senha deve possuir pelo menos 6 caracteres.';
        }
        final licenseError = _licenseSettingsError(
          expiresAt: expiresAt,
          allowedPlatform: allowedPlatform,
          maxDevices: maxDevices,
        );
        if (licenseError != null) return licenseError;
        if (_customers.any((customer) => customer.login == normalizedLogin)) {
          return 'Este login já está sendo utilizado.';
        }

        final salt = _randomToken(16);
        final customer = LanLicenseCustomer(
          id: _randomToken(12),
          name: name.trim(),
          login: normalizedLogin,
          passwordSalt: salt,
          passwordHash: _hashPassword(password, salt),
          maxDevices: maxDevices,
          active: true,
          createdAt: _now(),
          devices: [],
          expiresAt: expiresAt,
          allowedPlatform: allowedPlatform,
        );
        _customers.add(customer);
        try {
          await _save();
        } catch (_) {
          _customers.remove(customer);
          _notify();
          return _storageErrorMessage;
        }
        _notify();
        return null;
      });

  Future<String?> updateCustomerLicense({
    required LanLicenseCustomer customer,
    required DateTime? expiresAt,
    required String allowedPlatform,
    required int maxDevices,
  }) =>
      _withMutation(() async {
        if (_loadError != null) return _loadError;
        if (!_customers.contains(customer)) return 'Cliente não encontrado.';
        final error = _licenseSettingsError(
          expiresAt: expiresAt,
          allowedPlatform: allowedPlatform,
          maxDevices: maxDevices,
        );
        if (error != null) return error;
        if (maxDevices < customer.devices.length) {
          return 'Libere dispositivos antes de reduzir o limite abaixo da quantidade em uso.';
        }
        final previousExpiration = customer.expiresAt;
        final previousPlatform = customer.allowedPlatform;
        final previousLimit = customer.maxDevices;
        customer.expiresAt = expiresAt?.toUtc();
        customer.allowedPlatform = allowedPlatform;
        customer.maxDevices = maxDevices;
        try {
          await _save();
        } catch (_) {
          customer.expiresAt = previousExpiration;
          customer.allowedPlatform = previousPlatform;
          customer.maxDevices = previousLimit;
          _notify();
          return _storageErrorMessage;
        }
        _notify();
        return null;
      });

  String? _licenseSettingsError({
    required DateTime? expiresAt,
    required String allowedPlatform,
    required int maxDevices,
  }) {
    if (maxDevices < 1 || maxDevices > 999) {
      return 'A quantidade deve ficar entre 1 e 999 dispositivos.';
    }
    if (!const {'both', 'android', 'windows'}.contains(allowedPlatform)) {
      return 'Selecione Android, Windows ou ambos.';
    }
    if (expiresAt != null && !expiresAt.toUtc().isAfter(_now())) {
      return 'O vencimento deve ser posterior à data e hora atuais.';
    }
    return null;
  }

  Future<void> setCustomerActive(LanLicenseCustomer customer, bool active) =>
      _withMutation(() async {
        if (_loadError != null) throw StateError(_loadError!);
        if (!_customers.contains(customer)) {
          throw StateError('Cliente não encontrado.');
        }
        final previousActive = customer.active;
        customer.active = active;
        try {
          await _save();
        } catch (_) {
          customer.active = previousActive;
          _notify();
          throw StateError(_storageErrorMessage);
        }
        _notify();
      });

  Future<void> releaseDevice(
    LanLicenseCustomer customer,
    LanLicensedDevice device,
  ) =>
      _withMutation(() async {
        if (_loadError != null) throw StateError(_loadError!);
        if (!_customers.contains(customer)) {
          throw StateError('Cliente não encontrado.');
        }
        final index = customer.devices.indexOf(device);
        if (index < 0) return;
        customer.devices.removeAt(index);
        try {
          await _save();
        } catch (_) {
          customer.devices.insert(index, device);
          _notify();
          throw StateError(_storageErrorMessage);
        }
        _notify();
      });

  Future<T> _withMutation<T>(Future<T> Function() action) {
    final operation = _mutationQueue.then((_) => action());
    _mutationQueue = operation.then<void>(
      (_) {},
      onError: (Object error, StackTrace stackTrace) {},
    );
    return operation;
  }

  String createCustomerProvision(LanLicenseCustomer customer) {
    if (_loadError != null || _saveError != null) {
      throw StateError(_loadError ?? _saveError!);
    }
    final customerData = Map<String, dynamic>.from(customer.toJson());
    customerData['devices'] = <Object>[];
    return _encodeEnvelope({
      'version': 1,
      'customers': [customerData],
    });
  }

  Future<void> _startDiscovery() async {
    try {
      _discoverySocket = await RawDatagramSocket.bind(
        InternetAddress.anyIPv4,
        discoveryPort,
        reuseAddress: true,
      );
      _discoverySocket!.listen((event) {
        if (event != RawSocketEvent.read) return;
        final datagram = _discoverySocket?.receive();
        if (datagram == null) return;
        final message = utf8.decode(datagram.data, allowMalformed: true);
        if (message == 'MASTTER_LICENSE_DISCOVER') {
          _discoverySocket?.send(
            utf8.encode('MASTTER_LICENSE_SERVER|${boundPort ?? port}'),
            datagram.address,
            datagram.port,
          );
        }
      });
    } catch (_) {
      // O endereco manual continua funcionando se a descoberta for bloqueada.
    }
  }

  Future<void> _handleRequest(HttpRequest request) async {
    request.response.headers.contentType = ContentType.json;
    request.response.headers.set('Cache-Control', 'no-store');
    request.response.headers.set('X-Content-Type-Options', 'nosniff');
    try {
      if (!_allowRequest(request)) {
        request.response.statusCode = HttpStatus.tooManyRequests;
        request.response.headers.set('Retry-After', '60');
        _respond(request, {
          'success': false,
          'message': 'Muitas solicitações. Aguarde um minuto.'
        });
        return;
      }
      if (request.uri.path.startsWith('/admin/')) {
        await _handleAdminRequest(request);
        return;
      }
      if (request.method == 'GET' && request.uri.path == '/health') {
        _respond(
          request,
          _loadError != null || _saveError != null
              ? _storageFailure()
              : {'success': true, 'message': 'Servidor ativo.'},
        );
        return;
      }
      if (request.method != 'POST') {
        request.response.statusCode = HttpStatus.methodNotAllowed;
        _respond(
            request, {'success': false, 'message': 'Operação não permitida.'});
        return;
      }
      if (!const {'/activate', '/validate'}.contains(request.uri.path)) {
        request.response.statusCode = HttpStatus.notFound;
        _respond(
            request, {'success': false, 'message': 'Endereço não encontrado.'});
        return;
      }
      final body = await _readBody(request);
      if (request.uri.path == '/activate') {
        _respond(request, await _activate(body));
      } else if (request.uri.path == '/validate') {
        _respond(request, await _validate(body));
      } else {
        request.response.statusCode = HttpStatus.notFound;
        _respond(
            request, {'success': false, 'message': 'Endereço não encontrado.'});
      }
    } on _BodyTooLarge {
      request.response.statusCode = HttpStatus.requestEntityTooLarge;
      _respond(
          request, {'success': false, 'message': 'Solicitação muito grande.'});
    } on TimeoutException {
      request.response.statusCode = HttpStatus.requestTimeout;
      // A stalled request can still hold the request stream open. Close this
      // connection after flushing 408, instead of relying on its pending body.
      request.response.persistentConnection = false;
      await _respondAndClose(
          request, {'success': false, 'message': 'Tempo de leitura esgotado.'});
    } catch (_) {
      request.response.statusCode = HttpStatus.badRequest;
      _respond(request, {'success': false, 'message': 'Solicitação inválida.'});
    }
  }

  // Do not trust X-Forwarded-For from arbitrary clients. The deployment proxy
  // should enforce per-client limits too; this bound protects direct listeners.
  bool _allowRequest(HttpRequest request) {
    final now = _now();
    var address = request.connectionInfo?.remoteAddress.address ?? 'unknown';
    if (trustProxy) {
      // Caddy and Render append the actual client IP at the right. Ignore
      // attacker-controlled earlier entries and malformed values.
      final forwarded = request.headers.value('x-forwarded-for');
      final parsed =
          InternetAddress.tryParse(forwarded?.split(',').last.trim() ?? '');
      if (parsed != null) address = parsed.address;
    }
    _requestWindows.removeWhere((_, window) =>
        now.difference(window.startedAt) >= const Duration(minutes: 1));
    var window = _requestWindows[address];
    if (window == null) {
      // Refuse unknown addresses at capacity instead of evicting active limits.
      if (_requestWindows.length >= _maxRateLimitEntries) return false;
      window = _RequestWindow(now);
      _requestWindows[address] = window;
    }
    window.count++;
    return window.count <= maxRequestsPerMinute;
  }

  Future<Map<String, dynamic>> _readBody(HttpRequest request) async {
    if (request.contentLength > maxRequestBytes) throw const _BodyTooLarge();
    final bytes = <int>[];
    final timer = Stopwatch()..start();
    final chunks = StreamIterator<List<int>>(request);
    try {
      while (true) {
        final remaining = requestBodyTimeout - timer.elapsed;
        if (remaining <= Duration.zero) {
          throw TimeoutException('Leitura esgotada.');
        }
        if (!await chunks.moveNext().timeout(remaining)) break;
        if (bytes.length + chunks.current.length > maxRequestBytes) {
          throw const _BodyTooLarge();
        }
        bytes.addAll(chunks.current);
      }
    } finally {
      await chunks.cancel();
    }
    final decoded = jsonDecode(utf8.decode(bytes));
    if (decoded is! Map) {
      throw const FormatException('Objeto JSON obrigatório.');
    }
    return Map<String, dynamic>.from(decoded);
  }

  Future<void> _handleAdminRequest(HttpRequest request) async {
    if (_adminToken == null) {
      request.response.statusCode = HttpStatus.notFound;
      _respond(
          request, {'success': false, 'message': 'Endereço não encontrado.'});
      return;
    }
    final supplied =
        request.headers.value(HttpHeaders.authorizationHeader) ?? '';
    if (!_constantTimeEquals(supplied, 'Bearer $_adminToken')) {
      request.response.statusCode = HttpStatus.unauthorized;
      _respond(request,
          {'success': false, 'message': 'Credencial administrativa inválida.'});
      return;
    }
    if (request.method == 'GET' && request.uri.path == '/admin/customers') {
      if (_loadError != null || _saveError != null) {
        request.response.statusCode = HttpStatus.serviceUnavailable;
        _respond(request, _storageFailure());
      } else {
        _respond(request, {
          'success': true,
          'customers': _customers.map(_publicCustomer).toList()
        });
      }
      return;
    }
    if (request.method != 'POST') {
      request.response.statusCode = HttpStatus.methodNotAllowed;
      _respond(
          request, {'success': false, 'message': 'Operação não permitida.'});
      return;
    }
    if (!const {
      '/admin/customers',
      '/admin/update',
      '/admin/active',
      '/admin/release'
    }.contains(request.uri.path)) {
      request.response.statusCode = HttpStatus.notFound;
      _respond(
          request, {'success': false, 'message': 'Endereço não encontrado.'});
      return;
    }
    final body = await _readBody(request);
    DateTime? expiration() {
      if (body['expires_at'] == null) return null;
      final parsed = DateTime.tryParse(body['expires_at'].toString());
      if (parsed == null) throw const FormatException('Vencimento inválido.');
      return parsed;
    }

    String? error;
    if (request.uri.path == '/admin/customers') {
      error = await createCustomer(
        name: body['name']?.toString() ?? '',
        login: body['login']?.toString() ?? '',
        password: body['password']?.toString() ?? '',
        maxDevices: int.tryParse(body['max_devices']?.toString() ?? '') ?? 0,
        expiresAt: expiration(),
        allowedPlatform: body['allowed_platform']?.toString() ?? 'both',
      );
    } else {
      final customer = _customerById(body['customer_id']?.toString() ?? '');
      if (customer == null) {
        request.response.statusCode = HttpStatus.notFound;
        _respond(
            request, {'success': false, 'message': 'Cliente não encontrado.'});
        return;
      }
      try {
        switch (request.uri.path) {
          case '/admin/update':
            error = await updateCustomerLicense(
              customer: customer,
              expiresAt: expiration(),
              allowedPlatform: body['allowed_platform']?.toString() ?? '',
              maxDevices:
                  int.tryParse(body['max_devices']?.toString() ?? '') ?? 0,
            );
            break;
          case '/admin/active':
            if (body['active'] is! bool) {
              throw const FormatException('Situação inválida.');
            }
            await setCustomerActive(customer, body['active'] as bool);
            break;
          case '/admin/release':
            final code = body['machine_code']?.toString() ?? '';
            final device = customer.devices
                .where((device) => device.machineCode == code)
                .firstOrNull;
            if (device == null) {
              error = 'Dispositivo não encontrado.';
            } else {
              await releaseDevice(customer, device);
            }
            break;
        }
      } on StateError catch (failure) {
        error = failure.message.toString();
      }
    }
    _respond(request, {
      'success': error == null,
      if (error != null) 'message': error,
      if (error == null) 'customers': _customers.map(_publicCustomer).toList(),
    });
  }

  LanLicenseCustomer? _customerById(String id) {
    for (final customer in _customers) {
      if (customer.id == id) return customer;
    }
    return null;
  }

  Map<String, dynamic> _publicCustomer(LanLicenseCustomer customer) => {
        'id': customer.id,
        'name': customer.name,
        'login': customer.login,
        'max_devices': customer.maxDevices,
        'active': customer.active,
        'created_at': customer.createdAt.toIso8601String(),
        'expires_at': customer.expiresAt?.toIso8601String(),
        'allowed_platform': customer.allowedPlatform,
        'devices': customer.devices
            .map((device) => {
                  'machine_code': device.machineCode,
                  'machine_name': device.machineName,
                  'platform': device.platform,
                  'activated_at': device.activatedAt.toIso8601String(),
                  'last_seen_at': device.lastSeenAt.toIso8601String(),
                })
            .toList(),
      };

  Future<Map<String, dynamic>> _activate(Map<String, dynamic> body) =>
      _withMutation(() => _activateStored(body));

  Future<Map<String, dynamic>> _activateStored(
      Map<String, dynamic> body) async {
    if (!await _ensureStorageAvailable()) return _storageFailure();
    final now = _now();
    final login = body['login']?.toString().trim().toLowerCase() ?? '';
    final password = body['password']?.toString() ?? '';
    final machineCode = _digits(body['machine_code']?.toString() ?? '');
    final machineName = body['machine_name']?.toString().trim() ?? '';
    final platform = body['platform']?.toString() ?? 'windows';
    final customer = _customers.cast<LanLicenseCustomer?>().firstWhere(
          (item) => item?.login == login,
          orElse: () => null,
        );

    final expectedPassword =
        customer?.passwordHash ?? _hashPassword('unavailable', 'unavailable');
    final suppliedPassword =
        _hashPassword(password, customer?.passwordSalt ?? 'unavailable');
    final passwordMatches =
        _constantTimeEquals(expectedPassword, suppliedPassword);
    if (customer == null || !passwordMatches) {
      return {
        'success': false,
        'message': 'Login ou senha incorretos.',
        'error_code': 'invalid_credentials',
        'server_time': now.toIso8601String(),
      };
    }
    final licenseError = _customerAccessError(customer, platform, now);
    if (licenseError != null) return licenseError;
    if (machineCode.length != 12) {
      return _failure(
        customer,
        now,
        'invalid_machine_code',
        'Código do dispositivo inválido.',
      );
    }

    var device = customer.devices.cast<LanLicensedDevice?>().firstWhere(
          (item) => item?.machineCode == machineCode,
          orElse: () => null,
        );
    final isNewDevice = device == null;
    final previousName = device?.machineName;
    final previousSeen = device?.lastSeenAt;
    if (device == null) {
      if (customer.devices.length >= customer.maxDevices) {
        return _failure(
          customer,
          now,
          'device_limit',
          'Limite de dispositivos atingido. Libere um dispositivo no administrador.',
        );
      }
      device = LanLicensedDevice(
        machineCode: machineCode,
        machineName: machineName,
        token: _randomToken(32),
        activatedAt: now,
        lastSeenAt: now,
        platform: platform,
      );
      customer.devices.add(device);
    } else {
      if (device.platform != platform) {
        return _failure(
          customer,
          now,
          'platform_not_allowed',
          'Este dispositivo foi ativado em outra plataforma. Libere-o no administrador.',
        );
      }
      device.machineName = machineName;
      device.lastSeenAt = now;
    }
    try {
      await _save();
    } catch (_) {
      if (isNewDevice) {
        customer.devices.remove(device);
      } else {
        device.machineName = previousName!;
        device.lastSeenAt = previousSeen!;
      }
      _notify();
      return _storageFailure();
    }
    _notify();
    return {
      'success': true,
      'message': 'Sistema ativado com sucesso.',
      'token': device.token,
      ..._licenseInfo(customer, now),
    };
  }

  Future<Map<String, dynamic>> _validate(Map<String, dynamic> body) =>
      _withMutation(() => _validateStored(body));

  Future<Map<String, dynamic>> _validateStored(
      Map<String, dynamic> body) async {
    if (!await _ensureStorageAvailable()) return _storageFailure();
    final now = _now();
    final token = body['token']?.toString() ?? '';
    final machineCode = _digits(body['machine_code']?.toString() ?? '');
    for (final customer in _customers) {
      final device = customer.devices.cast<LanLicensedDevice?>().firstWhere(
            (item) =>
                item != null &&
                _constantTimeEquals(item.token, token) &&
                item.machineCode == machineCode,
            orElse: () => null,
          );
      if (device == null) continue;
      // Old Windows clients do not send a platform. New clients must match the
      // platform recorded when this token was activated.
      final platform = body['platform']?.toString() ?? 'windows';
      final licenseError = _customerAccessError(customer, device.platform, now);
      if (licenseError != null) return licenseError;
      if (platform != device.platform) {
        return _failure(
          customer,
          now,
          'platform_not_allowed',
          'A plataforma deste dispositivo não corresponde à ativação.',
        );
      }
      final previousSeen = device.lastSeenAt;
      device.lastSeenAt = now;
      try {
        await _save();
      } catch (_) {
        device.lastSeenAt = previousSeen;
        _notify();
        return _storageFailure();
      }
      return {
        'success': true,
        'message': 'Licença válida.',
        ..._licenseInfo(customer, now),
      };
    }
    return {
      'success': false,
      'message': 'Este dispositivo não está autorizado.',
      'error_code': 'unauthorized',
      'server_time': now.toIso8601String(),
    };
  }

  Future<bool> _ensureStorageAvailable() async {
    if (_loadError != null) return false;
    if (_saveError != null) {
      try {
        // All failed changes have already been rolled back. Persist that safe
        // state before allowing another activation or token validation.
        await _save();
        _notify();
      } catch (_) {
        return false;
      }
    }
    return true;
  }

  Map<String, dynamic> _storageFailure() => {
        'success': false,
        'message': _loadError ?? _saveError ?? _storageErrorMessage,
        'error_code': 'storage_unavailable',
        'retryable': _loadError == null,
        'server_time': _now().toIso8601String(),
      };

  Map<String, dynamic> _licenseInfo(
    LanLicenseCustomer customer,
    DateTime now,
  ) =>
      {
        'customer_name': customer.name,
        'max_devices': customer.maxDevices,
        'used_devices': customer.devices.length,
        'expires_at': customer.expiresAt?.toUtc().toIso8601String(),
        'server_time': now.toIso8601String(),
        'allowed_platform': customer.allowedPlatform,
      };

  Map<String, dynamic> _failure(
    LanLicenseCustomer customer,
    DateTime now,
    String errorCode,
    String message,
  ) =>
      {
        'success': false,
        'message': message,
        'error_code': errorCode,
        ..._licenseInfo(customer, now),
      };

  Map<String, dynamic>? _customerAccessError(
    LanLicenseCustomer customer,
    String platform,
    DateTime now,
  ) {
    if (!customer.active) {
      return _failure(customer, now, 'blocked', 'Este cliente está bloqueado.');
    }
    if (customer.isExpiredAt(now)) {
      return _failure(
        customer,
        now,
        'expired',
        'O prazo da licença terminou. Solicite a renovação ao administrador.',
      );
    }
    if (!const {'android', 'windows'}.contains(platform) ||
        (customer.allowedPlatform != 'both' &&
            customer.allowedPlatform != platform)) {
      return _failure(
        customer,
        now,
        'platform_not_allowed',
        'Esta licença não permite acesso nesta plataforma.',
      );
    }
    return null;
  }

  void _respond(HttpRequest request, Map<String, dynamic> data) {
    unawaited(_respondAndClose(request, data));
  }

  Future<void> _respondAndClose(
      HttpRequest request, Map<String, dynamic> data) async {
    request.response.write(jsonEncode({
      'server_time': _now().toIso8601String(),
      ...data,
    }));
    await request.response.close();
  }

  Future<void> _load({bool importProvision = true}) async {
    if (await _dataFile.exists()) {
      try {
        _applyData(_decodeEnvelope(await _dataFile.readAsString()));
        return;
      } catch (_) {
        _customers.clear();
        _loadError =
            'O cadastro de licenças está danificado ou foi alterado manualmente.';
        serverError = _loadError;
        return;
      }
    }

    if (!importProvision) return;
    final provision = File(
      '${File(Platform.resolvedExecutable).parent.path}'
      '${Platform.pathSeparator}$provisionFileName',
    );
    if (!await provision.exists()) return;
    try {
      _applyData(_decodeEnvelope(await provision.readAsString()));
      await _save();
    } catch (_) {
      _customers.clear();
      _loadError =
          'O arquivo de configuração do cliente é inválido ou foi alterado.';
      serverError = _loadError;
    }
  }

  Future<void> _save() async {
    if (_loadError != null) throw StateError(_loadError!);
    final contents = _encodeEnvelope({
      'version': 1,
      'customers': _customers.map((customer) => customer.toJson()).toList(),
    });
    _saveQueue = _saveQueue
        .catchError((Object error, StackTrace stackTrace) {})
        .then((_) => _writeDataFile(contents));
    try {
      await _saveQueue;
      _saveError = null;
      serverError = null;
    } catch (_) {
      _saveError = _storageErrorMessage;
      serverError = _saveError;
      rethrow;
    }
  }

  Future<void> _writeDataFile(String contents) async {
    await _dataFile.parent.create(recursive: true);
    final temporary = File('${_dataFile.path}.tmp');
    await temporary.writeAsString(
      contents,
      flush: true,
    );
    if (await _dataFile.exists()) {
      await _dataFile.copy('${_dataFile.path}.bak');
    }
    await temporary.rename(_dataFile.path);
  }

  static String _encodeEnvelope(Map<String, dynamic> data) {
    final payloadBytes = utf8.encode(jsonEncode(data));
    return const JsonEncoder.withIndent('  ').convert({
      'payload': base64Encode(payloadBytes),
      'signature': _sign(payloadBytes),
    });
  }

  static Map<String, dynamic> _decodeEnvelope(String contents) {
    final envelope = Map<String, dynamic>.from(jsonDecode(contents) as Map);
    final encodedPayload = envelope['payload']?.toString() ?? '';
    final savedSignature = envelope['signature']?.toString() ?? '';
    final payloadBytes = base64Decode(encodedPayload);
    final expectedSignature = _sign(payloadBytes);
    if (!_constantTimeEquals(savedSignature, expectedSignature)) {
      throw const FormatException('Assinatura inválida.');
    }
    return Map<String, dynamic>.from(
      jsonDecode(utf8.decode(payloadBytes)) as Map,
    );
  }

  void _applyData(Map<String, dynamic> data) {
    final now = _now();
    final customers = data['customers'] as List?;
    if (customers == null) throw const FormatException('Clientes ausentes.');
    _customers
      ..clear()
      ..addAll(
        customers.map(
          (item) => LanLicenseCustomer.fromJson(
            Map<String, dynamic>.from(item as Map),
            now: now,
          ),
        ),
      );
  }

  static String _sign(List<int> payload) =>
      Hmac(sha256, utf8.encode(_storageSecret)).convert(payload).toString();

  static bool _constantTimeEquals(String left, String right) {
    // Hash first to compare fixed-sized values even when input lengths differ.
    final a = sha256.convert(utf8.encode(left)).bytes;
    final b = sha256.convert(utf8.encode(right)).bytes;
    var difference = 0;
    for (var index = 0; index < a.length; index++) {
      difference |= a[index] ^ b[index];
    }
    return difference == 0;
  }

  static String _hashPassword(String password, String salt) =>
      sha256.convert(utf8.encode('$salt:$password')).toString();

  static String _randomToken(int bytes) {
    final random = Random.secure();
    return base64UrlEncode(
            List<int>.generate(bytes, (_) => random.nextInt(256)))
        .replaceAll('=', '');
  }

  static String _digits(String value) => value.replaceAll(RegExp(r'\D'), '');

  void dispose() {
    _discoverySocket?.close();
    _discoverySocket = null;
    _httpServer?.close(force: true);
    _httpServer = null;
    _requestWindows.clear();
  }
}

class _RequestWindow {
  _RequestWindow(this.startedAt);
  final DateTime startedAt;
  int count = 0;
}

class _BodyTooLarge implements Exception {
  const _BodyTooLarge();
}
