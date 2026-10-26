FROM dart:stable AS build
WORKDIR /app
COPY deploy/licensing/pubspec.yaml ./pubspec.yaml
RUN dart pub get
COPY lib/services/license_server_core.dart ./lib/services/license_server_core.dart
COPY tool/servidor_licencas.dart ./tool/servidor_licencas.dart
RUN mkdir -p /out && dart compile exe tool/servidor_licencas.dart -o /out/license_server

FROM scratch
COPY --from=build /runtime/ /
COPY --from=build /out/license_server /app/license_server
WORKDIR /app
ENV PORT=8787
ENV LICENSE_DATA_FILE=/var/data/lan_licenses.json
EXPOSE 8787
VOLUME ["/var/data"]
CMD ["/app/license_server"]
