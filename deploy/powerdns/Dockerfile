# PowerDNS Authoritative with the geoip backend enabled for GeoDNS (the geo Lua
# record functions country()/continent() need a geo database loaded). Bundles the
# free DB-IP IP-to-Country Lite database (CC BY 4.0), which uses the GeoLite2
# nested schema PowerDNS reads (country.iso_code / continent.code). Mount your own
# /etc/powerdns/geoip/country.mmdb to override.
# The PowerDNS base image is Debian 11 (bullseye), whose apt repos are EOL, so
# fetch + unpack the GeoIP database in a current-base build stage and copy the
# result in (no apt-get against the EOL image).
FROM debian:13-slim AS geoip
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gzip \
 && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /geoip \
 && m=$(date +%Y-%m); pm=$(date -d '1 month ago' +%Y-%m 2>/dev/null || echo "$m"); \
    ( curl -fsSL "https://download.db-ip.com/free/dbip-country-lite-${m}.mmdb.gz" -o /tmp/c.gz \
      || curl -fsSL "https://download.db-ip.com/free/dbip-country-lite-${pm}.mmdb.gz" -o /tmp/c.gz ) \
 && gunzip -c /tmp/c.gz > /geoip/country.mmdb \
 && rm -f /tmp/c.gz

FROM powerdns/pdns-auth-49:latest

USER root
COPY --from=geoip /geoip/country.mmdb /etc/powerdns/geoip/country.mmdb
COPY geoip-zones.yml /etc/powerdns/geoip-zones.yml
