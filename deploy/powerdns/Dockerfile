# PowerDNS Authoritative with the geoip backend enabled for GeoDNS (the geo Lua
# record functions country()/continent() need a geo database loaded). Bundles the
# free DB-IP IP-to-Country Lite database (CC BY 4.0), which uses the GeoLite2
# nested schema PowerDNS reads (country.iso_code / continent.code). Mount your own
# /etc/powerdns/geoip/country.mmdb to override.
FROM powerdns/pdns-auth-49:latest

USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gzip \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /etc/powerdns/geoip \
 && m=$(date +%Y-%m); pm=$(date -d '1 month ago' +%Y-%m 2>/dev/null || echo "$m"); \
    ( curl -fsSL "https://download.db-ip.com/free/dbip-country-lite-${m}.mmdb.gz" -o /tmp/c.gz \
      || curl -fsSL "https://download.db-ip.com/free/dbip-country-lite-${pm}.mmdb.gz" -o /tmp/c.gz ) \
 && gunzip -c /tmp/c.gz > /etc/powerdns/geoip/country.mmdb \
 && rm -f /tmp/c.gz
COPY geoip-zones.yml /etc/powerdns/geoip-zones.yml
