#!/usr/bin/env bash
set -eux

echo "Initializing jdk keystore and setting it to BouncyCastleFipsProvider..."

/usr/share/elasticsearch/jdk/bin/keytool \
-destkeystore /usr/share/elasticsearch/config/cacerts.bcfks \
-deststorepass ${%s} \
-deststoretype bcfks \
-importkeystore \
-providerclass org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider \
-providerpath /usr/share/bc-fips/bc-fips.jar \
-srckeystore /usr/share/elasticsearch/jdk/lib/security/cacerts \
-srcstorepass changeit \
-srcstoretype jks

echo "Keystore initialization successful."

echo "Initializing Elasticsearch keystore..."

/usr/share/elasticsearch/bin/elasticsearch-keystore create -p <<EOF
${%s}
${%s}
EOF

echo "Elasticsearch keystore initialization successful."
