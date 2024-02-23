#!/bin/bash
# See https://github.com/confluentinc/cp-demo/blob/5.2.4-post/scripts/security/certs-create.sh
set -o nounset \
    -o errexit \
    -o verbose \
    -o xtrace
DEFAULTPASS=confluent
ALTPASS=notconfluent
KEYTOOL=$JAVA_HOME/bin/keytool
# Generate a CA and truststore
# usage: generateCA name password
generateCA() {
  name=$1
  password=$2
  # Generate CA keypair
  openssl req -x509 -newkey rsa:4096 -sha256 \
          -keyout "${name}.key" -out "${name}.crt" \
          -days 365 -subj "/CN=$name/OU=Playtime/O=VDR/L=London/ST=England/C=GB" \
          -passin "pass:$password" -passout "pass:$password"
  # Create truststore and import the CA cert.
  rm -f "${name}truststore.p12"
  $KEYTOOL -noprompt -deststoretype pkcs12 -keystore "${name}truststore.p12" -alias CARoot -import -file "${name}.crt" -storepass "$password"
}
# Generate Keystore with User signed keypair and trusted chain.
# usage: generateKS name password ca capass
generateKS() {
  i=$1
  password=$2
  ca=$3
  capass=$4
  echo "===== Generate $i Keypair ====="

  rm -f $i.*
  # Create keypair and key
  $KEYTOOL -genkey -noprompt \
         -deststoretype pkcs12 \
         -alias "$i" \
         -dname "CN=$i, OU=Playtime, O=VDR, L=London, ST=England, C=GB" \
         -keystore "$i.p12" \
         -keyalg RSA \
         -storepass "$password" \
         -keypass "$password"
  # Create CSR, sign the key and import back into keystore
  # We need to request Alt Subject Name (SAN) to enable Server Host Authentication when running locally.
  $KEYTOOL -noprompt -keystore "$i.p12" -alias "$i" -certreq -file "$i.csr" -storepass "$password" -keypass "$password" \
           -ext "SAN=DNS:localhost,DNS:kafka,IP:127.0.0.1"
  # OpenSSL is by default quite reluctant to include SAN extension even when requested in the CSR.
  openssl x509 -req -CA "$ca.crt" -CAkey "$ca.key" -in $i.csr -out "$i-ca-signed.crt" -days 365 -sha256 -CAcreateserial -passin "pass:$capass" \
          -extfile <(printf "subjectAltName=DNS:kafka,DNS:localhost,IP:127.0.0.1")
  $KEYTOOL -noprompt -keystore "$i.p12" -alias CARoot -import -file "$ca.crt" -storepass "$password"
  $KEYTOOL -noprompt -keystore "$i.p12" -alias "$i" -import -file "$i-ca-signed.crt" -storepass "$password"
  rm "$i.csr"
  rm "$i-ca-signed.crt"
}
generateCA ca "$DEFAULTPASS"
#backward compatibility with unit test
mv catruststore.p12 truststore.p12
generateCA foreignca "$DEFAULTPASS"
#backward compatibility with unit test
mv foreigncatruststore.p12 foreigntruststore.p12
for i in client1 client2 server test
do
  generateKS "$i" "$DEFAULTPASS" ca "$DEFAULTPASS"
done
generateKS "client3" "$ALTPASS" ca "$DEFAULTPASS"

echo "$DEFAULTPASS" > keypass.creds
echo "$DEFAULTPASS" > password.creds