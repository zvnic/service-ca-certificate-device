from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

# Создание ключа CA
ca_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Определение данных сертификата CA
ca_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Moscow"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Moscow"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"My CA"),
])

# Создание корневого сертификата CA
ca_cert = x509.CertificateBuilder().subject_name(
    ca_name
).issuer_name(
    ca_name
).public_key(
    ca_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=3650)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True,
).sign(private_key=ca_key, algorithm=hashes.SHA256())

# Сохранение CA ключа
with open("ca_key.pem", "wb") as f:
    f.write(ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Сохранение CA сертификата
with open("ca_cert.pem", "wb") as f:
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
