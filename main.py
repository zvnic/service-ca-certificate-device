from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import os
import aiofiles

app = FastAPI()

# Папки для шаблонов и файлов
templates = Jinja2Templates(directory="templates")
output_dir = "static"
os.makedirs(output_dir, exist_ok=True)

# Загрузка корневого CA сертификата и ключа
with open("ca_key.pem", "rb") as key_file:
    ca_key = serialization.load_pem_private_key(key_file.read(), password=None)

with open("ca_cert.pem", "rb") as cert_file:
    ca_cert = x509.load_pem_x509_certificate(cert_file.read())


@app.get("/", response_class=HTMLResponse)
async def get_form(request: Request):
    """Отображает форму для ввода ID устройства."""
    return templates.TemplateResponse("form.html", {"request": request})


@app.post("/generate_certificate", response_class=HTMLResponse)
async def generate_certificate(request: Request, device_id: str = Form(...)):
    """Генерирует ключ и сертификат устройства по его ID."""

    # Генерация ключа устройства
    device_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    device_key_bytes = device_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Создание CSR (запроса на подпись сертификата)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyCompany"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"device_" + device_id),
    ])).sign(device_key, hashes.SHA256())

    # Подпись сертификата CA
    device_cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(private_key=ca_key, algorithm=hashes.SHA256())

    # Преобразование сертификатов и ключей в строковый формат
    device_cert_bytes = device_cert.public_bytes(serialization.Encoding.PEM)
    ca_cert_bytes = ca_cert.public_bytes(serialization.Encoding.PEM)

    # Сохранение файлов для загрузки
    device_key_path = os.path.join(output_dir, f"{device_id}_key.pem")
    device_cert_path = os.path.join(output_dir, f"{device_id}_cert.pem")
    ca_cert_path = os.path.join(output_dir, "ca_cert.pem")

    async with aiofiles.open(device_key_path, 'wb') as f:
        await f.write(device_key_bytes)

    async with aiofiles.open(device_cert_path, 'wb') as f:
        await f.write(device_cert_bytes)

    async with aiofiles.open(ca_cert_path, 'wb') as f:
        await f.write(ca_cert_bytes)

    # Показ значений на веб-странице
    return templates.TemplateResponse("result.html", {
        "request": request,
        "device_key": device_key_bytes.decode("utf-8"),
        "device_cert": device_cert_bytes.decode("utf-8"),
        "ca_cert": ca_cert_bytes.decode("utf-8"),
        "device_key_path": f"/download/{device_id}_key.pem",
        "device_cert_path": f"/download/{device_id}_cert.pem",
        "ca_cert_path": "/download/ca_cert.pem"
    })


@app.get("/download/{filename}")
async def download_file(filename: str):
    """Маршрут для скачивания файлов."""
    file_path = os.path.join(output_dir, filename)
    return FileResponse(file_path, media_type="application/octet-stream", filename=filename)


# Модель для тела запроса
class DeviceRequest(BaseModel):
    device_id: str

@app.post("/api/generate_certificate")
def generate_certificate(request: DeviceRequest):
    device_id = request.device_id

    # Генерация закрытого ключа устройства
    device_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    device_key_bytes = device_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Создание CSR (запрос на подпись сертификата)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyCompany"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"device_" + device_id),
    ])).sign(device_key, hashes.SHA256())

    # Подписание сертификата CA
    device_cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(private_key=ca_key, algorithm=hashes.SHA256())

    # Преобразование сертификатов и ключей в строковый формат
    device_cert_bytes = device_cert.public_bytes(serialization.Encoding.PEM)
    ca_cert_bytes = ca_cert.public_bytes(serialization.Encoding.PEM)

    return {
        "device_key": device_key_bytes.decode("utf-8"),
        "device_cert": device_cert_bytes.decode("utf-8"),
        "ca_cert": ca_cert_bytes.decode("utf-8")
    }

@app.get("/api/ca_certificate")
def get_ca_certificate():
    ca_cert_bytes = ca_cert.public_bytes(serialization.Encoding.PEM)
    return {"ca_cert": ca_cert_bytes.decode("utf-8")}
