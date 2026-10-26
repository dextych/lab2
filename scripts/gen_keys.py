#Генерация RSA-пары ключей для подписи JWT (RS256)

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Куда сохранять (папка keys/ в корне проекта)
KEYS_DIR = Path(__file__).parent.parent / "keys"
PRIVATE_KEY_PATH = KEYS_DIR / "rsa_private.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "rsa_public.pem"


def main() -> None:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Сохраняем приватный ключ в PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    PRIVATE_KEY_PATH.write_bytes(private_pem)
    print(f"Приватный ключ сохранён: {PRIVATE_KEY_PATH}")

    # Извлекаем публичный ключ и сохраняем
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    PUBLIC_KEY_PATH.write_bytes(public_pem)
    print(f"Публичный ключ сохранён: {PUBLIC_KEY_PATH}")


if __name__ == "__main__":
    main()