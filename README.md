# AuthZ Scanner

Python tabanli AuthZ Scanner projesi.

Bu repo, authorization testleri icin iki hedef API ve tek bir scanner motoru uzerine kuruludur:

- `apps/vulnerable_api`: Bilerek zayif bir API.
- `apps/hardened_api`: Ayni davranisin guvenli uygulanmis hali.
- `scanner`: API'leri HTTP uzerinden test eden scanner.

Proje Cursor, VS Code veya baska bir editorle acilabilir. Kod editorunden bagimsiz kalacak sekilde standart Python repo yapisi kullanilir.

## Baslangic

```bash
cd authz-scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Planlanan Yapi

```text
apps/
  vulnerable_api/
  hardened_api/
scanner/
  core/
  modules/
  reporting/
config/
tests/
reports/
```

## API'leri Calistirma

Iki API ayri portlarda calistirilir.

Vulnerable API:

```bash
uvicorn apps.vulnerable_api.main:app --reload --port 8001
```

Hardened API:

```bash
uvicorn apps.hardened_api.main:app --reload --port 8002
```

Kontrol endpointleri:

```text
http://127.0.0.1:8001/health
http://127.0.0.1:8002/health
```

OpenAPI dokumanlari:

```text
http://127.0.0.1:8001/openapi.json
http://127.0.0.1:8002/openapi.json
```

## Test Kullanicilari

Seed verisi API baslarken otomatik olusturulur.

| Kimlik | Email | Sifre | Rol |
|---|---|---|---|
| userA | `userA@example.com` | `Password123!` | `user` |
| userB | `userB@example.com` | `Password123!` | `user` |
| admin1 | `admin1@example.com` | `Password123!` | `admin` |

Seed kayitlari sabit UUID degerleriyle olusturulur. Bu, scanner raporlarinda ve testlerde ayni kaynaklarin kolay takip edilmesini saglar.

## Hızlı Kontrol

Login istegi:

```bash
curl -s -X POST http://127.0.0.1:8001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"userA@example.com","password":"Password123!"}'
```

Testleri calistirma:

```bash
pytest
```

Scanner'i calistirma:

```bash
python -m scanner.main --config config/vulnerable.yaml
python -m scanner.main --config config/hardened.yaml
```

## Mevcut Kapsam

API tarafinda su zafiyet siniflari icin vulnerable ve hardened davranis farklari hazirdir:

- BOLA
- BFLA
- Mass Assignment
- Excessive Data Exposure
- Privilege Escalation

Scanner su anda config-driven sekilde BOLA, BFLA ve property authorization kontrollerini calistirir.

Property authorization kapsami uc davranisi kontrol eder:

- Excessive Data Exposure: Response icinde `password_hash`, token, API key, kart bilgisi, MFA secret gibi hassas alan adlarini recursive olarak arar.
- Mass Assignment: Create/update payload'larina server tarafinda kontrol edilmesi gereken alanlar ekleyip API'nin bunlari kabul edip etmedigini kontrol eder.
- Privilege Escalation: Dusuk yetkili bir kullanicinin `role` gibi yetki alanlarini degistirip degistiremedigini dogrulama istegiyle kontrol eder.

`apps/` altindaki API'ler test laboratuvari, `scanner/` altindaki kod ise baska REST API'lere uyarlanabilir motor olarak tasarlanir. Yeni bir API icin temel beklenti, `config/*.yaml` icinde login, profil, identity ve test kurallarinin o API'ye gore tanimlanmasidir.

## Gelecek Gelistirmeler

- OpenAPI tabanli config discovery: Scanner ileride hedef API'nin `/openapi.json` dokumanini okuyarak taslak config uretebilir. Bu ozellik manuel config yaklasiminin yerine gecmekten cok, yeni API'ler icin baslangic config'i hazirlayan yardimci bir katman olarak planlanir. Authorization kurallari is kuralina bagli oldugu icin uretilen config insan tarafindan kontrol edilmelidir.
