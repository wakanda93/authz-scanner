# AuthZ Scanner

AuthZ Scanner, REST API'lerde authorization problemlerini test etmek icin gelistirilmis Python tabanli bir guvenlik test projesidir.

Proje iki parcadan olusur:

- Demo API laboratuvari: Bilerek zayif ve guvenli uygulanmis iki FastAPI hedefi.
- Scanner motoru: API'leri HTTP uzerinden test eden, config-driven authorization scanner.

Temel amac, ayni test motorunun iki farkli hedefte nasil davrandigini gostermektir:

```text
vulnerable API -> authorization bulgulari uretir
hardened API   -> ayni testlerde bulgu uretmemelidir
```

## Kapsam

Scanner su authorization zafiyet siniflarini kontrol eder:

- BOLA: Broken Object Level Authorization
- BFLA: Broken Function Level Authorization
- Excessive Data Exposure
- Mass Assignment
- Privilege Escalation

Demo API tarafinda bu davranislar bilincli olarak iki sekilde uygulanmistir:

- `apps/vulnerable_api`: Zafiyetleri gostermek icin bilerek zayif davranislar icerir.
- `apps/hardened_api`: Ayni endpointlerin guvenli uygulanmis halidir.

Scanner tarafinda hedefe ozel endpointler koda gomulu degildir. Hedef URL, login bilgisi, kullanici kimlikleri ve test kurallari `config/*.yaml` dosyalarindan okunur.

## Proje Yapisi

```text
apps/
  vulnerable_api/        # Bilerek zayif demo API
  hardened_api/          # Guvenli demo API
  reset_demo_data.py     # Demo SQLite verisini sifirlayan yardimci komut

scanner/
  core/                  # Config, identity, executor, result, evidence, finding modelleri
  modules/               # BOLA, BFLA ve property authorization scanner modulleri
  reporting/             # JSON ve Markdown rapor ureticileri
  main.py                # CLI giris noktasi

config/
  vulnerable.yaml        # Vulnerable API scanner config'i
  hardened.yaml          # Hardened API scanner config'i

tests/                   # API, scanner ve raporlama testleri
reports/                 # Lokal rapor ciktilari
```

## Kurulum

```bash
cd authz-scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Proje Cursor, VS Code veya baska bir editorle acilabilir. Kod editorunden bagimsiz standart Python repo yapisi kullanir.

## Demo API'leri Calistirma

Vulnerable API:

```bash
uvicorn apps.vulnerable_api.main:app --reload --port 8001
```

Hardened API:

```bash
uvicorn apps.hardened_api.main:app --reload --port 8002
```

Karsilastirmali scan icin iki API'nin ayni anda ayakta olmasi gerekir.

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

## Demo Kullanicilari

Seed verisi API baslarken otomatik olusturulur.

| Kimlik | Email | Sifre | Rol |
|---|---|---|---|
| userA | `userA@example.com` | `Password123!` | `user` |
| userB | `userB@example.com` | `Password123!` | `user` |
| admin1 | `admin1@example.com` | `Password123!` | `admin` |

Seed kayitlari sabit UUID degerleriyle olusturulur. Bu, scanner raporlarinda ayni kaynaklarin kolay takip edilmesini saglar.

## Scanner Kullanimi

Tek hedef tarama:

```bash
python -m scanner.main --config config/vulnerable.yaml
python -m scanner.main --config config/hardened.yaml
```

JSON rapor uretme:

```bash
python -m scanner.main --config config/vulnerable.yaml --report-format json
```

Markdown pentest raporu uretme:

```bash
python -m scanner.main --config config/vulnerable.yaml --report-format markdown
```

JSON ve Markdown raporu birlikte uretme:

```bash
python -m scanner.main --config config/vulnerable.yaml --report-format all
```

Iki hedefi karsilastirma:

```bash
python -m scanner.main --compare-config config/vulnerable.yaml config/hardened.yaml
```

Beklenen demo sonucu:

```text
vulnerable: 13 findings
hardened: 0 findings
```

Rapor dosyalari varsayilan olarak `reports/` klasorune yazilir. Bu klasor lokal calisma ciktisi olarak tutulur ve GitHub'a gonderilmez.

## Raporlama

Scanner iki rapor formati uretir:

- JSON: Makine tarafindan okunabilir ham tarama sonucu.
- Markdown: Insan tarafindan okunabilir pentest raporu.

Markdown rapor su bolumleri icerir:

- Executive Summary
- Scan Metadata
- Tested Identities
- Findings Summary
- Detailed Findings
- Evidence Appendix

Her bulguda su bilgiler yer alir:

- Severity
- Vulnerability class
- OWASP API category
- Affected endpoint
- Impact
- Steps to reproduce
- Evidence summary
- Remediation

Raporlama katmani hassas degerleri maskeler. Ornegin `password_hash`, `password`, `token`, `api_key`, `refresh_token`, `secret`, `ssn` ve kart bilgileri gibi alanlar raporda `[REDACTED]` olarak yazilir.

## Demo Verisini Sifirlama

Mutasyonlu scanner testleri demo verisini degistirebilir. Ornegin privilege escalation testi vulnerable API'de `userA` rolunu gecici olarak `admin` yapabilir veya mass assignment testleri yeni order kayitlari olusturabilir.

Demo verisini baslangic haline almak icin:

```bash
python -m apps.reset_demo_data
```

Beklenen cikti:

```text
Reset demo data for: vulnerable, hardened
```

Bu komut scanner'dan bagimsizdir. Scanner sadece test yapar; demo verisini temizleme sorumlulugu demo API laboratuvari tarafinda kalir.

## Hata Yonetimi

Scanner yaygin calisma hatalarini traceback yerine kisa CLI mesajlariyla raporlar:

- Eksik config dosyasi: `Scanner error: Config file not found`
- Gecersiz config dosyasi: `Scanner error: Config file is invalid`
- Login hatasi: `Authentication error`
- Kapali veya erisilemeyen API: `Connection error`

Bu durumlarda scanner `2` exit code ile kapanir.

## Testler

Tum testleri calistirma:

```bash
python -m pytest
```

Test kapsami su alanlari icerir:

- API health ve OpenAPI kontrolleri
- Login ve JWT davranisi
- Order, user ve admin endpoint davranislari
- BOLA scanner modulu
- BFLA scanner modulu
- Property authorization scanner modulu
- JSON raporlama
- Markdown raporlama
- CLI hata yonetimi
- Karsilastirmali scan komutu
- Demo veri reset komutu

## Tasinabilirlik

Scanner motoru demo API'ye dogrudan bagimli olacak sekilde yazilmamistir. Baska bir REST API icin temel olarak yeni bir config dosyasi gerekir:

- target base URL
- login endpoint'i
- token alan adi
- profil endpoint'i
- test kimlikleri
- BOLA/BFLA/property authorization test kurallari

Authorization kurallari is kuralina bagli oldugu icin scanner bunlari tamamen otomatik bilemez. Bu nedenle mevcut yaklasim manuel config uzerinden kontrollu test tanimlamaktir.

## Gelecek Gelistirmeler

- OpenAPI tabanli config discovery: `/openapi.json` dokumanindan baslangic config taslagi uretme.
- HTML rapor: Markdown raporun daha gorsel bir HTML ciktisi.
- Severity configuration: Bulgu severity degerlerini config uzerinden yonetme.
- Report manifest: Son uretilen raporlari takip eden `manifest.json` veya `latest` dosyalari.
- CI pipeline: Testleri GitHub Actions ile otomatik calistirma.
- Docker destegi: Iki API ve scanner icin tekrarlanabilir container tabanli calisma ortami.
