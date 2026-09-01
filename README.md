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

Ilk asamada dosyalar bilincli olarak bos veya minimum tutuldu. Sonraki adimda API veri modelleri, auth mantigi ve scanner cekirdek modelleri eklenecek.
