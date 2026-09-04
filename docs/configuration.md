# Scanner Configuration

AuthZ Scanner hedef API'ye ozel bilgileri YAML config dosyasindan okur. Scanner modulleri demo API endpointlerini koda gommez; yeni bir API icin yeni bir config dosyasi hazirlanir.

## Top-Level Alanlar

```yaml
target:
  name: vulnerable
  base_url: http://127.0.0.1:8001

auth:
  login_path: /auth/login
  token_field: access_token

profile:
  path: /users/me
  id_field: id

identities: {}
bola:
  tests: []
bfla:
  tests: []
property_auth:
  tests: []
```

| Alan | Aciklama |
|---|---|
| `target` | Taranacak API'nin adi ve base URL bilgisi. |
| `auth` | Scanner'in test kimlikleriyle login olmak icin kullanacagi endpoint ve token alan adi. |
| `profile` | Login olan kimligin subject/user id bilgisini almak icin kullanilan endpoint. |
| `identities` | Scanner'in kullanacagi test kullanicilari. |
| `bola` | Object-level authorization testleri. |
| `bfla` | Function-level authorization testleri. |
| `property_auth` | Field/property-level authorization testleri. |

## Target

```yaml
target:
  name: external-api
  base_url: https://api.example.test
```

`name`, rapor dosyalarinda ve terminal ciktisinda kullanilir. `base_url`, scanner'in tum requestleri icin temel adrestir.

## Auth

```yaml
auth:
  login_path: /session
  token_field: token
```

Scanner her identity icin `login_path` endpointine email/password gonderir. Cevap JSON icinde `token_field` ile belirtilen alandan bearer token okunur.

Beklenen login request:

```json
{
  "email": "user@example.test",
  "password": "secret"
}
```

## Profile

```yaml
profile:
  path: /me
  id_field: subject_id
```

Scanner BOLA ve property authorization testlerinde login olan kullanicinin kaynak sahipligi iliskisini anlamak icin profil endpointinden subject id okur.

## Identities

```yaml
identities:
  owner:
    email: owner@example.test
    password: owner-secret
    role: user
  attacker:
    email: attacker@example.test
    password: attacker-secret
    role: user
  admin:
    email: admin@example.test
    password: admin-secret
    role: admin
```

Identity anahtar isimleri serbesttir. Scanner sabit olarak `userA` veya `admin1` beklemez. Test modulleri role alanina gore uygun identity secer.

## BOLA Tests

```yaml
bola:
  tests:
    - name: users_cannot_read_each_others_resources
      role: user
      owner_field: owner_id
      resource:
        list_method: GET
        list_path: /resources
        id_field: id
      attack:
        method: GET
        path_template: /resources/{id}
      expected_status: 403
```

BOLA testinde scanner ayni role sahip iki identity secer. Ilk identity ile resource listesi alinir, `owner_field` degeri profil id ile eslesen kaynak bulunur. Sonra ikinci identity ayni kaynaga erismeyi dener.

`path_template` icinde `{id}` kaynak id ile doldurulur. Ek path parametreleri icin `path_params` kullanilabilir:

```yaml
attack:
  method: GET
  path_template: /resources/{id}/children/{child_id}
  path_params:
    child_id: children.0.id
```

## BFLA Tests

Resource'a bagli privileged action:

```yaml
bfla:
  tests:
    - name: users_cannot_approve_resources
      role: user
      resource:
        list_method: GET
        list_path: /resources
        id_field: id
        owner_field: owner_id
      attack:
        method: POST
        path_template: /resources/{id}/approve
      expected_status: 403
```

Dogudan fonksiyon testi:

```yaml
bfla:
  tests:
    - name: users_cannot_list_admin_users
      role: user
      attack:
        method: GET
        path_template: /admin/users
      expected_status: 403
```

BFLA testlerinde scanner verilen role sahip bir identity ile normalde yetkili role ait olmasi gereken fonksiyonu cagirmayi dener.

## Property Authorization Tests

### Excessive Data Exposure

```yaml
property_auth:
  tests:
    - name: profile_must_not_expose_sensitive_fields
      type: excessive_data_exposure
      role: user
      request:
        method: GET
        path_template: /me
      forbidden_fields:
        - password_hash
        - api_key
        - refresh_token
```

Scanner response body icinde yasakli alan adlarini recursive olarak arar. Alan bulunursa finding uretir; raporda degerler `[REDACTED]` olarak maskelenir.

### Mass Assignment

```yaml
property_auth:
  tests:
    - name: create_resource_must_not_accept_server_controlled_fields
      type: mass_assignment
      role: user
      request:
        method: POST
        path_template: /resources
      payloads:
        - name: force_approved_state
          json_body:
            state: approved
          forbidden_effects:
            state: approved
```

Scanner payload icindeki server-controlled alanlari gonderir. Response veya verification response icinde `forbidden_effects` degerleri gorulurse finding uretir.

### Privilege Escalation

```yaml
property_auth:
  tests:
    - name: users_cannot_promote_themselves
      type: privilege_escalation
      role: user
      request:
        method: PUT
        path_template: /users/{subject_id}
      payloads:
        - name: promote_to_admin
          json_body:
            role: admin
          verification:
            method: GET
            path_template: /me
          forbidden_effects:
            role: admin
```

`{subject_id}`, profil endpointinden okunan id ile doldurulur. Verification request varsa scanner asil payload'dan sonra bu endpointi cagirir ve etkinin gercekten olusup olusmadigini kontrol eder.

## Yeni API'ye Uyarlama Akisi

1. API'nin login endpointini ve token response alanini belirle.
2. Profil endpointinden kullanici id alanini belirle.
3. En az iki ayni role sahip identity ve gerekiyorsa bir privileged identity hazirla.
4. BOLA icin ownership iceren resource list endpointlerini sec.
5. BFLA icin dusuk yetkili kullanicinin erismemesi gereken fonksiyonlari sec.
6. Property authorization icin hassas response alanlarini ve server-controlled payload alanlarini tanimla.
7. Scanner'i once tek hedefe, sonra varsa hardened/staging hedefe karsi calistir.

## Notlar

- Scanner JWT decode etmez; token'i yalnizca bearer token olarak kullanir.
- Authorization kurallari is kuralina bagli oldugu icin tamamen otomatik belirlenmez.
- Config icindeki demo endpointler degistirilebilir; scanner modulleri demo API'ye dogrudan bagimli degildir.
