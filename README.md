# Spring Security Uygulaması

Spring Boot tabanlı, JWT kimlik doğrulama, e-posta doğrulama ve gelişmiş güvenlik özellikleri içeren bir güvenlik uygulaması.

## Özellikler

- **JWT Kimlik Doğrulama** – Access token ve refresh token ile stateless oturum yönetimi
- **E-posta Doğrulama** – Kayıt ve giriş sonrası cihaz/IP değişikliğinde doğrulama kodu
- **Brute Force Koruması** – Başarısız giriş denemelerinde geçici ve kalıcı hesap kilidi
- **Rate Limiting** – Login ve refresh token istekleri için istek sınırı
- **IP Kontrolü** – Cihaz ve IP değişikliği tespiti
- **Token Blacklist** – Çıkış sonrası token’ların geçersiz kılınması
- **Güvenlik Denetim Kaydı** – Önemli olayların loglanması
- **Cookie Tabanlı Refresh Token** – HttpOnly, Secure, SameSite ayarları

## Teknolojiler

- **Java 21**
- **Spring Boot 4.0.1**
- **Spring Security**
- **Spring Data JPA**
- **PostgreSQL**
- **JJWT** (JWT)
- **Thymeleaf**
- **Lombok**

## Gereksinimler

- JDK 21
- PostgreSQL 12+
- Gradle 8.x

## Kurulum

### 1. Veritabanı

PostgreSQL’de veritabanı oluşturun:

```sql
CREATE DATABASE security_db;
```

### 2. Yapılandırma

`src/main/resources/application.properties` dosyasında veritabanı ve JWT ayarlarını güncelleyin:

```properties
# PostgreSQL
spring.datasource.url=jdbc:postgresql://localhost:5432/security_db
spring.datasource.username=postgres
spring.datasource.password=YOUR_PASSWORD

# JWT (production’da güçlü bir secret kullanın)
jwt.secret=YOUR_SECRET_KEY
jwt.access-token-expiration=900000
jwt.refresh-token-expiration=604800000
```

E-posta doğrulama kullanacaksanız SMTP ayarlarını ekleyin:

```properties
spring.mail.host=smtp.example.com
spring.mail.port=587
spring.mail.username=your-email@example.com
spring.mail.password=your-password
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true
```

### 3. Çalıştırma

```bash
./gradlew bootRun
```

Uygulama varsayılan olarak `http://localhost:8080` adresinde çalışır.

## API Endpoints

### Kimlik Doğrulama (`/api/auth`)

| Metod | Endpoint | Açıklama |
|-------|----------|----------|
| POST | `/register` | Yeni kullanıcı kaydı (e-posta doğrulama gerekir) |
| POST | `/login` | Giriş (e-posta + şifre) |
| POST | `/refresh-token` | Access token yenileme (refresh token cookie’den) |
| POST | `/logout` | Çıkış (token blacklist’e alınır) |
| POST | `/verify-email` | E-posta doğrulama kodu ile doğrulama |
| POST | `/resend-verification` | Doğrulama kodu tekrar gönderme |

### Kullanıcı (`/api/user`)

| Metod | Endpoint | Açıklama |
|-------|----------|----------|
| GET | `/profile` | Profil bilgisi (Bearer token gerekli) |

## Örnek İstekler

### Kayıt

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePass123!"}'
```

### Giriş

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePass123!"}'
```

### Profil (Access token ile)

```bash
curl -X GET http://localhost:8080/api/user/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Güvenlik Ayarları

- **Rate limit:** Login için 5 deneme/dakika, refresh için 10 deneme/dakika
- **Brute force:** 5 başarısız denemede 15 dakika kilitleme, 10’da kalıcı kilitleme
- **Token süreleri:** Access 15 dk, refresh 7 gün (application.properties’ten değiştirilebilir)
- **Cookie:** Refresh token HttpOnly, Secure, SameSite=Strict

## Proje Yapısı

```
src/main/java/spring/security/
├── auth/           # Kayıt, giriş, token, e-posta doğrulama
├── config/         # Security ve filtre yapılandırması
├── exception/      # Global hata yönetimi
├── jwt/            # JWT üretimi ve filtre
├── user/           # Kullanıcı entity, servis, controller
└── SecurityApplication.java
```

## Test

```bash
./gradlew test
```

Testlerde H2 in-memory veritabanı kullanılır.

## Lisans

Bu proje demo amaçlıdır.
