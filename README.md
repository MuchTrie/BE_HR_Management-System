# SecureHR Backend

Backend SecureHR dibuat menggunakan Go, Gin, GORM, JWT, dan MySQL Laragon untuk development lokal.

## Prasyarat

- Go 1.24 atau versi yang lebih baru
- MySQL Laragon berjalan pada port `3306`
- Database `securehr` sudah dibuat di MySQL

## Instalasi

Dari folder `backend`, jalankan:

```powershell
Copy-Item .env.example .env
go mod download
```

Edit `.env` dan ubah minimal nilai berikut:

```env
JWT_SECRET=gunakan-secret-yang-kuat
```

Konfigurasi MySQL Laragon:

```env
DATABASE_DRIVER=mysql
DATABASE_DSN=root:@tcp(127.0.0.1:3306)/securehr?charset=utf8mb4&parseTime=True&loc=Local
```

Jika MySQL Laragon menggunakan password, ubah bagian setelah `root:` pada `DATABASE_DSN`.

Buat database sekali melalui HeidiSQL/phpMyAdmin:

```sql
CREATE DATABASE securehr CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

## Menjalankan

```powershell
go run .\cmd\server
```

API tersedia di:

```text
http://localhost:8080/api/v1
```

Frontend Vite dapat berjalan melalui `localhost:5173` atau `127.0.0.1:5173`. Kedua origin tersebut sudah diizinkan oleh CORS development agar request JWT dari frontend dapat diterima.

Saat pertama kali dijalankan, server otomatis membuat database, role, akun demo, department, position, employee relation, attendance, dan leave melalui seeder internal di `internal/seeder/`.

## Akun seed development

Seeder internal membuat akun berikut:

```text
admin@example.com / change-me-admin
manager@example.com / change-me-manager
employee@example.com / change-me-employee
```

Data tersebut khusus development. Ganti atau nonaktifkan fixture seeder sebelum deployment production.
