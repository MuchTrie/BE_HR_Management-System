# SecureHR Backend

Backend SecureHR dibuat menggunakan Go, Gin, GORM, JWT, dan SQLite untuk development lokal. Backend juga mendukung MySQL melalui konfigurasi environment.

## Prasyarat

- Go 1.24 atau versi yang lebih baru
- MySQL 8.x jika tidak menggunakan SQLite

## Instalasi

Dari folder `backend`, jalankan:

```powershell
Copy-Item .env.example .env
go mod download
```

Edit `.env` dan ubah minimal nilai berikut:

```env
JWT_SECRET=gunakan-secret-yang-kuat
SEED_ADMIN_PASSWORD=password-admin
SEED_MANAGER_PASSWORD=password-manager
SEED_EMPLOYEE_PASSWORD=password-employee
```

Secara default aplikasi menggunakan SQLite lokal:

```env
DATABASE_DRIVER=sqlite
DATABASE_DSN=securehr.db
```

## Menjalankan

```powershell
go run .\cmd\server
```

API tersedia di:

```text
http://localhost:8080/api/v1
```

Saat pertama kali dijalankan, server otomatis membuat database, role, dan akun seed dari `.env`.
