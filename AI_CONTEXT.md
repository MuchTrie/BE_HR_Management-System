# Konteks Backend untuk Pengembangan Lanjutan

Backend adalah modular monolith Go. Request mengalir dari router/middleware ke handler, service, repository, lalu database. Saat ini fondasi endpoint inti berada di `cmd/server/main.go`; pemisahan handler/service/repository dapat dilakukan bertahap tanpa mengubah kontrak API.

## Keputusan Bisnis

- Role: `ADMIN`, `MANAGER`, `EMPLOYEE`.
- Manager melihat bawahan berdasarkan `employees.manager_id`.
- Attendance hanya satu record per employee per tanggal; check-in kedua ditolak dan check-out hanya sekali.
- Leave dengan tanggal overlap terhadap leave `PENDING` atau `APPROVED` milik employee yang sama ditolak.
- Data master tidak dihapus permanen; gunakan soft delete/nonaktifkan agar histori tetap tersedia.
- Password di-hash dengan bcrypt.
- Access token JWT berumur pendek; refresh token disimpan sebagai hash dan dapat dicabut saat logout.

## Database dan Seed

`migrations/` berisi referensi migration MySQL 8.x. Untuk development lokal server menjalankan GORM AutoMigrate dan seed role + akun demo dari environment variables. Jangan commit `.env`; gunakan `.env.example`.

## Kontrak API

Semua response konsisten memakai `{success,data}` atau `{success:false,error:{code,message}}`. Endpoint berprefix `/api/v1`. Error bisnis harus dikembalikan sebagai HTTP error eksplisit, bukan fallback sukses. Frontend mengonsumsi endpoint melalui `frontend/src/lib/api.ts`.

## Perintah

```text
go mod tidy
go run ./cmd/server
go test ./...
```

Sebelum production, ganti driver SQLite development dengan MySQL, wajibkan `JWT_SECRET` yang kuat, tambahkan rate limiting, audit log, dan migration runner yang eksplisit.
