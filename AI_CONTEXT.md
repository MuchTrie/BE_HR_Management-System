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

`migrations/` berisi referensi migration MySQL 8.x. Untuk development lokal server menjalankan GORM AutoMigrate lalu `internal/seeder/Seed`, yang membuat role, akun demo, department, position, relasi employee, attendance, dan leave. Kredensial fixture berada di seeder internal, bukan `.env`; fixture ini hanya untuk development.

Seeder bersifat idempotent: menjalankan server berulang kali tidak menggandakan data berdasarkan unique email, employee number, department/position name, atau attendance per hari.

## Kontrak API

Semua response konsisten memakai `{success,data}` atau `{success:false,error:{code,message}}`. Endpoint berprefix `/api/v1`. Error bisnis harus dikembalikan sebagai HTTP error eksplisit, bukan fallback sukses. Frontend mengonsumsi endpoint melalui `frontend/src/lib/api.ts`.

### CORS dan query filter

Development CORS mengizinkan origin Vite `localhost:5173` dan `127.0.0.1:5173`, termasuk header `Authorization` untuk request JWT. Endpoint list employee, attendance, dan leave menerapkan filter yang dikirim frontend (`department_id`, `status`, `employee_id`, `date_from`, dan `date_to`) setelah authorization scope.

## Perintah

```text
go mod tidy
go run ./cmd/server
go test ./...
```

Sebelum production, ganti fixture credential, wajibkan `JWT_SECRET` yang kuat, tambahkan rate limiting, audit log, dan migration runner yang eksplisit.
