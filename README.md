# SecureHR Backend

Backend REST API untuk SecureHR menggunakan Go, Gin, GORM, dan JWT. Jalankan lokal dengan SQLite pure-Go (`securehr.db`) secara default; `DATABASE_DRIVER=mysql` dan `DATABASE_DSN` dapat diarahkan ke MySQL 8.x.

## Menjalankan

1. Salin `.env.example` menjadi `.env` dan ubah secret/password seed.
2. Jalankan `go mod tidy`.
3. Jalankan `go run ./cmd/server`.
4. API tersedia di `http://localhost:8080/api/v1`.

Server melakukan auto-migration untuk development dan membuat tiga role serta tiga akun demo dari environment variables. Password tidak pernah dikembalikan oleh API.
