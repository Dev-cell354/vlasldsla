# Deploy Omnimun AI langsung ke Netlify

## Sebelum upload
- Gunakan Node.js 22+.
- Upload semua file dan folder project ke root repository GitHub. Folder `netlify/functions` wajib ikut.
- Jangan upload `.env`, kredensial, atau data pengguna.
- Jika repository lama memiliki `package-lock.json` dari versi project lain, hapus file lama lalu commit agar dependensi diselesaikan ulang dari `package.json` terbaru.

## Netlify
1. Import repository dari GitHub.
2. Biarkan Netlify memakai `netlify.toml`: publish directory `public`, functions directory `netlify/functions`, runtime Node 22. Build command hanya menampilkan pesan dan tidak bergantung pada `scripts/build-netlify.js`.
3. Tambahkan environment variables berikut di Site configuration → Environment variables:
   - `NODE_ENV=production`
   - `SESSION_SECRET` — secret acak yang panjang
   - `GEMINI_API_KEY`
   - `GMAIL_USER`
   - `GMAIL_PASS` — Google App Password
   - `MEDIA_JOB_SECRET` — secret acak lain yang panjang
   - `GEMINI_MEDIA_ENABLED=false`
4. Untuk Google OAuth (opsional): set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, dan `GOOGLE_CALLBACK_URL=https://NAMA-SITUS.netlify.app/auth/google/callback`; daftarkan callback itu pada Google Cloud Console.
5. Deploy dan tes halaman `/api/health`, lalu registrasi/email OTP/login/chat.

## Jika build gagal
- Pastikan `netlify.toml` berada di root repository, bukan di dalam subfolder.
- Pastikan `netlify/functions/api.js` dan `netlify/functions/generate-media-background.js` sudah di-commit.
- Pastikan Node.js runtime 22 terlihat di deploy log.
- Jangan gunakan build command `node scripts/build-netlify.js` dari pengaturan UI lama; `netlify.toml` versi ini tidak memerlukannya.
- Jika repository menyimpan lockfile lama yang mengacu pada dependensi berbeda, hapus `package-lock.json` lama lalu commit perubahan.
