# Aegis NetSec Dashboard - Panduan Instalasi & Penggunaan

Aegis NetSec Dashboard adalah aplikasi web keamanan siber modern berbasis Python Flask yang dirancang untuk menganalisis dan memvisualisasikan lalu lintas jaringan berkas packet capture (`.pcap`/`.pcapng`) serta catatan log deteksi Suricata (`eve.json`/`fast.log`). 

Aplikasi ini memiliki desain premium bertema gelap (*dark mode*) dengan gaya *glassmorphism* dan grafik interaktif (menggunakan Chart.js dengan sistem *fallback* SVG lokal jika komputer offline/tidak memiliki koneksi internet).

---

## Fitur Utama

1.  **Analisis Trafik PCAP/PCAPNG**: Mengekstrak volume data, jumlah paket, durasi lalu lintas, statistik protokol (TCP, UDP, ICMP, DNS), dan memetakan koneksi IP aktif berdasarkan volume byte terbesar.
2.  **Analisis Log Suricata (`eve.json` / `fast.log`)**: Mendukung format *line-delimited* JSON maupun format JSON Array standar. Menampilkan statistik sebaran aturan (*rules*) yang terpicu, pengelompokan tingkat bahaya (*Severity* 1/2/3), dan tabel riwayat peringatan yang dapat dicari/difilter.
3.  **Visualisasi Garis Waktu (Communication Timeline)**: Menunjukkan kepadatan paket jaringan atau frekuensi munculnya alert per waktu. Jika hanya terdapat 1 data waktu (misal pada trafik singkat), sistem akan otomatis membentuk grafik puncak visual yang presisi.
4.  **Deteksi Indikator Kompromi (IoC)**: Memindai alamat IP dan domain kueri DNS dari trafik yang diunggah terhadap pangkalan data intelijen ancaman (*Threat Intelligence*) lokal (`ioc_list.json`).
5.  **Ekspor Laporan PDF & CSV**: Menghasilkan dokumen laporan ringkasan keamanan formal berformat PDF yang dirancang rapi dengan tabel statistik, serta ekspor berkas data tabular mentah (.CSV).
6.  **Sistem Mode Offline (Resilient SVG Fallback)**: Jika komputer klien tidak terhubung ke internet untuk memuat library visualisasi dari CDN, sistem secara otomatis menggambar diagram grafis responsif menggunakan SVG internal peramban agar web tidak rusak/eror.
7.  **Simulation / Quick Test**: Tombol pintas untuk memuat berkas simulasi (`test.pcap` dan `eve.json`) secara instan untuk tujuan demonstrasi.

---

## Struktur Direktori Proyek

```text
dashboard/
├── app.py                      # Backend utama Flask (Route, Parser PCAP & Suricata)
├── ioc_list.json               # Database lokal ancaman (Dapat disesuaikan)
├── requirements.txt            # Daftar pustaka dependensi Python
├── generate_test_data.py       # Script untuk membuat data simulasi uji coba (.pcap, eve.json)
├── README.md                   # Dokumentasi panduan ini
├── templates/
│   └── index.html              # Template halaman utama HTML5
└── static/
    ├── css/
    │   └── style.css           # Desain tema gelap, glassmorphism, & animasi glow
    └── js/
        └── dashboard.js        # Logika unggah file, filter tabel, & render grafik (Chart.js / SVG)
```

---

## Panduan Instalasi (Langkah demi Langkah)

### Prasyarat System
*   **Python**: Versi 3.8 ke atas (Direkomendasikan Python 3.10 atau 3.11).
*   **Peramban Web**: Chrome, Edge, Firefox, atau Safari versi terbaru.

### Langkah 1: Siapkan Folder Proyek
Salin seluruh folder proyek `dashboard` ini ke komputer Anda.

### Langkah 2: Buka Command Prompt / Terminal
Buka terminal (CMD / PowerShell di Windows, atau Terminal di macOS/Linux) dan masuk ke direktori tempat Anda menyimpan proyek ini:
```bash
# Contoh jika diletakkan di drive D:\dashboard
d:
cd \dashboard
```

### Langkah 3: Membuat Virtual Environment (Sangat Direkomendasikan)
Gunakan virtual environment agar dependensi proyek ini tidak bentrok dengan pustaka lain di sistem operasi Anda:
```bash
# Membuat virtual environment bernama 'venv'
python -m venv venv

# Mengaktifkan venv di Windows (Command Prompt)
venv\Scripts\activate

# Atau mengaktifkan venv di Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# Atau mengaktifkan venv di macOS/Linux
source venv/bin/activate
```

### Langkah 4: Instalasi Dependensi Pustaka
Instal seluruh pustaka Python yang dibutuhkan yang tercantum di dalam berkas `requirements.txt`:
```bash
pip install -r requirements.txt
```
*Catatan: Dependensi utama yang akan diinstal meliputi `Flask`, `scapy` (untuk memproses paket capture), `fpdf2` (untuk mencetak PDF), dan `pandas` (untuk pengolahan data CSV).*

### Langkah 5: Membuat Berkas Pengujian/Simulasi (Opsional)
Untuk menghasilkan berkas simulasi pengujian (`mock_test.pcap`, `mock_eve.json`, `mock_fast.log`, dan `ioc_list.json`) secara otomatis di komputer lokal Anda, jalankan skrip generator berikut:
```bash
python generate_test_data.py
```

---

## Cara Menjalankan Aplikasi

1.  Pastikan virtual environment Anda telah aktif.
2.  Jalankan server Flask menggunakan perintah berikut:
    ```bash
    python app.py
    ```
3.  Setelah muncul pesan `* Running on http://127.0.0.1:5000`, buka peramban web (*browser*) Anda dan akses:
    **[http://127.0.0.1:5000/](http://127.0.0.1:5000/)**
4.  Untuk mematikan server, tekan tombol `CTRL + C` pada terminal Anda.

---

## Panduan Penggunaan Aplikasi

### A. Uji Coba Simulasi Cepat (Quick Test)
Jika Anda tidak memiliki file log keamanan untuk diuji, Anda bisa menggunakan tombol simulasi yang terletak di tengah dashboard:
1.  Klik **"Gunakan test.pcap (Simulasi)"** untuk memuat berkas simulasi trafik paket data PCAP.
2.  Klik **"Gunakan eve.json (Simulasi)"** untuk memuat berkas simulasi alert serangan IDS Suricata.
3.  Klik **"Gunakan dns-additionals.pcap (PCAP Asli)"** untuk memuat capture kueri DNS dari lalu lintas jaringan nyata.

### B. Menganalisis Berkas Anda Sendiri
1.  Pada panel sebelah kiri (**Unggah File Analisis**), seret berkas Anda ke area putus-putus atau klik tombol **Pilih File**.
2.  Pilih salah satu berkas dari penyimpanan Anda:
    *   Berkas trafik jaringan: `.pcap` atau `.pcapng` (Maksimal ukuran unggahan default: 50MB).
    *   Berkas log Suricata: `eve.json` atau `fast.log`.
3.  Sistem akan menampilkan lingkaran pemuatan (*loading spinner*) selama proses analisis berlangsung.
4.  Setelah selesai, data Anda akan ditampilkan dalam tab-tab visualisasi interaktif.

### C. Menavigasi Visualisasi
*   **Tab Distribusi Trafik**: Menampilkan bagan sebaran protokol (TCP/UDP/ICMP/DNS) dan daftar koneksi IP paling aktif (Top 10) berdasarkan volume transmisi byte.
*   **Tab Garis Waktu Komunikasi**: Menampilkan diagram garis waktu yang memetakan aktivitas komunikasi berdasarkan timestamp paket.
*   **Tab Alert Suricata** *(Hanya muncul jika mengunggah log Suricata)*: Menampilkan bagan kategori aturan terpicu, grafik sebaran tingkat bahaya (Severity), serta tabel detail log peringatan. Anda dapat mencari kata kunci IP atau signature tertentu pada kotak pencarian yang disediakan.
*   **Tab Indikator Kompromi (IoC)**: Menampilkan tabel daftar IP atau domain mencurigakan yang terdeteksi di dalam jaringan Anda berdasarkan database `ioc_list.json`.

### D. Mengustomisasi Database Deteksi Ancaman (IoC)
Anda dapat memodifikasi berkas [ioc_list.json](file:///c:/Users/PC/Documents/dashboard/ioc_list.json) di folder proyek untuk memperbarui daftar hitam ancaman (*threat list*) Anda sendiri. Cukup tambahkan entri IP atau domain ke dalam array `"ips"` atau `"domains"` dengan format JSON sebagai berikut:
```json
{
  "ips": [
    {
      "ip": "8.8.8.8",
      "type": "IP Flagged",
      "description": "Contoh deskripsi deteksi ancaman",
      "threat_level": "High"
    }
  ],
  "domains": [
    {
      "domain": "evil-c2-domain.net",
      "type": "C2 Domain",
      "description": "Contoh domain Command and Control",
      "threat_level": "High"
    }
  ]
}
```

### E. Mengekspor Laporan
Setelah berkas berhasil dianalisis:
*   Klik tombol **Ekspor CSV** di panel kiri untuk mengunduh data analisis tabular mentah.
*   Klik tombol **Ekspor PDF** untuk mengunduh berkas PDF formal yang mencakup ringkasan metrik, tabel deteksi bahaya, serta data distribusi trafik yang bersih dan siap dipresentasikan.

---

## Menjalankan Analisis Jaringan Asli di Windows (Live Capture & Suricata)

Karena **Npcap** dan **Suricata** telah berhasil diinstal di sistem Anda, sekarang Anda dapat melakukan sniffing lalu lintas jaringan secara langsung (*live capture*) dan menjalankan analisis Suricata secara nyata.

### A. Melakukan Sniffing Lalu Lintas Jaringan dengan Scapy (Live Capture)
Anda dapat menggunakan Scapy untuk merekam lalu lintas jaringan nyata dari kartu jaringan (Network Interface Card/NIC) Anda.

Untuk melihat daftar nama kartu jaringan yang tersedia di komputer Anda, jalankan perintah berikut dalam terminal (pastikan venv Anda aktif):
```bash
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

Untuk merekam lalu lintas (misalnya sebanyak 100 paket) dan menyimpannya ke berkas PCAP:
```python
from scapy.all import sniff, wrpcap

# Merekam lalu lintas jaringan
packets = sniff(count=100, timeout=10)
wrpcap("live_capture.pcap", packets)
```
Unggah berkas `live_capture.pcap` yang dihasilkan langsung ke Aegis NetSec Dashboard untuk dianalisis.

### B. Menjalankan Suricata Secara Nyata di Windows
Untuk mempermudah jalannya Suricata tanpa harus mengingat perintah yang panjang, kami telah menyediakan skrip pembantu **`run_suricata.py`** di dalam folder proyek ini.

Skrip ini secara otomatis mendeteksi lokasi instalasi Suricata, membaca daftar interface jaringan yang tersedia di PC Anda, dan mengonfigurasi Suricata agar menyimpan output berkas `eve.json` dan `fast.log` **langsung ke folder proyek tempat skrip ini berada** (sangat dinamis untuk siapa pun yang mengkloning proyek ini).

Cara menjalankannya:
1. Buka **Command Prompt** atau **PowerShell** sebagai **Administrator** (*Run as Administrator*).
2. Masuk ke direktori hasil klon dashboard Anda.
3. Aktifkan virtual environment Anda (`.\venv\Scripts\Activate.ps1`).
4. Jalankan perintah berikut:
   ```bash
   python run_suricata.py
   ```
5. Pilih nomor interface jaringan aktif Anda dari menu yang ditampilkan.
6. Suricata akan mulai mendeteksi lalu lintas jaringan secara real-time dan log deteksi (`eve.json`) akan otomatis dibuat di dalam folder proyek Anda!
7. Unggah berkas `eve.json` tersebut ke dashboard untuk visualisasi deteksi ancaman secara instan.


