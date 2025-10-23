import os
import pandas as pd  # <-- TAMBAHAN BARU
import streamlit as st
from sqlalchemy import create_engine, text, Engine
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext

# --------------------
# KONFIGURASI APLIKASI
# --------------------
st.set_page_config(page_title="Admin - Buat User Baru", page_icon="🔑", layout="centered")
st.title("🔑 Manajemen User PWH")

# -----------------------------
# KONEKSI DATABASE (Disalin dari main.py)
# -----------------------------
def _resolve_db_url() -> str:
    """Mencari DATABASE_URL dari st.secrets atau environment variables."""
    try:
        # --- PERBAIKAN DI SINI ---
        # Kita cari di dalam blok [secrets]
        sec = st.secrets.get("secrets", {}).get("DATABASE_URL", "")
        # --- SELESAI PERBAIKAN ---
        if sec: 
            return sec
    except Exception:
        pass
        
    # Fallback ke os.environ jika di-deploy di tempat lain
    env = os.environ.get("DATABASE_URL")
    if env: 
        return env
    
    # Error jika tidak ditemukan di st.secrets (di Streamlit Cloud)
    st.error('DATABASE_URL tidak ditemukan di Streamlit Secrets.')
    st.caption("Pastikan Anda sudah menambahkan `DATABASE_URL` ke dalam blok `[secrets]` di Streamlit Cloud.")
    return None

@st.cache_resource(show_spinner="Menghubungkan ke database...")
def get_engine(dsn: str) -> Engine:
    """Membuat dan menyimpan koneksi database engine."""
    if not dsn:
        st.stop()
    try:
        engine = create_engine(dsn, pool_pre_ping=True)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return engine
    except Exception as e:
        st.error(f"Gagal terhubung ke database: {e}")
        st.stop()

# --- Inisialisasi Engine & Hashing ---
DB_URL = _resolve_db_url()
if DB_URL:
    DB_ENGINE = get_engine(DB_URL)
else:
    st.stop()

pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")

# --- FUNGSI BARU: Mengambil Daftar Cabang ---
@st.cache_data(show_spinner="Memuat daftar cabang...")
def fetch_cabang_list(_engine: Engine) -> list:
    # --- PERBAIKAN: Ganti nama tabel di docstring ---
    """Mengambil daftar unik cabang dari tabel pwh.hmhi_cabang."""
    try:
        # --- PERBAIKAN: Ganti nama tabel di query ---
        query = text("SELECT DISTINCT cabang FROM pwh.hmhi_cabang WHERE cabang IS NOT NULL ORDER BY cabang")
        with _engine.connect() as conn:
            df = pd.read_sql(query, conn) 
            
        # Konversi ke list
        cabang_list = df['cabang'].dropna().tolist()
        
        # Tambahkan 'ALL' untuk Admin dan opsi kosong untuk placeholder
        return ["", "ALL"] + cabang_list
    except Exception as e:
        st.error(f"Gagal memuat daftar cabang: {e}")
        # --- PERBAIKAN: Ganti nama tabel di pesan error ---
        st.info("Pastikan tabel 'pwh.hmhi_cabang' ada dan memiliki kolom 'cabang'.")
        return ["", "ALL"] # Fallback jika error

# --------------------
# FUNGSI KEAMANAN (WAJIB!)
# --------------------
def check_master_key():
    """
    Memeriksa Master Key sebelum menampilkan form.
    Ini MENCEGAH siapa saja membuat user admin baru.
    """
    
    # 1. Dapatkan master key dari Streamlit Secrets
    try:
        # --- PERBAIKAN DI SINI ---
        # Kita cari di dalam blok [secrets]
        MASTER_KEY = st.secrets.get("secrets", {}).get("MASTER_KEY", "")
        # --- SELESAI PERBAIKAN ---
        
        if not MASTER_KEY:
            st.error("Aplikasi ini tidak dikonfigurasi dengan benar.")
            st.caption("Admin: Harap tambahkan `MASTER_KEY` ke dalam blok `[secrets]` di Streamlit Secrets.")
            st.stop()
    except Exception:
        st.error("Gagal membaca Streamlit Secrets.")
        st.stop()

    # 2. Minta Master Key
    st.subheader("🔒 Verifikasi Admin Utama")
    st.warning("Halaman ini hanya untuk Super Admin.")
    
    master_key_input = st.text_input("Masukkan Master Key:", type="password", key="master_key_input")
    
    # --- PERUBAHAN: Tombol Verifikasi Eksplisit ---
    # Kita tidak lagi memvalidasi secara otomatis saat mengetik.
    # Kita menunggu tombol ini diklik.
    if st.button("Verifikasi Master Key", type="primary"):
        if master_key_input == MASTER_KEY:
            st.session_state.master_auth_ok = True
            st.rerun() # Refresh untuk masuk ke langkah berikutnya
        else:
            st.error("Master Key salah.")
            # Jangan st.stop() agar user bisa mencoba lagi

# --------------------
# FORMULIR UTAMA
# --------------------
def show_create_user_form():
    """Menampilkan formulir untuk membuat user baru."""
    st.subheader("➕ Buat User Baru")
    
    # Panggil fungsi yang sudah di-cache untuk dapatkan list cabang
    cabang_options = fetch_cabang_list(DB_ENGINE)
    
    with st.form("create_user_form", clear_on_submit=True):
        username = st.text_input("Username Baru", help="Username untuk login.")
        
        password = st.text_input("Password Baru", type="password", help="Password minimal 8 karakter.")
        password_confirm = st.text_input("Konfirmasi Password", type="password")
        
        # --- PERUBAHAN: dari st.text_input ke st.selectbox ---
        cabang = st.selectbox(
            "Nama Cabang",
            options=cabang_options,
            index=0, # Default ke "" (kosong)
            help="Pilih 'ALL' untuk Admin, atau pilih nama cabang."
        )
        # --- SELESAI PERBAIKAN ---
        
        submitted = st.form_submit_button("Buat User Baru", type="primary")

        if submitted:
            # Validasi input
            # Validasi 'cabang' sekarang memeriksa apakah string-nya kosong
            if not username or not password or not cabang:
                st.error("Semua field wajib diisi.")
                return

            if password != password_confirm:
                st.error("Password tidak cocok. Silakan coba lagi.")
                return
            
            if len(password) < 8:
                st.error("Password terlalu pendek. Harap gunakan minimal 8 karakter.")
                return

            # Proses pembuatan user
            try:
                # --- PERBAIKAN: Truncate password ke 72 bytes ---
                # bcrypt punya limit 72 bytes (karakter). 
                # Kita potong manual untuk mencegah error jika password terlalu panjang.
                password_to_hash = password[:72]
                
                # Buat hash password
                hashed_password = pwd_context.hash(password_to_hash)
                # --- SELESAI PERBAIKAN ---
                
                # Simpan ke database
                with DB_ENGINE.begin() as conn:
                    query = text(
                        "INSERT INTO pwh.users (username, hashed_password, cabang) "
                        "VALUES (:user, :pass, :branch)"
                    )
                    conn.execute(query, {
                        "user": username.strip(),
                        "pass": hashed_password,
                        "branch": cabang  # Langsung gunakan nilai dari selectbox
                    })
                
                st.success(f"Sukses! User '{username}' untuk cabang '{cabang}' telah ditambahkan.")
                
            except IntegrityError as e:
                # Error jika username sudah ada
                if "unique constraint" in str(e).lower():
                    st.error(f"Error: Username '{username}' sudah ada. Silakan gunakan username lain.")
                else:
                    st.error(f"Error database: {e}")
            except Exception as e:
                st.error(f"Terjadi error: {e}")

# --------------------
# MAIN APP LOGIC
# --------------------

# --- PERUBAHAN: Logika 3 Langkah ---

# Langkah 1: Belum terverifikasi
if not st.session_state.get("master_auth_ok", False):
    check_master_key()

# Langkah 2: Terverifikasi, tapi belum klik "Masuk"
elif st.session_state.get("master_auth_ok", False) and not st.session_state.get("show_form", False):
    st.success("Verifikasi berhasil.")
    
    # Ini adalah tombol "Login" yang Anda minta
    if st.button("Masuk ke Halaman Admin ➔", type="primary"):
        st.session_state.show_form = True # Set status untuk menampilkan form
        st.rerun() # Refresh untuk menampilkan form

# Langkah 3: Terverifikasi DAN sudah klik "Masuk"
else:
    show_create_user_form()

