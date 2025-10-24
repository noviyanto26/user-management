import os
import pandas as pd
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
# KONEKSI DATABASE
# -----------------------------
def _resolve_db_url() -> str:
    try:
        sec = st.secrets.get("secrets", {}).get("DATABASE_URL", "")
        if sec:
            return sec
    except Exception:
        pass
    env = os.environ.get("DATABASE_URL")
    if env:
        return env
    st.error('DATABASE_URL tidak ditemukan di Streamlit Secrets.')
    st.caption("Pastikan Anda sudah menambahkan `DATABASE_URL` di blok `[secrets]` Streamlit Cloud.")
    return None

@st.cache_resource(show_spinner="Menghubungkan ke database...")
def get_engine(dsn: str) -> Engine:
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

DB_URL = _resolve_db_url()
if DB_URL:
    DB_ENGINE = get_engine(DB_URL)
else:
    st.stop()

pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")

# --------------------
# AMBIL DAFTAR CABANG
# --------------------
@st.cache_data(show_spinner="Memuat daftar cabang...")
def fetch_cabang_list(_engine: Engine) -> list:
    try:
        query = text("SELECT DISTINCT cabang FROM pwh.hmhi_cabang WHERE cabang IS NOT NULL ORDER BY cabang")
        with _engine.connect() as conn:
            df = pd.read_sql(query, conn)
        return ["", "ALL"] + df['cabang'].dropna().tolist()
    except Exception as e:
        st.error(f"Gagal memuat daftar cabang: {e}")
        st.info("Pastikan tabel 'pwh.hmhi_cabang' ada dan memiliki kolom 'cabang'.")
        return ["", "ALL"]

# --------------------
# CEK MASTER KEY
# --------------------
def check_master_key():
    try:
        MASTER_KEY = st.secrets.get("secrets", {}).get("MASTER_KEY", "")
        if not MASTER_KEY:
            st.error("Aplikasi ini tidak dikonfigurasi dengan benar.")
            st.caption("Tambahkan `MASTER_KEY` ke `[secrets]` di Streamlit Cloud.")
            st.stop()
    except Exception:
        st.error("Gagal membaca Streamlit Secrets.")
        st.stop()

    st.subheader("🔒 Verifikasi Admin Utama")
    st.warning("Halaman ini hanya untuk Super Admin.")
    master_key_input = st.text_input("Masukkan Master Key:", type="password", key="master_key_input")
    if st.button("Verifikasi Master Key", type="primary"):
        if master_key_input == MASTER_KEY:
            st.session_state.master_auth_ok = True
            st.rerun()
        else:
            st.error("Master Key salah.")

# --------------------
# TAMPILKAN USER EXISTING
# --------------------
@st.cache_data(show_spinner="Memuat data user...")
def fetch_user_list(_engine: Engine):
    """Menampilkan daftar user yang sudah ada di database."""
    try:
        query = text("""
            SELECT username, cabang,
                   COALESCE(created_at::text, '(tidak tersedia)') AS created_at
            FROM pwh.users
            ORDER BY username
        """)
        with _engine.connect() as conn:
            df = pd.read_sql(query, conn)
        return df
    except Exception as e:
        st.error(f"Gagal memuat data user: {e}")
        return pd.DataFrame(columns=["username", "cabang", "created_at"])

# --------------------
# FORMULIR BUAT USER BARU
# --------------------
def show_create_user_form():
    st.subheader("➕ Buat User Baru")
    cabang_options = fetch_cabang_list(DB_ENGINE)

    with st.form("create_user_form", clear_on_submit=True):
        username = st.text_input("Username Baru")
        password = st.text_input("Password Baru", type="password")
        password_confirm = st.text_input("Konfirmasi Password", type="password")
        cabang = st.selectbox("Nama Cabang", options=cabang_options, index=0)
        submitted = st.form_submit_button("Buat User Baru", type="primary")

        if submitted:
            if not username or not password or not cabang:
                st.error("Semua field wajib diisi.")
                return
            if password != password_confirm:
                st.error("Password tidak cocok.")
                return
            if len(password) < 8:
                st.error("Password minimal 8 karakter.")
                return

            try:
                hashed_password = pwd_context.hash(password[:72])
                with DB_ENGINE.begin() as conn:
                    query = text("""
                        INSERT INTO pwh.users (username, hashed_password, cabang)
                        VALUES (:user, :pass, :branch)
                    """)
                    conn.execute(query, {"user": username.strip(), "pass": hashed_password, "branch": cabang})
                st.success(f"Sukses! User '{username}' telah ditambahkan.")
                st.cache_data.clear()  # refresh data user
            except IntegrityError as e:
                if "unique" in str(e).lower():
                    st.error(f"Username '{username}' sudah ada.")
                else:
                    st.error(f"Error database: {e}")
            except Exception as e:
                st.error(f"Terjadi error: {e}")

    # --------------------
    # TAMPILKAN TABEL USER
    # --------------------
    st.divider()
    st.subheader("📋 Daftar User yang Sudah Ada")
    df_users = fetch_user_list(DB_ENGINE)
    if df_users.empty:
        st.info("Belum ada data user.")
    else:
        st.dataframe(df_users, use_container_width=True)

# --------------------
# MAIN LOGIC
# --------------------
if not st.session_state.get("master_auth_ok", False):
    check_master_key()
elif st.session_state.get("master_auth_ok", False) and not st.session_state.get("show_form", False):
    st.success("Verifikasi berhasil.")
    if st.button("Masuk ke Halaman Admin ➔", type="primary"):
        st.session_state.show_form = True
        st.rerun()
else:
    show_create_user_form()
