import os
import pandas as pd
import streamlit as st
from sqlalchemy import create_engine, text, Engine
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext

# --------------------
# KONFIGURASI APLIKASI
# --------------------
st.set_page_config(page_title="Admin - Manajemen User", page_icon="🔑", layout="centered")
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
    st.error("DATABASE_URL tidak ditemukan di Streamlit Secrets.")
    st.caption("Tambahkan `DATABASE_URL` ke blok `[secrets]` Streamlit Cloud.")
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
# DATA CABANG
# --------------------
@st.cache_data(show_spinner="Memuat daftar cabang...")
def fetch_cabang_list(_engine: Engine) -> list:
    try:
        query = text("SELECT DISTINCT cabang FROM pwh.hmhi_cabang WHERE cabang IS NOT NULL ORDER BY cabang")
        with _engine.connect() as conn:
            df = pd.read_sql(query, conn)
        return ["", "ALL"] + df["cabang"].dropna().tolist()
    except Exception as e:
        st.error(f"Gagal memuat daftar cabang: {e}")
        return ["", "ALL"]

# --------------------
# CEK MASTER KEY
# --------------------
def check_master_key():
    try:
        MASTER_KEY = st.secrets.get("secrets", {}).get("MASTER_KEY", "")
        if not MASTER_KEY:
            st.error("Aplikasi tidak dikonfigurasi dengan benar. Tambahkan MASTER_KEY di secrets.")
            st.stop()
    except Exception:
        st.error("Gagal membaca Streamlit Secrets.")
        st.stop()

    st.subheader("🔒 Verifikasi Admin Utama")
    st.warning("Halaman ini hanya untuk Super Admin.")
    master_key_input = st.text_input("Masukkan Master Key:", type="password")
    if st.button("Verifikasi Master Key", type="primary"):
        if master_key_input == MASTER_KEY:
            st.session_state.master_auth_ok = True
            st.rerun()
        else:
            st.error("Master Key salah.")

# --------------------
# FUNGSI DATA USER
# --------------------
@st.cache_data(show_spinner="Memuat data user...")
def fetch_user_list(_engine: Engine):
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

def update_user_password(_engine: Engine, username: str, new_password: str):
    """Update password untuk user tertentu."""
    try:
        hashed = pwd_context.hash(new_password[:72])
        with _engine.begin() as conn:
            conn.execute(
                text("UPDATE pwh.users SET hashed_password = :p WHERE username = :u"),
                {"p": hashed, "u": username},
            )
        st.success(f"Password untuk '{username}' berhasil diperbarui.")
        st.cache_data.clear()
    except Exception as e:
        st.error(f"Gagal memperbarui password: {e}")

def delete_user(_engine: Engine, username: str):
    """Menghapus user tertentu dari database."""
    try:
        with _engine.begin() as conn:
            conn.execute(text("DELETE FROM pwh.users WHERE username = :u"), {"u": username})
        st.warning(f"User '{username}' telah dihapus.")
        st.cache_data.clear()
    except Exception as e:
        st.error(f"Gagal menghapus user: {e}")

# --------------------
# TAB FORM DAN DAFTAR USER
# --------------------
def admin_tabs():
    tab1, tab2 = st.tabs(["➕ Buat User Baru", "📋 Daftar User"])

    # === TAB 1: FORM USER BARU ===
    with tab1:
        st.subheader("Form Pembuatan User Baru")
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
                elif password != password_confirm:
                    st.error("Password tidak cocok.")
                elif len(password) < 8:
                    st.error("Password minimal 8 karakter.")
                else:
                    try:
                        hashed_password = pwd_context.hash(password[:72])
                        with DB_ENGINE.begin() as conn:
                            query = text("""
                                INSERT INTO pwh.users (username, hashed_password, cabang)
                                VALUES (:user, :pass, :branch)
                            """)
                            conn.execute(query, {"user": username.strip(), "pass": hashed_password, "branch": cabang})
                        st.success(f"Sukses! User '{username}' telah ditambahkan.")
                        st.cache_data.clear()
                    except IntegrityError as e:
                        if "unique" in str(e).lower():
                            st.error(f"Username '{username}' sudah ada.")
                        else:
                            st.error(f"Error database: {e}")
                    except Exception as e:
                        st.error(f"Terjadi error: {e}")

    # === TAB 2: DAFTAR USER ===
    with tab2:
        st.subheader("📋 Daftar User yang Sudah Ada")
        df_users = fetch_user_list(DB_ENGINE)

        if df_users.empty:
            st.info("Belum ada data user.")
        else:
            for i, row in df_users.iterrows():
                with st.expander(f"👤 {row.username} — {row.cabang}"):
                    st.write(f"**Cabang:** {row.cabang}")
                    st.write(f"**Dibuat:** {row.created_at}")

                    col1, col2, col3 = st.columns([2, 2, 1])
                    with col1:
                        new_pw = st.text_input(
                            f"Password baru untuk {row.username}",
                            key=f"newpw_{i}",
                            type="password",
                            placeholder="Masukkan password baru..."
                        )
                    with col2:
                        if st.button(f"🔄 Update Password", key=f"update_{i}"):
                            if len(new_pw) < 8:
                                st.error("Password minimal 8 karakter.")
                            else:
                                update_user_password(DB_ENGINE, row.username, new_pw)
                    with col3:
                        if st.button(f"🗑️ Hapus", key=f"del_{i}"):
                            if st.session_state.get(f"confirm_delete_{i}", False):
                                delete_user(DB_ENGINE, row.username)
                                st.session_state[f"confirm_delete_{i}"] = False
                                st.rerun()
                            else:
                                st.session_state[f"confirm_delete_{i}"] = True
                                st.warning("Tekan sekali lagi untuk konfirmasi hapus!")

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
    admin_tabs()
