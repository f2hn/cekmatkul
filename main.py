import os
import re
import json
import time
import base64
import threading
from datetime import datetime, timezone, timedelta
import flet as ft

# Gunakan curl_cffi jika tersedia (PC/Termux), fallback ke requests standar (agar aman saat build APK)
try:
    from curl_cffi import requests as req_lib
    USE_CURL_CFFI = True
except ImportError:
    import requests as req_lib
    USE_CURL_CFFI = False

BASE_URL = "https://mentari.unpam.ac.id/api"
BATAS_HARI = 7
TTL_DAFTAR_MATKUL_DETIK = 7 * 24 * 3600
TURNSTILE_SITEKEY = "0x4AAAAAAAZ9GTupaM2GWdJn"


# =====================================================================
# 1. HELPER JWT, WAKTU, & PENYIMPANAN LOKAL
# =====================================================================

def decode_jwt_payload(token: str) -> dict:
    """Mengekstrak NIM (username) dan Nama Lengkap langsung dari JWT Bearer Token."""
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return {}
        payload_b64 = parts[1]
        padding = "=" * ((4 - len(payload_b64) % 4) % 4)
        decoded_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        return json.loads(decoded_bytes.decode("utf-8"))
    except Exception:
        return {}


def bersihkan_nama_matkul(raw_name: str) -> str:
    if not raw_name:
        return "MATA KULIAH"
    nama = re.sub(r"^\[\d+\]\s*", "", raw_name)
    return nama.split("#")[0].strip().upper()


def parse_waktu_iso(iso_str: str):
    if not iso_str or not isinstance(iso_str, str):
        return None
    try:
        return datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    except Exception:
        return None


def masih_dalam_batas_hari(iso_str: str, batas_hari: int = BATAS_HARI) -> bool:
    dt = parse_waktu_iso(iso_str)
    if not dt:
        return False
    return (datetime.now(timezone.utc) - dt) <= timedelta(days=batas_hari)


# =====================================================================
# 2. ENGINE API MENTARI & CLOUDFLARE HANDLER
# =====================================================================

class MentariClient:
    def __init__(self, storage_dir: str):
        self.cache_file = os.path.join(storage_dir, "mentari_cache.json")
        self.auth_file = os.path.join(storage_dir, "mentari_auth.json")
        self.cache = self._muat_json(self.cache_file, {"courses_ts": 0, "courses": [], "forum_topics": {}})
        self.auth = self._muat_json(self.auth_file, {
            "username": "251011450229",
            "fullname": "MAHASISWA UNPAM",
            "bearer_token": "",
            "cf_clearance": "",
            "sl_session": ""
        })
        self.session = self._buat_session()

    def _muat_json(self, path: str, default: dict) -> dict:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return default

    def simpan_cache(self):
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def simpan_auth(self):
        try:
            with open(self.auth_file, "w", encoding="utf-8") as f:
                json.dump(self.auth, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _buat_session(self):
        if USE_CURL_CFFI:
            s = req_lib.Session(impersonate="chrome")
        else:
            s = req_lib.Session()

        s.headers.update({
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "origin": "https://mentari.unpam.ac.id",
            "referer": "https://mentari.unpam.ac.id/login",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
        })
        self.terapkan_kredensial_ke_session(s)
        return s

    def terapkan_kredensial_ke_session(self, s=None):
        target = s or self.session
        token = self.auth.get("bearer_token", "").strip()
        cf = self.auth.get("cf_clearance", "").strip()
        sl = self.auth.get("sl_session", "").strip()

        if token:
            target.headers["authorization"] = f"Bearer {token}"
        else:
            target.headers["authorization"] = "Bearer undefined"

        if cf:
            target.cookies.set("cf_clearance", cf, domain="mentari.unpam.ac.id")
        if sl:
            target.cookies.set("sl-session", sl, domain="mentari.unpam.ac.id")

    def login_api(self, username: str, password: str, captcha_token: str, cf_clearance: str = "", sl_session: str = "") -> tuple[bool, str]:
        """
        Melakukan POST ke https://mentari.unpam.ac.id/api/login
        persis seperti struktur cURL yang diberikan.
        """
        if cf_clearance:
            self.auth["cf_clearance"] = cf_clearance.strip()
        if sl_session:
            self.auth["sl_session"] = sl_session.strip()

        self.session = self._buat_session()
        self.session.headers["authorization"] = "Bearer undefined"
        self.session.headers["content-type"] = "application/json"

        payload = {
            "username": username.strip(),
            "password": password,
            "captcha": captcha_token.strip()
        }

        try:
            resp = self.session.post(f"{BASE_URL}/login", json=payload, timeout=20)
            if resp.status_code not in (200, 201):
                return False, f"HTTP {resp.status_code}: Gagal melewati Cloudflare / kredensial salah."

            data = resp.json()
            # Ekstrak token dari berbagai kemungkinan key response API Mentari
            token = (
                data.get("token")
                or data.get("access_token")
                or (data.get("data", {}) if isinstance(data.get("data"), dict) else {}).get("token")
                or (data.get("data", {}) if isinstance(data.get("data"), dict) else {}).get("access_token")
            )

            if not token:
                pesan_err = data.get("message") or data.get("error") or str(data)
                return False, f"Login gagal: {pesan_err}"

            # Simpan cookie sl-session baru jika diberikan oleh response header
            new_sl = resp.cookies.get("sl-session")
            if new_sl:
                self.auth["sl_session"] = new_sl

            self.set_token_manual(token, self.auth.get("cf_clearance", ""), self.auth.get("sl_session", ""))
            return True, "Login berhasil!"
        except Exception as e:
            return False, f"Error koneksi: {str(e)}"

    def set_token_manual(self, bearer_token: str, cf_clearance: str, sl_session: str) -> tuple[bool, str]:
        bersih_token = bearer_token.replace("Bearer ", "").strip()
        payload = decode_jwt_payload(bersih_token)
        if not payload:
            return False, "Format Bearer Token (JWT) tidak valid!"

        exp = payload.get("exp", 0)
        if exp and exp < time.time():
            return False, "Bearer Token sudah kedaluwarsa (expired)!"

        self.auth["bearer_token"] = bersih_token
        self.auth["cf_clearance"] = cf_clearance.strip()
        self.auth["sl_session"] = sl_session.strip()
        self.auth["username"] = str(payload.get("username") or self.auth.get("username") or "")
        self.auth["fullname"] = str(payload.get("fullname") or "MAHASISWA")

        self.simpan_auth()
        self.session = self._buat_session()
        return True, f"Berhasil masuk sebagai {self.auth['fullname']} ({self.auth['username']})"

    def get_json(self, url: str):
        ts = str(int(time.time() * 1000))
        sep = "&" if "?" in url else "?"
        full_url = f"{url}{sep}t={ts}"
        try:
            resp = self.session.get(full_url, headers={"t": ts}, timeout=15)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    def ambil_semua_matkul_hemat(self, paksa_refresh: bool = False) -> list:
        sekarang_ts = time.time()
        if (
            not paksa_refresh
            and self.cache.get("courses")
            and (sekarang_ts - self.cache.get("courses_ts", 0) < TTL_DAFTAR_MATKUL_DETIK)
        ):
            return self.cache["courses"]

        data = self.get_json(f"{BASE_URL}/user-course?page=1&limit=12")
        if isinstance(data, dict) and isinstance(data.get("data"), list) and data["data"]:
            ringkas = [
                {
                    "kode_course": m.get("kode_course"),
                    "nama_mata_kuliah": m.get("nama_mata_kuliah") or bersihkan_nama_matkul(m.get("coursename", "")),
                }
                for m in data["data"]
                if m.get("kode_course")
            ]
            self.cache["courses"] = ringkas
            self.cache["courses_ts"] = sekarang_ts
            self.simpan_cache()
            return ringkas

        return self.cache.get("courses", [])

    def ambil_topic_ids_hemat(self, forum_id: str) -> list:
        forum_topics_map = self.cache.setdefault("forum_topics", {})
        if forum_id in forum_topics_map and forum_topics_map[forum_id]:
            return forum_topics_map[forum_id]

        topic_data = self.get_json(f"{BASE_URL}/forum/topic/{forum_id}")
        if not isinstance(topic_data, dict):
            return []

        topics = topic_data.get("topics", [])
        topic_ids = [str(t["id"]) for t in topics if isinstance(t, dict) and t.get("id")]

        if topic_ids:
            forum_topics_map[forum_id] = topic_ids
            self.simpan_cache()

        return topic_ids

    def ada_balasan_dosen_belum_dibalas(self, forum_id: str) -> bool:
        nim_saya = str(self.auth.get("username", "")).strip()
        topic_ids = self.ambil_topic_ids_hemat(forum_id)
        if not topic_ids:
            return False

        for topic_id in topic_ids:
            reply_json = self.get_json(f"{BASE_URL}/forum/reply/{topic_id}")
            if not isinstance(reply_json, dict):
                continue

            daftar_post = reply_json.get("data", [])
            if not isinstance(daftar_post, list) or not daftar_post:
                continue

            post_by_id = {}
            children_map = {}
            for post in daftar_post:
                if not isinstance(post, dict) or not post.get("id"):
                    continue
                pid = str(post["id"])
                parent_id = str(post.get("id_parent") or "")
                post_by_id[pid] = post
                children_map.setdefault(parent_id, []).append(post)

            def ambil_semua_turunan(root_id):
                turunan = []
                stack = list(children_map.get(root_id, []))
                while stack:
                    curr = stack.pop(0)
                    turunan.append(curr)
                    curr_id = str(curr.get("id") or "")
                    if curr_id in children_map:
                        stack.extend(children_map[curr_id])
                return turunan

            akar_komentar_saya = [
                p for p in daftar_post
                if isinstance(p, dict)
                and str(p.get("nim") or "") == nim_saya
                and str(p.get("id_parent") or "") not in post_by_id
            ]

            for akar in akar_komentar_saya:
                akar_id = str(akar["id"])
                semua_di_thread = [akar] + ambil_semua_turunan(akar_id)

                post_dosen_di_thread = [
                    p for p in semua_di_thread
                    if p.get("id_dosen") is not None or p.get("dosen") is not None
                ]
                if not post_dosen_di_thread:
                    continue

                post_saya_di_thread = [
                    p for p in semua_di_thread
                    if str(p.get("nim") or "") == nim_saya
                ]

                for p_dosen in post_dosen_di_thread:
                    waktu_dosen_str = p_dosen.get("createdAt")
                    if not masih_dalam_batas_hari(waktu_dosen_str, BATAS_HARI):
                        continue

                    id_dosen_post = str(p_dosen.get("id") or "")
                    dt_dosen = parse_waktu_iso(waktu_dosen_str)

                    turunan_dosen_ids = {str(x.get("id")) for x in ambil_semua_turunan(id_dosen_post)}
                    sudah_saya_balas = False

                    for p_saya in post_saya_di_thread:
                        parent_saya = str(p_saya.get("id_parent") or "")
                        dt_saya = parse_waktu_iso(p_saya.get("createdAt"))

                        if parent_saya == id_dosen_post or parent_saya in turunan_dosen_ids:
                            sudah_saya_balas = True
                            break
                        if dt_saya and dt_dosen and dt_saya > dt_dosen:
                            sudah_saya_balas = True
                            break

                    if not sudah_saya_balas:
                        return True

        return False


# =====================================================================
# 3. ANTARMUKA PENGGUNA (FLET MATERIAL 3 UI)
# =====================================================================

def main(page: ft.Page):
    page.title = "Mentari UNPAM Tracker"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 0
    page.window_width = 430
    page.window_height = 840
    page.bgcolor = "#0F172A"  # Slate 900

    storage_dir = os.path.dirname(os.path.abspath(__file__))
    client = MentariClient(storage_dir)

    # Set default token dari script user jika belum ada yang tersimpan
    if not client.auth.get("bearer_token"):
        default_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjVjOGZlYmNiLTkwYjAtNDBhYi04MDU1LTZjM2E3NmY2NGIzZiIsInVzZXJuYW1lIjoiMjUxMDExNDUwMjI5Iiwicm9sZSI6Ik1BSEFTSVNXQSIsImZ1bGxuYW1lIjoiTS4gUEFSSEFOIEFXQUxVUk9ITUFOIiwicHJvZGkiOlsiNTUyMDEiXSwiaWF0IjoxNzk0NzU3Mzc5LCJleHAiOjE4MDI1MzMzNzl9.O0pSHQdaLTOWlPxQJyB_-GqHHVmIdmUXNLvAEkpq060"
        default_cf = "Cu8LJniLTrLvHXwuu-P0Fm8uC1--ojVDUlddwxRn-QTSBZ3uV8qEd3NcbhKFRRAIVbCeKW-Ggaqpx0iw-_ypwUBNhqnBKxYfsNhfpo1hoXmf__-y0uuhzC-RZhhY8Nl8k2BYeBTu8QkMgqWQfUosm3DlDtid-VkI0SMZXX_02vqn_c0fQ4XQcxuxUB5cjffjpiOzq70qk_AHknOu39Sg5StxS26E_HiegFHeXsFpGzFxSfTl7OPlmG9ecLQxab92FvWE9hR4mJnzkGtF1hmngoYI2ignsC8o-mhow_OpSqucjzlAM7QJ"
        default_sl = "GUiRPk4j+2qkw3IVRwu1IQ=="
        client.set_token_manual(default_jwt, default_cf, default_sl)

    def tampilkan_pesan(teks: str, warna: str = "#10B981"):
        page.snack_bar = ft.SnackBar(
            content=ft.Text(teks, color="white", weight=ft.FontWeight.W_500),
            bgcolor=warna,
            duration=3000,
        )
        page.snack_bar.open = True
        page.update()

    # -----------------------------------------------------------------
    # KOMPONEN BADGE STATUS (PRETEST, FORUM, POSTTEST, KUISONER)
    # -----------------------------------------------------------------
    def buat_chip_status(label: str, selesai: bool):
        warna_bg = "#064E3B" if selesai else "#450A0A"
        warna_border = "#10B981" if selesai else "#EF4444"
        warna_teks = "#34D399" if selesai else "#F87171"
        ikon = ft.Icons.CHECK_CIRCLE_ROUNDED if selesai else ft.Icons.CANCEL_ROUNDED

        return ft.Container(
            expand=True,
            padding=ft.padding.symmetric(horizontal=10, vertical=8),
            bgcolor=warna_bg,
            border=ft.border.all(1, warna_border),
            border_radius=10,
            content=ft.Row(
                alignment=ft.MainAxisAlignment.START,
                spacing=6,
                controls=[
                    ft.Icon(ikon, color=warna_teks, size=16),
                    ft.Text(label, size=12, weight=ft.FontWeight.BOLD, color=warna_teks),
                ],
            ),
        )

    def buat_kartu_pertemuan(nama_matkul: str, nama_pert: str, st: dict):
        return ft.Container(
            margin=ft.margin.only(bottom=12),
            padding=16,
            bgcolor="#1E293B",
            border_radius=14,
            border=ft.border.all(1, "#334155"),
            content=ft.Column(
                spacing=10,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Container(
                                expand=True,
                                content=ft.Text(
                                    nama_matkul,
                                    size=14,
                                    weight=ft.FontWeight.BOLD,
                                    color="#F8FAFC",
                                ),
                            ),
                            ft.Container(
                                padding=ft.padding.symmetric(horizontal=8, vertical=4),
                                bgcolor="#3B82F6",
                                border_radius=6,
                                content=ft.Text(nama_pert, size=10, weight=ft.FontWeight.BOLD, color="white"),
                            ),
                        ],
                    ),
                    ft.Divider(height=1, color="#334155"),
                    ft.Row(
                        spacing=8,
                        controls=[
                            buat_chip_status("PRETEST", st["pretest"]),
                            buat_chip_status("FORUM", st["forum"]),
                        ],
                    ),
                    ft.Row(
                        spacing=8,
                        controls=[
                            buat_chip_status("POSTTEST", st["posttest"]),
                            buat_chip_status("KUISONER", st["kuesioner"]),
                        ],
                    ),
                ],
            ),
        )

    def buat_kartu_balasan(nama_matkul: str, nama_pert: str):
        return ft.Container(
            margin=ft.margin.only(bottom=12),
            padding=16,
            bgcolor="#064E3B",
            border_radius=14,
            border=ft.border.all(1, "#10B981"),
            content=ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    ft.Column(
                        expand=True,
                        spacing=4,
                        controls=[
                            ft.Text(nama_matkul, size=14, weight=ft.FontWeight.BOLD, color="white"),
                            ft.Text(nama_pert, size=12, color="#A7F3D0"),
                        ],
                    ),
                    ft.Container(
                        padding=ft.padding.symmetric(horizontal=10, vertical=6),
                        bgcolor="#10B981",
                        border_radius=8,
                        content=ft.Row(
                            spacing=4,
                            controls=[
                                ft.Icon(ft.Icons.MARK_CHAT_UNREAD_ROUNDED, size=14, color="#064E3B"),
                                ft.Text("DIBALAS DOSEN", size=11, weight=ft.FontWeight.BOLD, color="#064E3B"),
                            ],
                        ),
                    ),
                ],
            ),
        )

    # -----------------------------------------------------------------
    # HALAMAN DASHBOARD UTAMA
    # -----------------------------------------------------------------
    kolom_tugas = ft.Column(scroll=ft.ScrollMode.ADAPTIVE, expand=True, spacing=0)
    kolom_balasan = ft.Column(scroll=ft.ScrollMode.ADAPTIVE, expand=True, spacing=0)
    teks_status_scan = ft.Text("Siap memindai data Mentari...", size=12, color="#94A3B8")
    progress_bar = ft.ProgressBar(value=0, color="#3B82F6", bgcolor="#1E293B", visible=False)

    badge_jml_tugas = ft.Text("0", size=12, weight=ft.FontWeight.BOLD, color="#F87171")
    badge_jml_balasan = ft.Text("0", size=12, weight=ft.FontWeight.BOLD, color="#34D399")

    def jalankan_pemindaian(paksa_refresh_matkul: bool = False):
        def worker():
            progress_bar.visible = True
            progress_bar.value = None
            kolom_tugas.controls.clear()
            kolom_balasan.controls.clear()
            teks_status_scan.value = "Mengambil daftar mata kuliah..."
            page.update()

            daftar_matkul = client.ambil_semua_matkul_hemat(paksa_refresh=paksa_refresh_matkul)
            if not daftar_matkul:
                progress_bar.visible = False
                teks_status_scan.value = "Gagal mengambil mata kuliah! Cek Token / CF Clearance Anda."
                kolom_tugas.controls.append(
                    ft.Container(
                        padding=20,
                        bgcolor="#450A0A",
                        border_radius=12,
                        content=ft.Text(
                            "Gagal mengambil daftar mata kuliah! Sesi atau cf_clearance mungkin sudah habis. Silakan perbarui di menu Login/Sesi.",
                            color="#FCA5A5",
                        ),
                    )
                )
                page.update()
                return

            antrean_cek_forum = []
            jml_tugas = 0
            jml_balasan = 0
            total_mk = len(daftar_matkul)

            # TAHAP 1: CEK PERTEMUAN (<= 7 HARI) DENGAN PATOKAN KUISONER
            for idx, mk in enumerate(daftar_matkul, start=1):
                kode_course = mk.get("kode_course")
                nama_matkul = mk.get("nama_mata_kuliah")
                teks_status_scan.value = f"[{idx}/{total_mk}] Memeriksa {nama_matkul}..."
                progress_bar.value = idx / (total_mk + 1)
                page.update()

                course_json = client.get_json(f"{BASE_URL}/user-course/{kode_course}")
                if not course_json:
                    continue

                sections = course_json.get("data", [])
                for sec in sections:
                    kode_sec = sec.get("kode_section", "")
                    if not kode_sec.startswith("PERTEMUAN_"):
                        continue

                    nama_pert = sec.get("nama_section", kode_sec).upper()
                    sub_sections = sec.get("sub_section", [])
                    peta_sub = {sub.get("kode_template"): sub for sub in sub_sections if isinstance(sub, dict)}

                    forum = peta_sub.get("FORUM_DISKUSI")
                    forum_id = forum.get("id") if forum else None
                    waktu_forum = forum.get("createdAt") if forum_id else None

                    if forum_id and forum.get("completion") and masih_dalam_batas_hari(waktu_forum, BATAS_HARI):
                        antrean_cek_forum.append({
                            "nama_matkul": nama_matkul,
                            "nama_pert": nama_pert,
                            "forum_id": forum_id,
                        })

                    # Logika cek_komponen_pertemuan
                    if not forum_id:
                        continue
                    kuesioner = peta_sub.get("KUESIONER")
                    waktu_kuesioner = kuesioner.get("createdAt") if (kuesioner and kuesioner.get("id")) else None
                    masih_baru = (
                        (waktu_forum and masih_dalam_batas_hari(waktu_forum, BATAS_HARI))
                        or (waktu_kuesioner and masih_dalam_batas_hari(waktu_kuesioner, BATAS_HARI))
                    )
                    if not masih_baru:
                        continue

                    pretest = peta_sub.get("PRE_TEST")
                    posttest = peta_sub.get("POST_TEST")

                    st_pre = bool(pretest.get("completion")) if (pretest and pretest.get("id")) else False
                    st_for = bool(forum.get("completion"))
                    st_pos = bool(posttest.get("completion")) if (posttest and posttest.get("id")) else False
                    st_kue = bool(kuesioner.get("completion")) if (kuesioner and kuesioner.get("id")) else False

                    # PATOKAN UTAMA: Jika KUISONER selesai, sembunyikan!
                    if st_kue:
                        continue

                    jml_tugas += 1
                    badge_jml_tugas.value = str(jml_tugas)
                    kolom_tugas.controls.append(
                        buat_kartu_pertemuan(
                            nama_matkul,
                            nama_pert,
                            {"pretest": st_pre, "forum": st_for, "posttest": st_pos, "kuesioner": st_kue},
                        )
                    )
                    page.update()

            if jml_tugas == 0:
                kolom_tugas.controls.append(
                    ft.Container(
                        padding=30,
                        alignment=ft.alignment.center,
                        content=ft.Column(
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            controls=[
                                ft.Icon(ft.Icons.VERIFIED_ROUNDED, color="#10B981", size=48),
                                ft.Text("Semua kuesioner (<= 7 hari) sudah selesai!", color="#94A3B8"),
                            ],
                        ),
                    )
                )

            # TAHAP 2: CEK BALASAN DOSEN
            total_forum = len(antrean_cek_forum)
            for idx_f, item in enumerate(antrean_cek_forum, start=1):
                teks_status_scan.value = f"Mengecek balasan dosen ({idx_f}/{total_forum}): {item['nama_matkul']}..."
                page.update()

                if client.ada_balasan_dosen_belum_dibalas(item["forum_id"]):
                    jml_balasan += 1
                    badge_jml_balasan.value = str(jml_balasan)
                    kolom_balasan.controls.append(
                        buat_kartu_balasan(item["nama_matkul"], item["nama_pert"])
                    )
                    page.update()

            if jml_balasan == 0:
                kolom_balasan.controls.append(
                    ft.Container(
                        padding=30,
                        alignment=ft.alignment.center,
                        content=ft.Column(
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            controls=[
                                ft.Icon(ft.Icons.MARK_CHAT_READ_ROUNDED, color="#3B82F6", size=48),
                                ft.Text("Tidak ada balasan dosen yang belum dibalas.", color="#94A3B8"),
                            ],
                        ),
                    )
                )

            client.simpan_cache()
            progress_bar.visible = False
            waktu_selesai = datetime.now().strftime("%H:%M:%S")
            teks_status_scan.value = f"Pemindaian selesai pada {waktu_selesai} ({jml_tugas} Tugas, {jml_balasan} Balasan Dosen)"
            page.update()

        threading.Thread(target=worker, daemon=True).start()

    # -----------------------------------------------------------------
    # DIALOG / VIEW LOGIN & PENGATURAN SESI CLOUDFLARE
    # -----------------------------------------------------------------
    def tampilkan_halaman_login(e=None):
        input_nim = ft.TextField(
            label="NIM / Username",
            value=client.auth.get("username", ""),
            border_radius=10,
            prefix_icon=ft.Icons.PERSON_ROUNDED,
        )
        input_pass = ft.TextField(
            label="Password Mentari",
            password=True,
            can_reveal_password=True,
            border_radius=10,
            prefix_icon=ft.Icons.LOCK_ROUNDED,
        )
        input_captcha = ft.TextField(
            label="Token Turnstile (captcha)",
            hint_text="1.jEbbydjqlV8V48qeFe9a7lS_1UyVa6jS...",
            multiline=True,
            max_lines=3,
            border_radius=10,
            prefix_icon=ft.Icons.SHIELD_ROUNDED,
        )
        input_bearer = ft.TextField(
            label="Bearer Token (JWT)",
            value=client.auth.get("bearer_token", ""),
            multiline=True,
            max_lines=3,
            border_radius=10,
        )
        input_cf = ft.TextField(
            label="Cookie cf_clearance (Cloudflare)",
            value=client.auth.get("cf_clearance", ""),
            multiline=True,
            max_lines=2,
            border_radius=10,
        )
        input_sl = ft.TextField(
            label="Cookie sl-session",
            value=client.auth.get("sl_session", ""),
            border_radius=10,
        )

        def proses_login_langsung(ev):
            if not input_nim.value or not input_pass.value or not input_captcha.value:
                tampilkan_pesan("NIM, Password, dan Token Captcha wajib diisi!", "#EF4444")
                return
            ok, msg = client.login_api(
                username=input_nim.value,
                password=input_pass.value,
                captcha_token=input_captcha.value,
                cf_clearance=input_cf.value,
                sl_session=input_sl.value,
            )
            if ok:
                tampilkan_pesan(msg, "#10B981")
                buka_dashboard()
            else:
                tampilkan_pesan(msg, "#EF4444")

        def proses_simpan_token(ev):
            ok, msg = client.set_token_manual(
                bearer_token=input_bearer.value,
                cf_clearance=input_cf.value,
                sl_session=input_sl.value,
            )
            if ok:
                tampilkan_pesan(msg, "#10B981")
                buka_dashboard()
            else:
                tampilkan_pesan(msg, "#EF4444")

        tabs_login = ft.Tabs(
            selected_index=0,
            animation_duration=200,
            expand=True,
            tabs=[
                ft.Tab(
                    text="Login API (+Turnstile)",
                    icon=ft.Icons.LOGIN_ROUNDED,
                    content=ft.Container(
                        padding=16,
                        content=ft.Column(
                            scroll=ft.ScrollMode.ADAPTIVE,
                            spacing=12,
                            controls=[
                                ft.Text(
                                    "Login ke /api/login menggunakan NIM, Password, dan Token Captcha Cloudflare Turnstile.",
                                    size=12,
                                    color="#94A3B8",
                                ),
                                input_nim,
                                input_pass,
                                input_captcha,
                                input_cf,
                                ft.ElevatedButton(
                                    "Login ke Mentari",
                                    icon=ft.Icons.SEND_ROUNDED,
                                    bgcolor="#3B82F6",
                                    color="white",
                                    height=46,
                                    on_click=proses_login_langsung,
                                ),
                            ],
                        ),
                    ),
                ),
                ft.Tab(
                    text="Token & Cookie",
                    icon=ft.Icons.KEY_ROUNDED,
                    content=ft.Container(
                        padding=16,
                        content=ft.Column(
                            scroll=ft.ScrollMode.ADAPTIVE,
                            spacing=12,
                            controls=[
                                ft.Text(
                                    "Otomatis mengekstrak NIM & Nama dari Bearer Token JWT.",
                                    size=12,
                                    color="#94A3B8",
                                ),
                                input_bearer,
                                input_cf,
                                input_sl,
                                ft.ElevatedButton(
                                    "Simpan & Gunakan Sesi",
                                    icon=ft.Icons.SAVE_ROUNDED,
                                    bgcolor="#10B981",
                                    color="white",
                                    height=46,
                                    on_click=proses_simpan_token,
                                ),
                            ],
                        ),
                    ),
                ),
            ],
        )

        page.controls.clear()
        page.add(
            ft.Container(
                expand=True,
                padding=16,
                content=ft.Column(
                    expand=True,
                    controls=[
                        ft.Row(
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                            controls=[
                                ft.Text("Autentikasi Mentari", size=20, weight=ft.FontWeight.BOLD),
                                ft.IconButton(ft.Icons.CLOSE_ROUNDED, on_click=lambda _: buka_dashboard()),
                            ],
                        ),
                        tabs_login,
                    ],
                ),
            )
        )
        page.update()

    # -----------------------------------------------------------------
    # RENDER DASHBOARD
    # -----------------------------------------------------------------
    def buka_dashboard():
        page.controls.clear()

        header_profil = ft.Container(
            padding=ft.padding.symmetric(horizontal=20, vertical=18),
            gradient=ft.LinearGradient(
                begin=ft.alignment.top_left,
                end=ft.alignment.bottom_right,
                colors=["#1E3A8A", "#0F172A"],
            ),
            content=ft.Column(
                spacing=12,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Column(
                                spacing=2,
                                controls=[
                                    ft.Text(
                                        client.auth.get("fullname", "MAHASISWA"),
                                        size=16,
                                        weight=ft.FontWeight.BOLD,
                                        color="white",
                                    ),
                                    ft.Text(
                                        f"NIM: {client.auth.get('username', '-')} • Filter <= {BATAS_HARI} Hari",
                                        size=12,
                                        color="#93C5FD",
                                    ),
                                ],
                            ),
                            ft.Row(
                                spacing=4,
                                controls=[
                                    ft.IconButton(
                                        icon=ft.Icons.SYNC_ROUNDED,
                                        tooltip="Refresh Paksa Daftar Matkul",
                                        icon_color="white",
                                        on_click=lambda _: jalankan_pemindaian(paksa_refresh_matkul=True),
                                    ),
                                    ft.IconButton(
                                        icon=ft.Icons.MANAGE_ACCOUNTS_ROUNDED,
                                        tooltip="Pengaturan Login & Cloudflare",
                                        icon_color="white",
                                        on_click=tampilkan_halaman_login,
                                    ),
                                ],
                            ),
                        ],
                    ),
                    ft.Row(
                        spacing=10,
                        controls=[
                            ft.Container(
                                expand=True,
                                padding=10,
                                bgcolor="#1E293B",
                                border_radius=10,
                                content=ft.Row(
                                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                    controls=[
                                        ft.Text("Kuesioner Belum", size=12, color="#CBD5E1"),
                                        badge_jml_tugas,
                                    ],
                                ),
                            ),
                            ft.Container(
                                expand=True,
                                padding=10,
                                bgcolor="#1E293B",
                                border_radius=10,
                                content=ft.Row(
                                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                    controls=[
                                        ft.Text("Dibalas Dosen", size=12, color="#CBD5E1"),
                                        badge_jml_balasan,
                                    ],
                                ),
                            ),
                        ],
                    ),
                    teks_status_scan,
                    progress_bar,
                ],
            ),
        )

        tabs_utama = ft.Tabs(
            selected_index=0,
            animation_duration=250,
            expand=True,
            tabs=[
                ft.Tab(
                    text="Tugas & Kuesioner",
                    icon=ft.Icons.ASSIGNMENT_LATE_ROUNDED,
                    content=ft.Container(padding=16, content=kolom_tugas),
                ),
                ft.Tab(
                    text="Cek Balasan Dosen",
                    icon=ft.Icons.FORUM_ROUNDED,
                    content=ft.Container(padding=16, content=kolom_balasan),
                ),
            ],
        )

        tombol_scan = ft.FloatingActionButton(
            icon=ft.Icons.PLAY_ARROW_ROUNDED,
            text="Cek Sekarang",
            bgcolor="#3B82F6",
            on_click=lambda _: jalankan_pemindaian(paksa_refresh_matkul=False),
        )

        page.floating_action_button = tombol_scan
        page.add(
            ft.Column(
                expand=True,
                spacing=0,
                controls=[header_profil, tabs_utama],
            )
        )
        page.update()

    buka_dashboard()
    jalankan_pemindaian(paksa_refresh_matkul=False)


if __name__ == "__main__":
    ft.app(target=main)
