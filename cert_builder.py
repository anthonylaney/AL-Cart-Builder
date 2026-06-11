"""
SSL Cert Builder - Enterprise Windows Desktop Utility

A Tkinter GUI application for generating CSRs, importing, parsing,
and installing SSL certificates on Windows Server with IIS.

Usage:
    python cert_builder.py

Requires: pip install cryptography
Must run as Administrator for IIS certificate installation.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import threading
from typing import Optional

import cert_utils
import iis_manager


# ─── Retro 80s/90s Taco Bell Theme ───────────────────────────────────────────

# That classic pink, purple, teal, yellow on dark
BG_DARK = "#1a0a2e"          # Deep purple-black
BG_COLOR = "#2d1b4e"         # Dark purple (also used when no bg image)
BG_CARD = "#140820"          # Very dark card (lets bg show around edges)
SIDEBAR_BG = "#1a0a2e"       # Deep purple sidebar
FG_COLOR = "#f0e6ff"         # Light lavender text
FG_DIM = "#9b7ec8"           # Muted purple text
FG_DARK = "#5c3d8f"          # Dark purple text
ACCENT = "#ff0090"           # Hot pink (the iconic Taco Bell pink)
ACCENT_HOVER = "#ff33aa"     # Lighter hot pink
ACCENT_DIM = "#99005c"       # Dark pink
SUCCESS = "#00e5c6"          # Teal / cyan
SUCCESS_DIM = "#0a2e2a"      # Dark teal background
WARNING = "#ffd700"          # Golden yellow
WARNING_DIM = "#2e2a0a"      # Dark yellow background
ERROR = "#ff3366"            # Bright red-pink
ERROR_DIM = "#2e0a1a"        # Dark red background
BORDER = "#5c3d8f"           # Purple border
ENTRY_BG = "#120826"         # Very dark purple input
HIGHLIGHT = "#4a2080"        # Highlight purple

FONT_FAMILY = "Segoe UI"
FONT = (FONT_FAMILY, 10)
FONT_BOLD = (FONT_FAMILY, 10, "bold")
FONT_TITLE = (FONT_FAMILY, 16, "bold")
FONT_SUBTITLE = (FONT_FAMILY, 12, "bold")
FONT_SECTION = (FONT_FAMILY, 11, "bold")
FONT_SMALL = (FONT_FAMILY, 9)
FONT_TINY = (FONT_FAMILY, 8)
FONT_MONO = ("Consolas", 10)
FONT_MONO_SM = ("Consolas", 9)

# Sidebar nav items
NAV_ITEMS = [
    ("generate", "Generate CSR"),
    ("import", "Import Certificate"),
    ("details", "Certificate Details"),
    ("install", "Install to IIS"),
]


# ─── Background Image Support ────────────────────────────────────────────────

# Try to load Pillow for background image support
try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


class BackgroundFrame(tk.Frame):
    """A frame with an optional background image that scales to fill."""

    def __init__(self, parent, image_path=None, **kwargs):
        super().__init__(parent, **kwargs)
        self._image_path = image_path
        self._bg_label = None
        self._bg_photo = None
        self._original_image = None

        if image_path and HAS_PIL and os.path.isfile(image_path):
            try:
                self._original_image = Image.open(image_path)
                self._bg_label = tk.Label(self, bd=0, highlightthickness=0)
                self._bg_label.place(x=0, y=0, relwidth=1, relheight=1)
                self.bind("<Configure>", self._on_resize)
            except Exception:
                self._original_image = None

    def _on_resize(self, event=None):
        if not self._original_image:
            return
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 10 or h < 10:
            return
        resized = self._original_image.resize((w, h), Image.LANCZOS)
        self._bg_photo = ImageTk.PhotoImage(resized)
        self._bg_label.config(image=self._bg_photo)


def _find_background_image():
    """Look for a background image in the app directory or current working directory."""
    search_dirs = [
        os.path.dirname(os.path.abspath(__file__)),
        os.getcwd(),
        os.path.abspath("."),
    ]
    names = ("background.png", "background.jpg", "background.jpeg",
             "bg.png", "bg.jpg")
    for search_dir in search_dirs:
        for name in names:
            path = os.path.join(search_dir, name)
            if os.path.isfile(path):
                return path
    return None


# ─── Utility Widgets ─────────────────────────────────────────────────────────

class FlatButton(tk.Button):
    """A flat button with hover effects."""

    def __init__(self, parent, text, command, bg=ACCENT, fg=BG_DARK,
                 hover_bg=ACCENT_HOVER, font=FONT_BOLD, **kwargs):
        super().__init__(parent, text=text, command=command, bg=bg, fg=fg,
                         font=font, relief="flat", cursor="hand2",
                         activebackground=hover_bg, activeforeground=fg,
                         bd=0, padx=14, pady=6, **kwargs)
        self._bg = bg
        self._hover_bg = hover_bg
        self.bind("<Enter>", lambda e: self.config(bg=self._hover_bg))
        self.bind("<Leave>", lambda e: self.config(bg=self._bg))

    def set_state(self, state):
        if state == "disabled":
            self.config(state="disabled", bg=FG_DARK)
        else:
            self.config(state="normal", bg=self._bg)

    def set_text(self, text):
        self.config(text=text)


class StatusBar(tk.Frame):
    """Enterprise status bar with icon indicators."""

    def __init__(self, parent):
        super().__init__(parent, bg=SIDEBAR_BG, height=32)
        self.pack_propagate(False)

        self.dot = tk.Label(self, text="\u25cf", bg=SIDEBAR_BG, fg=FG_DIM,
                            font=(FONT_FAMILY, 8), padx=8)
        self.dot.pack(side="left")

        self.label = tk.Label(
            self, text="Ready", bg=SIDEBAR_BG, fg=FG_DIM,
            font=FONT_SMALL, anchor="w",
        )
        self.label.pack(side="left", fill="x", expand=True)

        self.version = tk.Label(
            self, text="SSL Cert Builder v1.0 // RADICAL EDITION", bg=SIDEBAR_BG, fg=FG_DARK,
            font=FONT_TINY, padx=12,
        )
        self.version.pack(side="right")

    def set(self, message: str, level: str = "info"):
        colors = {
            "info": FG_DIM,
            "success": SUCCESS,
            "warning": WARNING,
            "error": ERROR,
        }
        dot_colors = {
            "info": ACCENT,
            "success": SUCCESS,
            "warning": WARNING,
            "error": ERROR,
        }
        self.label.config(text=message, fg=colors.get(level, FG_DIM))
        self.dot.config(fg=dot_colors.get(level, FG_DIM))


class NavButton(tk.Frame):
    """Sidebar navigation button."""

    def __init__(self, parent, text, key, command, active=False):
        super().__init__(parent, bg=SIDEBAR_BG, cursor="hand2")
        self.key = key
        self.command = command
        self._active = active

        self.indicator = tk.Frame(self, bg=ACCENT if active else SIDEBAR_BG, width=3)
        self.indicator.pack(side="left", fill="y")

        self.label = tk.Label(
            self, text=text, bg=SIDEBAR_BG,
            fg=ACCENT if active else FG_DIM,
            font=FONT_BOLD if active else FONT,
            anchor="w", padx=16, pady=12,
        )
        self.label.pack(side="left", fill="x", expand=True)

        for widget in [self, self.label]:
            widget.bind("<Enter>", self._on_enter)
            widget.bind("<Leave>", self._on_leave)
            widget.bind("<Button-1>", self._on_click)

    def _on_enter(self, e):
        if not self._active:
            self.label.config(fg=FG_COLOR)
            self.config(bg=HIGHLIGHT)
            self.label.config(bg=HIGHLIGHT)

    def _on_leave(self, e):
        if not self._active:
            self.label.config(fg=FG_DIM)
            self.config(bg=SIDEBAR_BG)
            self.label.config(bg=SIDEBAR_BG)

    def _on_click(self, e):
        if self.command:
            self.command(self.key)

    def set_active(self, active: bool):
        self._active = active
        self.indicator.config(bg=ACCENT if active else SIDEBAR_BG)
        self.label.config(
            fg=ACCENT if active else FG_DIM,
            font=FONT_BOLD if active else FONT,
            bg=SIDEBAR_BG,
        )
        self.config(bg=SIDEBAR_BG)


# ─── Page: Generate CSR ──────────────────────────────────────────────────────

class GenerateCSRPage(tk.Frame):
    """Page for generating CSR and private key."""

    def __init__(self, parent, app):
        super().__init__(parent, bg=BG_COLOR)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        # Banner image
        self.app.create_banner(self, height=120)

        # Header
        header = tk.Frame(self, bg=BG_COLOR)
        header.pack(fill="x", padx=30, pady=(15, 5))
        tk.Label(header, text="Generate CSR", bg=BG_COLOR, fg=FG_COLOR,
                 font=FONT_TITLE, anchor="w").pack(fill="x")
        tk.Label(header, text="Create a private key and Certificate Signing Request to submit to your SSL provider.",
                 bg=BG_COLOR, fg=FG_DIM, font=FONT_SMALL, anchor="w").pack(fill="x", pady=(4, 0))

        # Divider
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=30, pady=(10, 15))

        # Form card
        card = tk.Frame(self, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", padx=30)

        tk.Label(card, text="Certificate Information", bg=BG_CARD, fg=FG_COLOR,
                 font=FONT_SECTION, anchor="w").pack(fill="x", padx=20, pady=(16, 10))

        fields = [
            ("Common Name *", "cn", "*.example.com"),
            ("Subject Alt Names", "sans", "example.com, www.example.com"),
            ("Organization", "org", ""),
            ("Country (2-letter)", "country", "US"),
            ("State / Province", "state", ""),
            ("City / Locality", "city", ""),
        ]

        self.vars = {}
        for label_text, key, placeholder in fields:
            row = tk.Frame(card, bg=BG_CARD)
            row.pack(fill="x", padx=20, pady=3)
            tk.Label(row, text=label_text, bg=BG_CARD, fg=FG_DIM,
                     font=FONT_SMALL, width=18, anchor="e").pack(side="left")
            var = tk.StringVar()
            entry = tk.Entry(
                row, textvariable=var, bg=ENTRY_BG, fg=FG_COLOR,
                font=FONT, width=40, insertbackground=FG_COLOR,
                relief="flat", highlightbackground=BORDER, highlightthickness=1,
            )
            entry.pack(side="left", padx=(10, 0), ipady=4)
            if placeholder:
                entry.insert(0, placeholder)
                entry.config(fg=FG_DIM)
                def _focus_in(e, ent=entry, ph=placeholder):
                    if ent.get() == ph:
                        ent.delete(0, "end")
                        ent.config(fg=FG_COLOR)
                def _focus_out(e, ent=entry, ph=placeholder):
                    if not ent.get():
                        ent.insert(0, ph)
                        ent.config(fg=FG_DIM)
                entry.bind("<FocusIn>", _focus_in)
                entry.bind("<FocusOut>", _focus_out)
            self.vars[key] = (var, entry, placeholder)

        # Key size row
        ks_row = tk.Frame(card, bg=BG_CARD)
        ks_row.pack(fill="x", padx=20, pady=(3, 16))
        tk.Label(ks_row, text="Key Size", bg=BG_CARD, fg=FG_DIM,
                 font=FONT_SMALL, width=18, anchor="e").pack(side="left")
        self.key_size_var = tk.StringVar(value="2048")
        ks_combo = ttk.Combobox(ks_row, textvariable=self.key_size_var,
                                values=["2048", "4096"], state="readonly",
                                font=FONT, width=8)
        ks_combo.pack(side="left", padx=(10, 0))

        # Output directory card
        dir_card = tk.Frame(self, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        dir_card.pack(fill="x", padx=30, pady=(12, 0))

        dir_inner = tk.Frame(dir_card, bg=BG_CARD)
        dir_inner.pack(fill="x", padx=20, pady=14)
        tk.Label(dir_inner, text="Save Location", bg=BG_CARD, fg=FG_DIM,
                 font=FONT_SMALL, width=18, anchor="e").pack(side="left")
        self.dir_var = tk.StringVar(value=os.path.expanduser("~"))
        tk.Entry(dir_inner, textvariable=self.dir_var, bg=ENTRY_BG, fg=FG_COLOR,
                 font=FONT, insertbackground=FG_COLOR, relief="flat",
                 highlightbackground=BORDER, highlightthickness=1,
                 ).pack(side="left", fill="x", expand=True, padx=(10, 8), ipady=4)
        tk.Button(dir_inner, text="Browse", bg=ACCENT_DIM, fg=FG_COLOR,
                  font=FONT_SMALL, relief="flat", cursor="hand2", padx=12,
                  command=self._browse_dir).pack(side="left")

        # Action row
        action = tk.Frame(self, bg=BG_COLOR)
        action.pack(fill="x", padx=30, pady=16)
        self.gen_btn = FlatButton(action, "Generate CSR", self._generate,
                                     bg=ACCENT)
        self.gen_btn.pack(side="left")

        # CSR output
        self.output_card = tk.Frame(self, bg=BG_CARD, highlightbackground=BORDER,
                                    highlightthickness=1)
        self.output_card.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        out_header = tk.Frame(self.output_card, bg=BG_CARD)
        out_header.pack(fill="x", padx=16, pady=(12, 0))
        tk.Label(out_header, text="CSR Output", bg=BG_CARD, fg=FG_COLOR,
                 font=FONT_SECTION, anchor="w").pack(side="left")
        self.copy_btn = tk.Button(out_header, text="Copy to Clipboard",
                                  bg=ACCENT_DIM, fg=FG_COLOR, font=FONT_SMALL,
                                  relief="flat", cursor="hand2", padx=10,
                                  command=self._copy_csr, state="disabled")
        self.copy_btn.pack(side="right")

        self.csr_text = tk.Text(
            self.output_card, bg=ENTRY_BG, fg=SUCCESS, font=FONT_MONO_SM,
            wrap="none", height=6, bd=0, padx=12, pady=8,
            insertbackground=FG_COLOR, relief="flat",
        )
        self.csr_text.pack(fill="both", expand=True, padx=16, pady=(8, 16))
        self.csr_text.insert("1.0", "CSR will appear here after generation...")
        self.csr_text.config(fg=FG_DARK)

    def _browse_dir(self):
        d = filedialog.askdirectory(title="Select output directory")
        if d:
            self.dir_var.set(d)

    def _get_field(self, key):
        var, entry, placeholder = self.vars[key]
        if entry.cget("fg") == FG_DIM:
            return ""
        return var.get().strip() if var.get() != placeholder else ""

    def _generate(self):
        cn = self._get_field("cn")
        if not cn:
            messagebox.showwarning("Required", "Common Name is required.")
            return

        output_dir = self.dir_var.get()
        if not output_dir or not os.path.isdir(output_dir):
            messagebox.showwarning("Required", "Please select a valid output directory.")
            return

        sans_str = self._get_field("sans")
        sans = [s.strip() for s in sans_str.split(",") if s.strip()] if sans_str else []

        self.gen_btn.set_text("Generating...")
        self.gen_btn.set_state("disabled")
        self.app.status.set("Generating private key and CSR...", "info")

        def generate():
            try:
                key_pem, csr_pem = cert_utils.generate_csr(
                    common_name=cn, sans=sans,
                    organization=self._get_field("org"),
                    country=self._get_field("country"),
                    state=self._get_field("state"),
                    city=self._get_field("city"),
                    key_size=int(self.key_size_var.get()),
                )
                key_path, csr_path = cert_utils.save_key_and_csr(
                    output_dir, cn, key_pem, csr_pem,
                )
                self.after(0, lambda: self._on_generated(key_path, csr_path, csr_pem))
            except Exception as e:
                err_msg = str(e)
                self.after(0, lambda: self._on_error(err_msg))

        threading.Thread(target=generate, daemon=True).start()

    def _on_generated(self, key_path, csr_path, csr_pem):
        self.app._last_key_path = key_path
        self.csr_text.config(fg=SUCCESS)
        self.csr_text.delete("1.0", "end")
        self.csr_text.insert("1.0", csr_pem.decode("utf-8"))
        self.copy_btn.config(state="normal")
        self.gen_btn.set_text("Generated!")

        self.app.status.set(f"CSR generated. Key saved: {os.path.basename(key_path)}", "success")
        messagebox.showinfo(
            "CSR Generated",
            f"Files saved:\n\n"
            f"  Private Key:  {key_path}\n"
            f"  CSR:  {csr_path}\n\n"
            f"Next steps:\n"
            f"1. Copy the CSR and submit it to your SSL provider\n"
            f"2. Go to 'Import Certificate' when you receive the cert files\n"
            f"3. The app will auto-pair with the saved private key",
        )

    def _on_error(self, msg):
        self.gen_btn.set_text("Generate CSR")
        self.gen_btn.set_state("normal")
        self.app.status.set(f"Error: {msg}", "error")
        messagebox.showerror("Generation Error", msg)

    def _copy_csr(self):
        csr = self.csr_text.get("1.0", "end").strip()
        if csr and not csr.startswith("CSR will"):
            self.clipboard_clear()
            self.clipboard_append(csr)
            self.copy_btn.config(text="Copied!")
            self.after(2000, lambda: self.copy_btn.config(text="Copy to Clipboard"))


# ─── Page: Import Certificate ────────────────────────────────────────────────

class ImportPage(tk.Frame):
    """Page for importing certificate files."""

    def __init__(self, parent, app):
        super().__init__(parent, bg=BG_COLOR)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        # Banner
        self.app.create_banner(self, height=120)

        # Header
        header = tk.Frame(self, bg=BG_COLOR)
        header.pack(fill="x", padx=30, pady=(15, 5))
        tk.Label(header, text="Import Certificate", bg=BG_COLOR, fg=FG_COLOR,
                 font=FONT_TITLE, anchor="w").pack(fill="x")
        tk.Label(header, text="Load certificate files from your SSL provider or existing PFX archives.",
                 bg=BG_COLOR, fg=FG_DIM, font=FONT_SMALL, anchor="w").pack(fill="x", pady=(4, 0))

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=30, pady=(15, 20))

        # Import option cards
        options = [
            ("Import from Folder", "Select a folder containing your cert files (.crt, .key, .ca-bundle, .txt).\nAuto-detects and loads all certificate components.", self._import_folder),
            ("Import Separate Files", "Select .crt, .key, and .ca-bundle individually.\nBest when files are in different locations.", self._import_separate),
            ("Import PFX / P12", "Load a PKCS#12 archive containing the certificate, key, and chain.\nCommon when migrating from another server.", self._import_pfx),
            ("Import PEM Bundle", "Load a single PEM file containing certificates and optionally a private key.", self._import_pem_bundle),
        ]

        for title, desc, cmd in options:
            card = tk.Frame(self, bg=BG_CARD, highlightbackground=BORDER,
                            highlightthickness=1, cursor="hand2")
            card.pack(fill="x", padx=30, pady=(0, 8))

            inner = tk.Frame(card, bg=BG_CARD)
            inner.pack(fill="x", padx=20, pady=16)

            tk.Label(inner, text=title, bg=BG_CARD, fg=ACCENT,
                     font=FONT_SECTION, anchor="w").pack(fill="x")
            tk.Label(inner, text=desc, bg=BG_CARD, fg=FG_DIM,
                     font=FONT_SMALL, anchor="w", justify="left").pack(fill="x", pady=(4, 0))

            btn = FlatButton(inner, "Select Files", cmd, bg=ACCENT_DIM,
                                fg=FG_COLOR, hover_bg=ACCENT, font=FONT)
            btn.pack(anchor="e", pady=(8, 0))

        # Key status indicator
        self.key_card = tk.Frame(self, bg=SUCCESS_DIM, highlightbackground=BORDER,
                                 highlightthickness=1)

        key_inner = tk.Frame(self.key_card, bg=SUCCESS_DIM)
        key_inner.pack(fill="x", padx=20, pady=12)
        self.key_label = tk.Label(key_inner, text="", bg=SUCCESS_DIM, fg=SUCCESS,
                                  font=FONT_SMALL, anchor="w")
        self.key_label.pack(fill="x")

    def show(self):
        """Called when page becomes visible."""
        if self.app._last_key_path and os.path.exists(self.app._last_key_path):
            self.key_card.pack(fill="x", padx=30, pady=(8, 0))
            self.key_label.config(
                text=f"Private key available: {os.path.basename(self.app._last_key_path)}  "
                     f"(will be auto-loaded during import)"
            )
        else:
            self.key_card.pack_forget()

    def _import_folder(self):
        """Auto-detect and load all cert files from a selected folder."""
        folder = filedialog.askdirectory(title="Select folder containing certificate files")
        if not folder:
            return

        self.app.status.set(f"Scanning folder: {folder}", "info")

        # Scan for cert-related files by extension
        cert_files = []  # .crt, .cer, .pem (non-key)
        key_files = []   # .key
        ca_bundles = []  # .ca-bundle
        txt_files = []   # .txt (may contain key)
        rtf_files = []   # .rtf (may contain cert)

        try:
            for filename in os.listdir(folder):
                filepath = os.path.join(folder, filename)
                if not os.path.isfile(filepath):
                    continue
                lower = filename.lower()
                if lower.endswith(".ca-bundle"):
                    ca_bundles.append(filepath)
                elif lower.endswith(".key"):
                    key_files.append(filepath)
                elif lower.endswith((".crt", ".cer")):
                    cert_files.append(filepath)
                elif lower.endswith(".pem"):
                    # Check if it's a key or cert by peeking at contents
                    data = cert_utils.load_cert_file(filepath)
                    if b"PRIVATE KEY" in data:
                        key_files.append(filepath)
                    else:
                        cert_files.append(filepath)
                elif lower.endswith(".txt"):
                    # Check if it contains a private key
                    data = cert_utils.load_cert_file(filepath)
                    if b"PRIVATE KEY" in data:
                        key_files.append(filepath)
                elif lower.endswith(".rtf"):
                    rtf_files.append(filepath)
        except Exception as e:
            self.app.status.set(f"Error scanning folder: {e}", "error")
            messagebox.showerror("Scan Error", str(e))
            return

        if not cert_files and not ca_bundles and not rtf_files:
            self.app.status.set("No certificate files found in folder", "error")
            messagebox.showwarning("No Files Found",
                f"No certificate files (.crt, .cer, .pem, .ca-bundle) found in:\n{folder}")
            return

        # Build a summary of what was found
        found = []
        if cert_files:
            found.append(f"Certs: {', '.join(os.path.basename(f) for f in cert_files)}")
        if key_files:
            found.append(f"Keys: {', '.join(os.path.basename(f) for f in key_files)}")
        if ca_bundles:
            found.append(f"CA: {', '.join(os.path.basename(f) for f in ca_bundles)}")
        if rtf_files:
            found.append(f"RTF: {', '.join(os.path.basename(f) for f in rtf_files)}")

        self.app.status.set(f"Found: {'; '.join(found)}", "info")

        # Combine all PEM data
        try:
            all_cert_data = b""
            for f in cert_files:
                all_cert_data += cert_utils.load_cert_file(f) + b"\n"
            for f in ca_bundles:
                all_cert_data += cert_utils.load_cert_file(f) + b"\n"
            for f in rtf_files:
                all_cert_data += cert_utils.load_cert_file(f) + b"\n"

            key_data = b""
            for f in key_files:
                key_data += cert_utils.load_cert_file(f) + b"\n"

            # Also check for a previously generated key
            if not key_data and self.app._last_key_path and os.path.exists(self.app._last_key_path):
                key_data = cert_utils.load_cert_file(self.app._last_key_path)

            bundle = cert_utils.parse_pem_bundle(all_cert_data, key_data)
            self.app.set_bundle(bundle)

        except Exception as e:
            self.app.status.set(f"Error: {e}", "error")
            messagebox.showerror("Import Error", str(e))

    def _import_pfx(self):
        path = filedialog.askopenfilename(
            title="Select PFX/P12 File",
            filetypes=[("PFX Files", "*.pfx"), ("P12 Files", "*.p12"), ("All Files", "*.*")],
        )
        if not path:
            return

        password = simpledialog.askstring("PFX Password",
            "Enter PFX password (leave blank for none):", show="*")

        self.app.status.set("Parsing PFX file...", "info")
        try:
            data = cert_utils.load_cert_file(path)
            bundle = cert_utils.parse_pfx(data, password or None)
            self.app.set_bundle(bundle)
        except Exception as e:
            self.app.status.set(f"Error: {e}", "error")
            messagebox.showerror("Import Error", str(e))

    def _import_pem_bundle(self):
        path = filedialog.askopenfilename(
            title="Select PEM/CRT Bundle",
            filetypes=[("PEM Files", "*.pem"), ("CRT Files", "*.crt"),
                       ("CER Files", "*.cer"), ("All Files", "*.*")],
        )
        if not path:
            return

        self.app.status.set("Parsing PEM bundle...", "info")
        try:
            data = cert_utils.load_cert_file(path)
            bundle = cert_utils.parse_pem_bundle(data)

            if not bundle.has_private_key:
                if self.app._last_key_path and os.path.exists(self.app._last_key_path):
                    key_data = cert_utils.load_cert_file(self.app._last_key_path)
                    bundle = cert_utils.parse_pem_bundle(data, key_data)
                else:
                    load_key = messagebox.askyesno("Private Key",
                        "No private key found. Load a separate key file?")
                    if load_key:
                        key_path = filedialog.askopenfilename(
                            title="Select Private Key File",
                            filetypes=[("Key / Text Files", "*.key *.pem *.txt"),
                                       ("All Files", "*.*")])
                        if key_path:
                            key_data = cert_utils.load_cert_file(key_path)
                            bundle = cert_utils.parse_pem_bundle(data, key_data)

            self.app.set_bundle(bundle)
        except Exception as e:
            self.app.status.set(f"Error: {e}", "error")
            messagebox.showerror("Import Error", str(e))

    def _import_separate(self):
        # Step 1: Server certificate
        cert_path = filedialog.askopenfilename(
            title="Step 1 of 3: Select Server Certificate (.crt file)",
            filetypes=[("Certificate Files", "*.crt *.pem *.cer *.rtf"), ("All Files", "*.*")],
        )
        if not cert_path:
            return

        # Step 2: Private key (auto-load if available)
        key_path = None
        if self.app._last_key_path and os.path.exists(self.app._last_key_path):
            use_saved = messagebox.askyesno("Use Generated Key?",
                f"Use the previously generated private key?\n\n{self.app._last_key_path}")
            if use_saved:
                key_path = self.app._last_key_path

        if not key_path:
            key_path = filedialog.askopenfilename(
                title="Step 2 of 3: Select Private Key (.key or .txt file)",
                filetypes=[("Key / Text Files", "*.key *.pem *.txt"), ("All Files", "*.*")],
            )

        # Step 3: CA bundle
        ca_path = filedialog.askopenfilename(
            title="Step 3 of 3: Select CA Bundle (.ca-bundle) - Cancel to skip",
            filetypes=[("CA Bundle", "*.ca-bundle *.crt *.pem"), ("All Files", "*.*")],
        )

        loaded = [f"Cert: {os.path.basename(cert_path)}"]
        loaded.append(f"Key: {os.path.basename(key_path)}" if key_path else "Key: (none)")
        loaded.append(f"CA: {os.path.basename(ca_path)}" if ca_path else "CA: (none)")
        self.app.status.set(f"Loading: {', '.join(loaded)}", "info")

        try:
            cert_data = cert_utils.load_cert_file(cert_path)
            key_data = cert_utils.load_cert_file(key_path) if key_path else b""
            ca_data = cert_utils.load_cert_file(ca_path) if ca_path else b""

            combined_pem = cert_data + b"\n" + ca_data
            bundle = cert_utils.parse_pem_bundle(combined_pem, key_data)
            self.app.set_bundle(bundle)
        except Exception as e:
            self.app.status.set(f"Error: {e}", "error")
            messagebox.showerror("Import Error", str(e))


# ─── Page: Certificate Details ───────────────────────────────────────────────

class DetailsPage(tk.Frame):
    """Page showing parsed certificate details."""

    def __init__(self, parent, app):
        super().__init__(parent, bg=BG_COLOR)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        # Banner
        self.app.create_banner(self, height=120)

        # Header
        header = tk.Frame(self, bg=BG_COLOR)
        header.pack(fill="x", padx=30, pady=(15, 5))
        tk.Label(header, text="Certificate Details", bg=BG_COLOR, fg=FG_COLOR,
                 font=FONT_TITLE, anchor="w").pack(side="left")

        self.export_btn = FlatButton(header, "Export Components", self._export,
                                        bg=ACCENT_DIM, fg=FG_COLOR, hover_bg=ACCENT,
                                        font=FONT)
        self.export_btn.pack(side="right")

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=30, pady=(15, 20))

        # Certificate details text
        card = tk.Frame(self, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        self.text = tk.Text(
            card, bg=BG_CARD, fg=FG_COLOR, font=FONT_MONO,
            wrap="word", bd=0, padx=20, pady=16,
            insertbackground=FG_COLOR, selectbackground=ACCENT_DIM,
            relief="flat",
        )
        scrollbar = ttk.Scrollbar(card, command=self.text.yview)
        self.text.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y", padx=(0, 2), pady=2)
        self.text.pack(fill="both", expand=True, padx=(2, 0), pady=2)

        # Tag styles
        self.text.tag_config("header", foreground=ACCENT, font=(FONT_FAMILY, 11, "bold"))
        self.text.tag_config("label", foreground=WARNING)
        self.text.tag_config("value", foreground=FG_COLOR)
        self.text.tag_config("good", foreground=SUCCESS)
        self.text.tag_config("bad", foreground=ERROR)
        self.text.tag_config("warn_text", foreground=WARNING)
        self.text.tag_config("separator", foreground=FG_DARK)
        self.text.config(state="disabled")

        # Empty state
        self._show_empty()

    def _show_empty(self):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("end", "\n  No certificate loaded.\n\n", "separator")
        self.text.insert("end", "  Go to 'Import Certificate' to load certificate files,\n", "separator")
        self.text.insert("end", "  or 'Generate CSR' to create a new key pair.\n", "separator")
        self.text.config(state="disabled")

    def display_bundle(self, bundle: cert_utils.ParsedCertBundle):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")

        if bundle.errors:
            for err in bundle.errors:
                self._a(f"  ERROR: {err}\n", "bad")
            self._a("\n")

        if bundle.server_cert:
            self._display_cert("SERVER CERTIFICATE", bundle.server_cert)
            if bundle.server_cert.is_expired:
                self._a("  ** CERTIFICATE IS EXPIRED **\n", "bad")
            elif bundle.server_cert.days_until_expiry <= 30:
                self._a(f"  ** Expires in {bundle.server_cert.days_until_expiry} days **\n", "bad")
            elif bundle.server_cert.days_until_expiry <= 90:
                self._a(f"  ** Expires in {bundle.server_cert.days_until_expiry} days **\n", "warn_text")

        for i, cert in enumerate(bundle.intermediates):
            self._a("\n" + "  " + "\u2500" * 56 + "\n", "separator")
            self._display_cert(f"INTERMEDIATE CA #{i + 1}", cert)

        if bundle.root_ca:
            self._a("\n" + "  " + "\u2500" * 56 + "\n", "separator")
            self._display_cert("ROOT CA", bundle.root_ca)

        self._a("\n" + "  " + "\u2500" * 56 + "\n", "separator")
        key_status = "Present" if bundle.has_private_key else "Not loaded"
        key_tag = "good" if bundle.has_private_key else "bad"
        self._a("  Private Key:   ", "label")
        self._a(f"{key_status}\n", key_tag)

        chain_len = len(bundle.intermediates) + (1 if bundle.root_ca else 0)
        self._a("  Chain Length:  ", "label")
        self._a(f"{chain_len} certificate(s)\n", "value")

        self.text.config(state="disabled")

    def _a(self, text, tag="value"):
        self.text.insert("end", text, tag)

    def _display_cert(self, title, cert):
        self._a(f"\n  {title}\n", "header")
        self._a("  " + "\u2500" * 40 + "\n", "separator")

        fields = [
            ("Common Name", cert.common_name or "(none)"),
            ("Subject", cert.subject),
            ("Issuer", cert.issuer),
            ("Serial", cert.serial_number),
            ("Thumbprint", cert.thumbprint),
            ("Valid", cert.validity_display),
        ]
        if cert.sans:
            fields.append(("SANs", ", ".join(cert.sans)))

        for label, value in fields:
            self._a(f"  {label + ':':<15} ", "label")
            self._a(f"{value}\n", "value")

    def _export(self):
        if not self.app.bundle:
            messagebox.showinfo("No Certificate", "Import a certificate first.")
            return

        output_dir = filedialog.askdirectory(title="Select Export Directory")
        if not output_dir:
            return

        self.app.status.set("Exporting components...", "info")
        try:
            exported = cert_utils.export_components(self.app.bundle, output_dir)
            file_list = "\n".join(f"  - {os.path.basename(p)}" for p in exported.values())
            self.app.status.set(f"Exported {len(exported)} files to {output_dir}", "success")
            messagebox.showinfo("Export Complete",
                f"Exported {len(exported)} file(s) to:\n{output_dir}\n\n{file_list}")
        except Exception as e:
            self.app.status.set(f"Export error: {e}", "error")
            messagebox.showerror("Export Error", str(e))


# ─── Page: Install to IIS ───────────────────────────────────────────────────

class InstallPage(tk.Frame):
    """Page for installing certificate to IIS."""

    def __init__(self, parent, app):
        super().__init__(parent, bg=BG_COLOR)
        self.app = app
        self._sites = []
        self._build_ui()

    def _build_ui(self):
        # Banner
        self.app.create_banner(self, height=120)

        # Header
        header = tk.Frame(self, bg=BG_COLOR)
        header.pack(fill="x", padx=30, pady=(15, 5))
        tk.Label(header, text="Install to IIS", bg=BG_COLOR, fg=FG_COLOR,
                 font=FONT_TITLE, anchor="w").pack(fill="x")
        tk.Label(header, text="Import the certificate into the Windows certificate store and bind it to an IIS site.",
                 bg=BG_COLOR, fg=FG_DIM, font=FONT_SMALL, anchor="w").pack(fill="x", pady=(4, 0))

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=30, pady=(10, 15))

        # Prerequisites card
        prereq_card = tk.Frame(self, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        prereq_card.pack(fill="x", padx=30)
        tk.Label(prereq_card, text="Prerequisites", bg=BG_CARD, fg=FG_COLOR,
                 font=FONT_SECTION, anchor="w").pack(fill="x", padx=20, pady=(14, 6))

        self.cert_status = tk.Label(prereq_card, text="  Certificate: Not loaded", bg=BG_CARD,
                                    fg=ERROR, font=FONT_SMALL, anchor="w")
        self.cert_status.pack(fill="x", padx=20)
        self.key_status = tk.Label(prereq_card, text="  Private Key: Not loaded", bg=BG_CARD,
                                   fg=ERROR, font=FONT_SMALL, anchor="w")
        self.key_status.pack(fill="x", padx=20)
        self.admin_status = tk.Label(prereq_card, text="  Administrator: Checking...", bg=BG_CARD,
                                     fg=FG_DIM, font=FONT_SMALL, anchor="w")
        self.admin_status.pack(fill="x", padx=20)
        self.iis_status = tk.Label(prereq_card, text="  IIS Module: Checking...", bg=BG_CARD,
                                   fg=FG_DIM, font=FONT_SMALL, anchor="w")
        self.iis_status.pack(fill="x", padx=20, pady=(0, 14))

        # Binding options card
        bind_card = tk.Frame(self, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        bind_card.pack(fill="x", padx=30, pady=(12, 0))
        tk.Label(bind_card, text="Binding Configuration", bg=BG_CARD, fg=FG_COLOR,
                 font=FONT_SECTION, anchor="w").pack(fill="x", padx=20, pady=(14, 10))

        # IIS Site
        row0 = tk.Frame(bind_card, bg=BG_CARD)
        row0.pack(fill="x", padx=20, pady=3)
        tk.Label(row0, text="IIS Site", bg=BG_CARD, fg=FG_DIM,
                 font=FONT_SMALL, width=14, anchor="e").pack(side="left")
        self.site_var = tk.StringVar()
        self.site_combo = ttk.Combobox(row0, textvariable=self.site_var,
                                       state="disabled", font=FONT, width=35)
        self.site_combo.pack(side="left", padx=(10, 0))

        fields_data = [
            ("IP Address", "ip", "*"),
            ("Port", "port", "443"),
            ("Hostname (SNI)", "host", ""),
        ]

        self.bind_vars = {}
        for label, key, default in fields_data:
            row = tk.Frame(bind_card, bg=BG_CARD)
            row.pack(fill="x", padx=20, pady=3)
            tk.Label(row, text=label, bg=BG_CARD, fg=FG_DIM,
                     font=FONT_SMALL, width=14, anchor="e").pack(side="left")
            var = tk.StringVar(value=default)
            tk.Entry(row, textvariable=var, bg=ENTRY_BG, fg=FG_COLOR,
                     font=FONT, width=25, insertbackground=FG_COLOR,
                     relief="flat", highlightbackground=BORDER,
                     highlightthickness=1).pack(side="left", padx=(10, 0), ipady=3)
            self.bind_vars[key] = var

        # Restart checkbox
        self.restart_var = tk.BooleanVar(value=False)
        tk.Checkbutton(bind_card, text="Restart site after binding",
                       variable=self.restart_var, bg=BG_CARD, fg=FG_COLOR,
                       selectcolor=ENTRY_BG, activebackground=BG_CARD,
                       activeforeground=FG_COLOR, font=FONT_SMALL
                       ).pack(padx=30, pady=(6, 14), anchor="w")

        # Install button
        action = tk.Frame(self, bg=BG_COLOR)
        action.pack(fill="x", padx=30, pady=16)
        self.install_btn = FlatButton(action, "Install Certificate", self._do_install,
                                         bg=SUCCESS, fg=BG_DARK, hover_bg="#33ffdd")
        self.install_btn.pack(side="left")
        self.install_btn.set_state("disabled")

        # Result area
        self.result_card = tk.Frame(self, bg=BG_CARD, highlightbackground=BORDER,
                                    highlightthickness=1)
        self.result_label = tk.Label(self.result_card, text="", bg=BG_CARD, fg=FG_COLOR,
                                     font=FONT, wraplength=500, justify="left", padx=20, pady=14)
        self.result_label.pack(fill="x")

    def show(self):
        """Called when page becomes visible. Refresh prerequisites."""
        self._update_cert_status()
        threading.Thread(target=self._check_system, daemon=True).start()

    def _update_cert_status(self):
        bundle = self.app.bundle
        if bundle and bundle.server_cert:
            cn = bundle.server_cert.common_name
            self.cert_status.config(text=f"  Certificate: {cn}", fg=SUCCESS)
            # Set hostname from cert CN
            if cn and not self.bind_vars["host"].get():
                self.bind_vars["host"].set(cn)
        else:
            self.cert_status.config(text="  Certificate: Not loaded", fg=ERROR)

        if bundle and bundle.has_private_key:
            self.key_status.config(text="  Private Key: Present", fg=SUCCESS)
        else:
            self.key_status.config(text="  Private Key: Not loaded", fg=ERROR)

    def _check_system(self):
        is_admin = iis_manager.check_admin()
        has_iis = iis_manager.check_iis_installed() if is_admin else False
        sites = []
        if has_iis:
            sites, _ = iis_manager.get_iis_sites()
        self.after(0, lambda: self._update_system(is_admin, has_iis, sites))

    def _update_system(self, is_admin, has_iis, sites):
        self.admin_status.config(
            text=f"  Administrator: {'Yes' if is_admin else 'No (required!)'}",
            fg=SUCCESS if is_admin else ERROR,
        )
        self.iis_status.config(
            text=f"  IIS Module: {'Available' if has_iis else 'Not found'}",
            fg=SUCCESS if has_iis else ERROR,
        )

        self._sites = sites
        if sites:
            site_names = [s.name for s in sites]
            self.site_combo.config(values=site_names, state="readonly")
            self.site_combo.current(0)

        # Enable install button if everything is ready
        bundle = self.app.bundle
        can_install = (
            is_admin and has_iis and sites
            and bundle and bundle.server_cert and bundle.has_private_key
        )
        self.install_btn.set_state("normal" if can_install else "disabled")

    def _do_install(self):
        site_name = self.site_var.get()
        if not site_name:
            messagebox.showwarning("No Site", "Please select an IIS site.")
            return

        bundle = self.app.bundle
        if not bundle or not bundle.server_cert or not bundle.has_private_key:
            messagebox.showwarning("Cannot Install",
                "Certificate and private key are required.")
            return

        self.install_btn.set_text("Installing...")
        self.install_btn.set_state("disabled")
        self.app.status.set("Installing certificate...", "warning")

        def install():
            try:
                # Build PFX
                chain_pems = [c.pem_data for c in bundle.chain_certs]
                pfx_data = cert_utils.build_pfx(
                    bundle.server_cert.pem_data, bundle.private_key,
                    chain_pems,
                    friendly_name=bundle.server_cert.common_name or "SSL Cert",
                )

                # Write temp PFX
                import tempfile
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pfx")
                tmp.write(pfx_data)
                tmp.close()

                # Import to store
                success, thumbprint = iis_manager.import_pfx_to_store(tmp.name)
                os.unlink(tmp.name)

                if not success:
                    self.after(0, lambda: self._install_done(False, thumbprint))
                    return

                # Bind to site
                port = int(self.bind_vars["port"].get())
                success, msg = iis_manager.bind_cert_to_site(
                    site_name=site_name, thumbprint=thumbprint,
                    ip=self.bind_vars["ip"].get(), port=port,
                    hostname=self.bind_vars["host"].get(),
                )

                if not success:
                    self.after(0, lambda: self._install_done(False, msg))
                    return

                if self.restart_var.get():
                    iis_manager.restart_iis_site(site_name)

                self.after(0, lambda: self._install_done(
                    True, f"Certificate installed and bound to '{site_name}' on port {port}."
                ))

            except Exception as e:
                err_msg = str(e)
                self.after(0, lambda: self._install_done(False, err_msg))

        threading.Thread(target=install, daemon=True).start()

    def _install_done(self, success, message):
        self.result_card.pack(fill="x", padx=30, pady=(0, 12))
        if success:
            self.result_card.config(highlightbackground=SUCCESS)
            self.result_label.config(text=f"  {message}", fg=SUCCESS)
            self.install_btn.set_text("Installed!")
            self.app.status.set(message, "success")
            messagebox.showinfo("Success", message)
        else:
            self.result_card.config(highlightbackground=ERROR)
            self.result_label.config(text=f"  Failed: {message}", fg=ERROR)
            self.install_btn.set_text("Install Certificate")
            self.install_btn.set_state("normal")
            self.app.status.set(f"Failed: {message}", "error")
            messagebox.showerror("Installation Failed", message)


# ─── Main Application ───────────────────────────────────────────────────────

class CertBuilderApp:
    """Main application with sidebar navigation."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SSL Cert Builder")
        self.root.geometry("900x720")
        self.root.minsize(800, 600)
        self.root.configure(bg=BG_COLOR)

        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass

        self.bundle: Optional[cert_utils.ParsedCertBundle] = None
        self._last_key_path: Optional[str] = None
        self._current_page = None
        self._pages = {}
        self._nav_buttons = {}

        self._build_ui()
        self._navigate("generate")

        # Show background status
        if self._bg_path:
            self.status.set(f"Background loaded: {self._bg_path}", "success")
        elif not HAS_PIL:
            self.status.set("Install Pillow for background image: pip install Pillow", "warning")
        else:
            self.status.set("No background.png found in app folder", "info")

    def _build_ui(self):
        # Main container
        main = tk.Frame(self.root, bg=BG_COLOR)
        main.pack(fill="both", expand=True)

        # ─── Sidebar ───
        sidebar = tk.Frame(main, bg=SIDEBAR_BG, width=200)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # Logo area
        logo_frame = tk.Frame(sidebar, bg=SIDEBAR_BG)
        logo_frame.pack(fill="x", pady=(20, 24))
        tk.Label(logo_frame, text="SSL", bg=SIDEBAR_BG, fg=ACCENT,
                 font=(FONT_FAMILY, 22, "bold")).pack()
        tk.Label(logo_frame, text="Cert Builder", bg=SIDEBAR_BG, fg=SUCCESS,
                 font=FONT_SUBTITLE).pack(pady=(2, 0))
        tk.Label(logo_frame, text="RADICAL EDITION", bg=SIDEBAR_BG, fg=WARNING,
                 font=(FONT_FAMILY, 8, "bold")).pack()

        # Nav divider
        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(0, 8))

        # Nav buttons
        for key, label in NAV_ITEMS:
            btn = NavButton(sidebar, label, key, self._navigate)
            btn.pack(fill="x")
            self._nav_buttons[key] = btn

        # ─── Content area ───
        bg_image = _find_background_image()
        self._bg_path = bg_image
        self._bg_photo_ref = None  # Keep reference to prevent GC

        self._content = tk.Frame(main, bg=BG_COLOR)
        self._content.pack(side="left", fill="both", expand=True)

        # Load background image for banner headers
        if bg_image and HAS_PIL:
            try:
                self._bg_original = Image.open(bg_image)
            except Exception:
                self._bg_original = None
        else:
            self._bg_original = None

        # Create pages
        self._pages["generate"] = GenerateCSRPage(self._content, self)
        self._pages["import"] = ImportPage(self._content, self)
        self._pages["details"] = DetailsPage(self._content, self)
        self._pages["install"] = InstallPage(self._content, self)

        # ─── Status bar ───
        self.status = StatusBar(self.root)
        self.status.pack(fill="x", side="bottom")

    def _navigate(self, page_key: str):
        if self._current_page == page_key:
            return

        # Update nav button states
        for key, btn in self._nav_buttons.items():
            btn.set_active(key == page_key)

        # Hide all pages, show selected
        for key, page in self._pages.items():
            page.pack_forget()

        page = self._pages[page_key]
        page.pack(fill="both", expand=True)
        self._current_page = page_key

        # Notify page it's visible
        if hasattr(page, "show"):
            page.show()

    def create_banner(self, parent, height=140):
        """Create a banner with the background image, scaled to fill width."""
        if not self._bg_original:
            # Fallback: colored gradient banner
            banner = tk.Frame(parent, bg="#1a0a2e", height=height)
            banner.pack(fill="x")
            banner.pack_propagate(False)
            return banner

        banner = tk.Label(parent, bg=BG_COLOR, height=height)
        banner.pack(fill="x")
        banner._img_ref = None

        def _resize_banner(event=None):
            w = banner.winfo_width()
            if w < 10:
                return
            # Crop and resize the image to fill the banner
            img = self._bg_original.copy()
            # Take a horizontal strip from the image (upper portion with the sun)
            iw, ih = img.size
            crop_h = int(ih * 0.6)  # Top 60% of the image
            img = img.crop((0, 0, iw, crop_h))
            img = img.resize((w, height), Image.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            banner.config(image=photo, height=height)
            banner._img_ref = photo  # Prevent garbage collection

        banner.bind("<Configure>", _resize_banner)
        return banner

    def set_bundle(self, bundle: cert_utils.ParsedCertBundle):
        """Set the current certificate bundle and navigate to details."""
        self.bundle = bundle
        self._pages["details"].display_bundle(bundle)

        has_cert = bundle.server_cert is not None
        if bundle.errors:
            self.status.set(f"Imported with {len(bundle.errors)} warning(s)", "warning")
        elif has_cert:
            cn = bundle.server_cert.common_name or "certificate"
            self.status.set(f"Loaded: {cn}", "success")
        else:
            self.status.set("No server certificate found", "error")

        # Auto-navigate to details
        self._navigate("details")


def main():
    root = tk.Tk()

    # Apply dark ttk theme
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TCombobox", fieldbackground=ENTRY_BG, background=ACCENT_DIM,
                    foreground=FG_COLOR, selectbackground=ACCENT_DIM)
    style.configure("TScrollbar", background=ACCENT_DIM, troughcolor=ENTRY_BG,
                    arrowcolor=FG_COLOR)
    style.configure("TSeparator", background=BORDER)
    style.map("TCombobox", fieldbackground=[("readonly", ENTRY_BG)],
              foreground=[("readonly", FG_COLOR)])

    app = CertBuilderApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
