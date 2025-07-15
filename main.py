import json
import os
import csv
import secrets
import string
import random
import hashlib
import requests
from datetime import datetime

import customtkinter as ctk
from tkinter import messagebox

# =====================
# Configuration
# =====================
CONFIG_FILE = "config.json"

def load_config():
    """
    Load the application configuration from JSON file.
    Returns default config if file missing or invalid.
    """
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"appearance_mode": "Dark"}

def save_config(config):
    """
    Save configuration into JSON file.
    """
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)

# =====================
# Password Logic
# =====================

def generate_password(length: int, include_symbols: bool = True) -> str:
    """
    Generate a secure password ensuring mix of uppercase, lowercase,
    digits, and optional symbols. Minimum length 4.
    """
    if length < 4:
        return "Length must be ≥ 4"
    pool = string.ascii_letters + string.digits
    if include_symbols:
        pool += string.punctuation
    pwd = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits)
    ]
    if include_symbols:
        pwd.append(secrets.choice(string.punctuation))
    while len(pwd) < length:
        pwd.append(secrets.choice(pool))
    random.shuffle(pwd)
    return ''.join(pwd)

def generate_mnemonic_password() -> str:
    """
    Generate a mnemonic password: Word+Number+Symbol+Word.
    """
    words = ["Tiger", "Coffee", "Rain", "Planet", "Sky", "Moon", "Ocean", "Stone"]
    w1, w2 = random.sample(words, 2)
    return f"{w1}{random.randint(10,99)}{random.choice(string.punctuation)}{w2}!"

def check_password_breach(password: str) -> int | None:
    """
    Return breach count via HIBP API, or None on error.
    """
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return int(count)
        return 0
    except Exception:
        return None

def save_password(pwd: str) -> None:
    """
    Append password with timestamp to CSV file.
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("saved_passwords.csv", "a", newline="") as f:
        csv.writer(f).writerow([pwd, ts])

# =====================
# GUI Application Class
# =====================
class PasswordApp(ctk.CTk):
    """
    Main window for Password Generator Pro.
    """
    def __init__(self):
        super().__init__()
        self.title("🔐 Password Generator Pro")
        self.minsize(800, 600)

        # Apply user theme
        cfg = load_config()
        ctk.set_appearance_mode(cfg.get("appearance_mode", "Dark"))
        ctk.set_default_color_theme("dark-blue")

        # Layout
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Theme toggle
        ctk.CTkButton(self, text="🌙/☀️", command=self.toggle_theme).grid(
            row=0, column=0, padx=10, pady=10, sticky="nw"
        )

        # Tabs
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
        self.tabview.add("Generate")
        self.tabview.add("Saved Passwords")

        self._build_generate_tab()
        self._build_saved_tab()

    def _build_generate_tab(self):
        tab = self.tabview.tab("Generate")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_columnconfigure(1, weight=3)

        # Controls frame
        ctrl = ctk.CTkFrame(tab, corner_radius=10)
        ctrl.grid(row=0, column=0, sticky="nsew", padx=(0,10), pady=10)
        ctrl.grid_columnconfigure(0, weight=1)

        # Output frame
        out = ctk.CTkFrame(tab, corner_radius=10)
        out.grid(row=0, column=1, sticky="nsew", padx=(10,0), pady=10)
        out.grid_rowconfigure(0, weight=1)
        out.grid_columnconfigure(0, weight=1)

        # Length slider
        ctk.CTkLabel(ctrl, text="Length:").grid(
            row=0, column=0, sticky="w", pady=(10,2)
        )
        self.length_var = ctk.IntVar(value=12)
        self.len_label = ctk.CTkLabel(ctrl, text="12")
        self.len_label.grid(row=1, column=0, sticky="w")
        ctk.CTkSlider(
            ctrl,
            from_=4,
            to=32,
            variable=self.length_var,
            command=lambda v: self.len_label.configure(text=str(int(float(v))))
        ).grid(row=2, column=0, sticky="we", pady=(0,10))

        # Symbols checkbox
        self.sym_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            ctrl, text="Include Symbols", variable=self.sym_var
        ).grid(row=3, column=0, sticky="w", pady=5)

        # Mnemonic checkbox
        self.mnem_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            ctrl, text="Mnemonic Style", variable=self.mnem_var
        ).grid(row=4, column=0, sticky="w", pady=(0,10))

        # Bulk slider
        ctk.CTkLabel(ctrl, text="Bulk (count):").grid(
            row=5, column=0, sticky="w"
        )
        self.bulk_var = ctk.IntVar(value=1)
        self.bulk_label = ctk.CTkLabel(ctrl, text="1")
        self.bulk_label.grid(row=6, column=0, sticky="w")
        ctk.CTkSlider(
            ctrl,
            from_=1,
            to=20,
            variable=self.bulk_var,
            command=lambda v: self.bulk_label.configure(text=str(int(float(v))))
        ).grid(row=7, column=0, sticky="we", pady=(0,10))

        # Action buttons
        ctk.CTkButton(
            ctrl, text="🔐 Generate", command=self.on_generate
        ).grid(row=8, column=0, sticky="we", pady=5)
        self.copy_btn = ctk.CTkButton(
            ctrl, text="📋 Copy", command=self.copy_pwd, state="disabled"
        )
        self.copy_btn.grid(row=9, column=0, sticky="we", pady=5)
        self.save_btn = ctk.CTkButton(
            ctrl, text="💾 Save", command=self.save_pwd, state="disabled"
        )
        self.save_btn.grid(row=10, column=0, sticky="we", pady=5)

        # Output
        self.output = ctk.CTkTextbox(out)
        self.output.grid(row=0, column=0, sticky="nsew", padx=50, pady=50)

    def on_generate(self):
        self.output.delete('1.0', ctk.END)
        for _ in range(self.bulk_var.get()):
            pwd = (
                generate_mnemonic_password()
                if self.mnem_var.get()
                else generate_password(
                    self.length_var.get(), self.sym_var.get()
                )
            )
            self.output.insert(ctk.END, pwd + "\n")
        self.copy_btn.configure(state="normal")
        self.save_btn.configure(state="normal")

    def copy_pwd(self):
        text = self.output.get('1.0', ctk.END).strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)

    def save_pwd(self):
        text = self.output.get('1.0', ctk.END).strip()
        for pwd in text.splitlines():
            save_password(pwd)
        self.load_saved()

    def _build_saved_tab(self):
        tab = self.tabview.tab("Saved Passwords")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)

        frame = ctk.CTkFrame(tab, corner_radius=10)
        frame.grid(row=0, column=0, sticky="nsew", padx=15, pady=15)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)

        self.saved_text = ctk.CTkTextbox(frame)
        self.saved_text.grid(row=0, column=0, sticky="nsew", padx=20, pady=(0,20))
        ctk.CTkButton(
            frame, text="Refresh", command=self.load_saved
        ).grid(row=1, column=0, sticky="e", pady=(0,10))
        self.load_saved()

    def load_saved(self):
        self.saved_text.delete('1.0', ctk.END)
        if not os.path.isfile("saved_passwords.csv"):
            self.saved_text.insert(ctk.END, "No saved passwords.")
            return
        with open("saved_passwords.csv") as f:
            for row in csv.reader(f):
                pwd, ts = row[0], row[1]
                self.saved_text.insert(ctk.END, f"[{ts}] {pwd}\n")

    def toggle_theme(self):
        mode = "Light" if ctk.get_appearance_mode() == "Dark" else "Dark"
        ctk.set_appearance_mode(mode)
        save_config({"appearance_mode": mode})

# Run the app
if __name__ == "__main__":
    app = PasswordApp()
    app.mainloop()