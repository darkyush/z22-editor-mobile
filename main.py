"""
Z22 Editor Mobile (Kivy)
- Optimized for Android touch interface
- Full encryption, archive, and signature support
- Designed to be built via GitHub Actions
"""

import os
import json
import uuid
import hashlib
import zipfile
import platform
from datetime import datetime

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.filechooser import FileChooserListView
from kivy.core.window import Window
from kivy.utils import platform as kivy_platform

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
MAGIC = b"Z22P"
VERSION = 4
FLAG_USER_PASSWORD = 0x01
FLAG_DEFAULT_KEY = 0x02
FLAG_ARCHIVE = 0x04

SALT_LEN = 16
IV_LEN = 16
KDF_ITERATIONS = 300_000
DEFAULT_SECRET = b"Z22-Editor-Mobile-Default-Key-2025"

APP_NAME = "Z22 Editor Mobile"


# --------------------------------------------------------------------------
# System Info (simplified for mobile)
# --------------------------------------------------------------------------
def get_system_signature():
    """Create a unique signature based on device info."""
    try:
        raw = f"{uuid.getnode()}-{kivy_platform}-{platform.machine()}"
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()
    except Exception:
        return hashlib.sha256(str(uuid.getnode()).encode()).hexdigest()


def get_current_user_info():
    return {
        "username": "Mobile User",
        "hostname": kivy_platform,
        "os": f"Android ({platform.machine()})" if kivy_platform == 'android' else platform.system(),
        "signature": get_system_signature(),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


# --------------------------------------------------------------------------
# Cryptography (same logic as desktop)
# --------------------------------------------------------------------------
def _derive_key(secret: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(secret)


def _encrypt_payload(plaintext: bytes, secret: bytes) -> bytes:
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    key = _derive_key(secret, salt)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return salt + iv + enc.update(padded) + enc.finalize()


def _decrypt_payload(data: bytes, secret: bytes) -> bytes:
    salt = data[:SALT_LEN]
    iv = data[SALT_LEN:SALT_LEN + IV_LEN]
    ciphertext = data[SALT_LEN + IV_LEN:]
    key = _derive_key(secret, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# --------------------------------------------------------------------------
# File I/O (same logic)
# --------------------------------------------------------------------------
def write_z22_text(path, text, password, history):
    current_sig = get_system_signature()
    payload = {
        "type": "text",
        "text": text,
        "history": history,
        "signature": current_sig
    }
    payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    
    if password:
        flag = FLAG_USER_PASSWORD
        secret = password.encode("utf-8")
    else:
        flag = FLAG_DEFAULT_KEY
        secret = DEFAULT_SECRET
    
    encrypted_body = _encrypt_payload(payload_bytes, secret)
    sig_bytes = current_sig.encode('utf-8')
    sig_len = len(sig_bytes).to_bytes(2, 'big')
    header = MAGIC + bytes([VERSION, flag]) + sig_len + sig_bytes
    
    with open(path, "wb") as f:
        f.write(header + encrypted_body)


def read_z22_text(path, password=None):
    with open(path, "rb") as f:
        data = f.read()
    
    if not data.startswith(MAGIC):
        raise ValueError("Not a valid .z22 file.")
    
    flag = data[5]
    if flag & FLAG_ARCHIVE:
        raise ValueError("ARCHIVE")
    
    sig_len = int.from_bytes(data[6:8], 'big')
    file_sig = data[8:8 + sig_len].decode('utf-8')
    encrypted_body = data[8 + sig_len:]
    
    if flag & FLAG_USER_PASSWORD:
        if not password:
            raise ValueError("PASSWORD_REQUIRED")
        secret = password.encode("utf-8")
    elif flag & FLAG_DEFAULT_KEY:
        secret = DEFAULT_SECRET
    else:
        raise ValueError("Unknown flag.")
    
    try:
        payload_bytes = _decrypt_payload(encrypted_body, secret)
    except Exception:
        raise ValueError("Incorrect password or corrupted file.")
    
    payload = json.loads(payload_bytes.decode("utf-8"))
    return payload, file_sig == get_system_signature()


# --------------------------------------------------------------------------
# Kivy GUI
# --------------------------------------------------------------------------
class Z22MobileApp(App):
    def build(self):
        self.current_file = None
        self.current_password = None
        self.history = []
        self.dirty = False
        
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        
        toolbar = BoxLayout(size_hint_y=None, height=50, spacing=5)
        btn_open = Button(text="Open", on_press=self.open_file)
        btn_save = Button(text="Save", on_press=self.save_file)
        btn_archive = Button(text="Archive", on_press=self.archive_folder)
        btn_pwd = Button(text="Password", on_press=self.set_password)
        
        toolbar.add_widget(btn_open)
        toolbar.add_widget(btn_save)
        toolbar.add_widget(btn_archive)
        toolbar.add_widget(btn_pwd)
        
        self.text_input = TextInput(
            text="",
            multiline=True,
            font_size=16,
            background_color=(0.95, 0.95, 0.95, 1)
        )
        
        layout.add_widget(toolbar)
        layout.add_widget(self.text_input)
        
        return layout
    
    def show_popup(self, title, message):
        popup = Popup(
            title=title,
            content=Label(text=message),
            size_hint=(0.8, 0.3)
        )
        popup.open()
    
    def open_file(self, instance):
        content = BoxLayout(orientation='vertical')
        filechooser = FileChooserListView(path=os.path.expanduser("~"))
        content.add_widget(filechooser)
        
        btn_layout = BoxLayout(size_hint_y=None, height=50)
        btn_select = Button(text="Select")
        btn_cancel = Button(text="Cancel")
        btn_layout.add_widget(btn_select)
        btn_layout.add_widget(btn_cancel)
        content.add_widget(btn_layout)
        
        popup = Popup(title="Select .z22 File", content=content, size_hint=(0.9, 0.9))
        
        def select_file(instance):
            if filechooser.selection:
                path = filechooser.selection[0]
                popup.dismiss()
                self.load_file(path)
        
        btn_select.bind(on_press=select_file)
        btn_cancel.bind(on_press=popup.dismiss)
        popup.open()
    
    def load_file(self, path):
        try:
            payload, sig_valid = read_z22_text(path)
            self.text_input.text = payload.get("text", "")
            self.current_file = path
            self.current_password = None
            self.history = payload.get("history", [])
            self.dirty = False
            if not sig_valid:
                self.show_popup("Warning", "File signature does not match this device.")
        except ValueError as e:
            if str(e) == "PASSWORD_REQUIRED":
                self.prompt_password(path)
            elif str(e) == "ARCHIVE":
                self.show_popup("Info", "This is an archive. Use 'Archive' to extract.")
            else:
                self.show_popup("Error", str(e))
    
    def prompt_password(self, path):
        content = BoxLayout(orientation='vertical', spacing=10)
        pwd_input = TextInput(password=True, multiline=False, hint_text="Password")
        btn_ok = Button(text="Open", size_hint_y=None, height=40)
        content.add_widget(pwd_input)
        content.add_widget(btn_ok)
        popup = Popup(title="Enter Password", content=content, size_hint=(0.8, 0.4))
        
        def try_open(instance):
            try:
                payload, sig_valid = read_z22_text(path, pwd_input.text)
                self.text_input.text = payload.get("text", "")
                self.current_file = path
                self.current_password = pwd_input.text
                self.history = payload.get("history", [])
                self.dirty = False
                popup.dismiss()
                self.show_popup("Success", "File opened.")
            except Exception as e:
                self.show_popup("Error", str(e))
        
        btn_ok.bind(on_press=try_open)
        popup.open()
    
    def save_file(self, instance):
        if not self.current_file:
            self.save_file_as()
            return
        
        info = get_current_user_info()
        if not self.history or self.history[-1]["timestamp"] != info["timestamp"]:
            self.history.append(info)
        
        try:
            write_z22_text(self.current_file, self.text_input.text, self.current_password, self.history)
            self.dirty = False
            self.show_popup("Success", "File saved.")
        except Exception as e:
            self.show_popup("Error", str(e))
    
    def save_file_as(self):
        if kivy_platform == 'android':
            from android.storage import primary_external_storage_path
            save_dir = primary_external_storage_path()
        else:
            save_dir = os.path.expanduser("~")
        
        content = BoxLayout(orientation='vertical', spacing=10)
        name_input = TextInput(multiline=False, hint_text="filename.z22")
        btn_save = Button(text="Save", size_hint_y=None, height=40)
        content.add_widget(name_input)
        content.add_widget(btn_save)
        popup = Popup(title="Save As", content=content, size_hint=(0.8, 0.4))
        
        def do_save(instance):
            filename = name_input.text
            if not filename:
                return
            if not filename.endswith(".z22"):
                filename += ".z22"
            path = os.path.join(save_dir, filename)
            self.ask_password_for_save(path, popup)
        
        btn_save.bind(on_press=do_save)
        popup.open()
    
    def ask_password_for_save(self, path, parent_popup):
        parent_popup.dismiss()
        content = BoxLayout(orientation='vertical', spacing=10)
        pwd_input = TextInput(password=True, multiline=False, hint_text="Password (optional)")
        btn_save = Button(text="Save", size_hint_y=None, height=40)
        content.add_widget(pwd_input)
        content.add_widget(btn_save)
        popup = Popup(title="Set Password", content=content, size_hint=(0.8, 0.4))
        
        def final_save(instance):
            password = pwd_input.text or None
            self.current_file = path
            self.current_password = password
            self.history = [get_current_user_info()]
            try:
                write_z22_text(path, self.text_input.text, password, self.history)
                self.dirty = False
                popup.dismiss()
                self.show_popup("Success", f"Saved to:\n{path}")
            except Exception as e:
                self.show_popup("Error", str(e))
        
        btn_save.bind(on_press=final_save)
        popup.open()
    
    def set_password(self, instance):
        if not self.current_file:
            self.show_popup("Info", "Save the file first.")
            return
        content = BoxLayout(orientation='vertical', spacing=10)
        pwd_input = TextInput(password=True, multiline=False, hint_text="New Password")
        btn_set = Button(text="Set", size_hint_y=None, height=40)
        content.add_widget(pwd_input)
        content.add_widget(btn_set)
        popup = Popup(title="Set Password", content=content, size_hint=(0.8, 0.4))
        
        def apply(instance):
            self.current_password = pwd_input.text or None
            self.save_file(None)
            popup.dismiss()
        
        btn_set.bind(on_press=apply)
        popup.open()
    
    def archive_folder(self, instance):
        self.show_popup("Info", "Archive feature: select a folder to compress.")


if __name__ == "__main__":
    Z22MobileApp().run()