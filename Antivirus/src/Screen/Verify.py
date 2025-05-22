import sqlite3
import flet as ft
import os
import hashlib
import hmac
from Screen.PasswordManager import passwordmanager
from Screen.FolderLockerUnlocker import folder_locker, folder_unlocker
from Screen.FileEncryptionDecryption import file_encryption, file_decryption
def file_decryptor(e: ft.FilePickerResultEvent, page: ft.Page):
    def handle_close(e):
        page.close(dia)
    if e.files and len(e.files) > 0:
        file = e.files[0].path
        if file.endswith(".encrypted"):
            file_decryption(page, file)
        else:
            dia = ft.AlertDialog(
                modal=True,
                title=ft.Text("Info"),
                content=ft.Text("First encrypt the file"),
                actions=[ft.TextButton("Ok", on_click=handle_close)],
                actions_alignment=ft.MainAxisAlignment.END,
                on_dismiss=lambda e: page.add(ft.Text("Modal dialog dismissed")),
            )
            page.open(dia)
def file_encryptor(e: ft.FilePickerResultEvent, page: ft.Page):
    if e.files and len(e.files) > 0:
        file_encryption(page, e.files[0].path)
def navigator(page,idx):
    lock_folder = ft.FilePicker(on_result=lambda e: folder_locker(e, page))
    page.overlay.append(lock_folder)
    unlock_folder = ft.FilePicker(on_result=lambda e: folder_unlocker(e, page))
    page.overlay.append(unlock_folder)
    file_encrypt = ft.FilePicker(on_result=lambda e: file_encryptor(e, page))
    page.overlay.append(file_encrypt)
    file_decrypt = ft.FilePicker(on_result=lambda e: file_decryptor(e, page))
    page.overlay.append(file_decrypt)
    if idx == "Password Manager":
        passwordmanager(page)
    elif idx == "Lock Folder":
        lock_folder.get_directory_path()
    elif idx == "Unlock Folder":
        unlock_folder.get_directory_path()
    elif idx == "File Encryption":
        file_encrypt.pick_files(allow_multiple=False)
    elif idx == "File Decryption":
        file_decrypt.pick_files(allow_multiple=False, allowed_extensions=["encrypted"])
def verify_yourself(page: ft.Page, idx):
    def fetch_password():
        with sqlite3.connect("storage/data/config.enc") as conn:
            cursor = conn.cursor()
            cursor.execute('CREATE TABLE IF NOT EXISTS passwords (salt BLOB NOT NULL,password BLOB NOT NULL)')
            cursor.execute('SELECT salt, password FROM passwords LIMIT 1')
            return cursor.fetchone()
    stored_row = fetch_password()
    def close_action(e):
        page.close(alert)
        page.update()
    def verifypassword(e):
        if len(cont.value) == 4:
            current_input = cont.value.encode()
            if stored_row:
                stored_salt, stored_hash = stored_row
                new_hash = hashlib.pbkdf2_hmac('sha256', current_input, stored_salt, 100000)
                if hmac.compare_digest(new_hash, stored_hash):
                    close_action(e)
                    navigator(page, idx)
                else:
                    cont.error_text = "Invalid Password"
                    page.update()
            else:
                salt = os.urandom(16)
                hashed_password = hashlib.pbkdf2_hmac('sha256', current_input, salt, 100000)
                with sqlite3.connect("storage/data/config.enc") as conn:
                    cursor = conn.cursor()
                    cursor.execute('INSERT INTO passwords (salt, password) VALUES (?, ?)', (salt, hashed_password))
                    conn.commit()
                close_action(e)
                navigator(page, idx)
    cont = ft.TextField(
        label="Password",
        password=True,
        can_reveal_password=True,
        keyboard_type=ft.KeyboardType.NUMBER,
        input_filter=ft.InputFilter(allow=True, regex_string=r"^\d*$", replacement_string=""),
        on_change=verifypassword,
        max_length=4,
        autofocus=True
    )
    alert = ft.AlertDialog(
        modal=True,
        title=ft.Row([
            ft.Text("Set Password" if not stored_row else "Enter 4 digit PIN", size=20, weight=ft.FontWeight.BOLD),
            ft.Container(expand=True),
            ft.IconButton(icon=ft.Icons.CLOSE, tooltip="Close", on_click=close_action),
        ], alignment=ft.MainAxisAlignment.START),
        content=cont,
        actions_alignment=ft.CrossAxisAlignment.END,
    )
    page.open(alert)