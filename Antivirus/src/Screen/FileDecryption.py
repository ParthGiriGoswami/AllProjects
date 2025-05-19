from cryptography.fernet import Fernet
import os,flet as ft
def load_key(key_file):
    with open(key_file, "rb") as file:
        key = file.read()
    return key
def file_decryption(page: ft.Page,encrypted_file_path):
    def handle_close(e):
        page.close(dia)
    if not os.path.exists(encrypted_file_path):
        pass
    base_name = encrypted_file_path.replace(".encrypted", "")
    key_file = f"{base_name}.key"
    if not os.path.exists(key_file):
        dia = ft.AlertDialog(
            modal=True,
            title=ft.Text("Info"),
            content=ft.Text(f"Key file not found for decryption: {key_file}"),
            actions=[
                ft.TextButton("Ok", on_click=handle_close),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
            on_dismiss=lambda e: page.add(
                ft.Text("Modal dialog dismissed"),
            ),
        )
        page.open(dia)
    key = load_key(key_file)
    fernet = Fernet(key)
    with open(encrypted_file_path, "rb") as file:
        encrypted_data = file.read()  
    decrypted_data = fernet.decrypt(encrypted_data)
    original_file = base_name
    with open(original_file, "wb") as file:
        file.write(decrypted_data)  
    dia = ft.AlertDialog(
        modal=True,
        title=ft.Text("Info"),
        content=ft.Text("File Decrypted"),
        actions=[
            ft.TextButton("Ok", on_click=handle_close),
        ],
        actions_alignment=ft.MainAxisAlignment.END,
        on_dismiss=lambda e: page.add(
            ft.Text("Modal dialog dismissed"),
        ),
    )
    page.open(dia)
    os.remove(encrypted_file_path)
    os.remove(key_file)
    return original_file