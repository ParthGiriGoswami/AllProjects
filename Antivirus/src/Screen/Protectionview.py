import flet as ft
from Screen.Createbutton import create_custom_button
from Screen.TempFileRemoval import temp_file_removal
from Screen.FileEncryption import file_encryption
def file_encryptor(e: ft.FilePickerResultEvent, page: ft.Page):
    if e.files and len(e.files) > 0:
        file_encryption(page, e.files[0].path)
def ProtectionView(page: ft.Page):
    file_encrypt = ft.FilePicker(on_result=lambda e: file_encryptor(e, page))
    page.overlay.append(file_encrypt)
    return ft.Container(
        expand=True,
        padding=10,
        adaptive=True,
        content=ft.Column(
            [
                create_custom_button(page,"File Encrypt","Encrypts a file",icon=ft.Icons.LOCK,h=100,on_click=lambda _: file_encrypt.pick_files(allow_multiple=False)),
                create_custom_button(page,"Temporary File Removal","Removes files that are stored in device",icon=ft.Icons.INSERT_DRIVE_FILE_SHARP,h=100,on_click=lambda _: temp_file_removal(page)),
            ],
            spacing=20,
        ),
    )