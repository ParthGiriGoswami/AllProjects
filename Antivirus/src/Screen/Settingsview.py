import flet as ft
from Screen.Createbutton import create_custom_button
from Screen.FileDecryption import file_decryption
def file_decryptor(e: ft.FilePickerResultEvent, page: ft.Page):
    def handle_close(e):
        page.close(dia)
    if e.files and len(e.files) > 0:
        file = e.files[0].path
        if(file.endswith(".encrypted")):
            file_decryption(page, e.files[0].path)
        else:
            dia = ft.AlertDialog(
                modal=True,
                title=ft.Text("Info"),
                content=ft.Text("First encrypt the file"),
                actions=[
                    ft.TextButton("Ok", on_click=handle_close),
                ],
                actions_alignment=ft.MainAxisAlignment.END,
                on_dismiss=lambda e: page.add(
                    ft.Text("Modal dialog dismissed"),
                ),
            )
            page.open(dia)
def SettingsView(page: ft.Page):
    file_decrypt = ft.FilePicker(on_result=lambda e: file_decryptor(e, page))
    page.overlay.append(file_decrypt)
    return ft.Container(
        expand=True,
        padding=10,
        adaptive=True,
        content=ft.Column(
            [
                create_custom_button(page,"File Decryption","Decrypt a file",icon=ft.Icons.LOCK_OPEN,h=100,on_click=lambda _:  file_decrypt.pick_files(allow_multiple=False)),  
            ],
            spacing=20,
        ),
    )