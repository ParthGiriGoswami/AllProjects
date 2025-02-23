import flet as ft
from Screen.Createbutton import create_custom_button
from Screen.FileDecryption import file_decryption
import os
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
def on_folder_picked_for_quick_scan(e: ft.FilePickerResultEvent, page: ft.Page):
    count=0
    def handle_close(e):
        page.close(dia)
    if e.path:
        try:
            quick_file_path = "storage/data/quickpath.txt"
            os.makedirs(os.path.dirname(quick_file_path), exist_ok=True)
            try:
                with open(quick_file_path, "a") as quick_file:
                    quick_file.write(f"{e.path}\n")
                    count=count+1
            except:
                pass
        except:
            pass
        if (count==0):
            dia=ft.AlertDialog(
                modal=True,
                title=ft.Text("Info"),
                content=ft.Text("No files selected"),
                actions=[
                    ft.TextButton("Ok", on_click=handle_close),
                ],
                actions_alignment=ft.MainAxisAlignment.END,
                on_dismiss=lambda e: page.add(
                    ft.Text("Modal dialog dismissed"),
                ),
            )
            page.open(dia)
        else:
            dia=ft.AlertDialog(
                modal=True,
                title=ft.Text("Info"),
                content=ft.Text("A  path is added to quick scan"),
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
    file_picker_for_quick_scan = ft.FilePicker(on_result=lambda e: on_folder_picked_for_quick_scan(e, page))
    page.overlay.append(file_picker_for_quick_scan)
    file_decrypt = ft.FilePicker(on_result=lambda e: file_decryptor(e, page))
    page.overlay.append(file_decrypt)
    return ft.Container(
        expand=True,
        padding=10,
        adaptive=True,
        content=ft.Column(
            [
                create_custom_button(page,"Add Files","Adds files to quickscan",icon=ft.Icons.ADD_BOX,h=100,on_click=lambda _: file_picker_for_quick_scan.get_directory_path()),
                create_custom_button(page,"File Decryption","Decrypt a file",icon=ft.Icons.LOCK_OPEN,h=100,on_click=lambda _:  file_decrypt.pick_files(allow_multiple=False)),  
            ],
            spacing=20,
        ),
    )