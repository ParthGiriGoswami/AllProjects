import flet as ft,subprocess,platform,os,stat
from Screen.Createbutton import create_custom_button
from Screen.TempFileRemoval import temp_file_removal
from Screen.FileEncryption import file_encryption
from Screen.PasswordManager import passwordmanager
def file_encryptor(e: ft.FilePickerResultEvent, page: ft.Page):
    if e.files and len(e.files) > 0:
        file_encryption(page, e.files[0].path)
def folder_locker(e: ft.FilePickerResultEvent, page: ft.Page):
    system = platform.system()
    def handle_close(e):
        page.close(dia)
    if e.path:
        if system == "Windows":
            command = f'icacls "{e.path}" /deny everyone:F'
            subprocess.run(command, shell=True, check=True)
            cont=ft.Text(f"{e.path} locked successfully")
        elif system in ("Linux", "Darwin"):  
            os.chmod(e.path, stat.S_IRWXU)
            cont=ft.Text(f"{e.path} locked successfully")
        else:
            cont=ft.Text("Cant lock the folder")
        dia=ft.AlertDialog(
            content=cont,
            modal=True,
            title=ft.Text("Info"),
            actions=[
                ft.TextButton("Ok", on_click=handle_close),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
            on_dismiss=lambda e: page.add(
                ft.Text("Modal dialog dismissed"),
            ),
        )
        page.open(dia)
def ProtectionView(page: ft.Page):
    file_encrypt = ft.FilePicker(on_result=lambda e: file_encryptor(e, page))
    lock_folder = ft.FilePicker(on_result=lambda e: folder_locker(e, page))
    page.overlay.append(file_encrypt)
    page.overlay.append(lock_folder)
    return ft.Container(
        expand=True,
        padding=10,
        adaptive=True,
        content=ft.Column(
            [
                ft.Text(value="Protection", size=20),
                create_custom_button(page,"File Encryption","Encrypts a file",icon=ft.Icons.LOCK,on_click=lambda _: file_encrypt.pick_files(allow_multiple=False)),
                create_custom_button(page,"Temporary File Removal","Removes files that are stored in device",icon=ft.Icons.INSERT_DRIVE_FILE_SHARP,on_click=lambda _: temp_file_removal(page)),  
                create_custom_button(page,"Password Manager","Manages passwords on this device",icon=ft.Icons.MANAGE_ACCOUNTS_ROUNDED,on_click=lambda _: passwordmanager(page)),
                create_custom_button(page,"Lock Folder","Locks any folder in the device",icon=ft.Icons.FOLDER_OFF,on_click=lambda _:lock_folder.get_directory_path()),    
            ],
            spacing=21,
        ),
    )