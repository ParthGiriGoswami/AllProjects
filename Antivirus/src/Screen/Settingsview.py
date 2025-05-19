import flet as ft,subprocess,platform,os,stat
from Screen.Createbutton import create_custom_button
from Screen.FileDecryption import file_decryption
from Screen.ListFiles import listfiles
def folder_unlocker(e: ft.FilePickerResultEvent, page: ft.Page):
    def handle_close(e):
        page.close(dia)
    if e.path:
        system = platform.system()
        if system == "Windows":
            command = f'icacls "{e.path}" /remove:d everyone'
            try:
                subprocess.run(command, shell=True, check=True)
                cont=ft.Text(f"{e.path} unlocked successfully")
            except:
                pass
        elif system in ("Linux", "Darwin"):  
            try:
                os.chmod(e.path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
                cont=ft.Text(f"{e.path} unlocked successfully")
            except:
                pass
        else:
            cont=ft.Text("Can't lock the folder")
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
def SettingsView(page: ft.Page,quickpath,quickfile):
    file_decrypt = ft.FilePicker(on_result=lambda e: file_decryptor(e, page))
    page.overlay.append(file_decrypt)
    unlock_folder = ft.FilePicker(on_result=lambda e: folder_unlocker(e, page))
    page.overlay.append(unlock_folder)
    exclusionpath=set()
    if os.path.exists("storage/data/exclusion.txt"):
        with open("storage/data/exclusion.txt", "r") as file:
            exclusionpath=set(line.strip() for line in file)
    return ft.Container(
        expand=True,
        padding=10,
        adaptive=True,
        content=ft.Column(
            [
                ft.Text(value="Settings", size=20),
                create_custom_button(page,"Edit Quick files","Adds or remove files from quickscan list",icon=ft.Icons.ADD_BOX,on_click=lambda _: listfiles(page,idp="Quick List",path=quickpath,file=quickfile)),
                create_custom_button(page,"Edit Exclusion files","Adds or remove files from exclusion list",icon=ft.Icons.ADD_BOX,on_click=lambda _: listfiles(page,idp="Exclusion List",path=exclusionpath)),
                create_custom_button(page,"File Decryption","Decrypt a file",icon=ft.Icons.LOCK_OPEN,on_click=lambda _:  file_decrypt.pick_files(allow_multiple=False, allowed_extensions=["encrypted"])), 
                create_custom_button(page,"Unlock Folder","Unlocks any locked folder in the device",icon=ft.Icons.MANAGE_ACCOUNTS_ROUNDED,on_click=lambda _:unlock_folder.get_directory_path()),
            ],
            spacing=21,
        ),
    )