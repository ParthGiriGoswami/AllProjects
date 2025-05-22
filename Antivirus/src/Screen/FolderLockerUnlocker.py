import flet as ft,subprocess,platform,os,stat
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