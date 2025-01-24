import flet as ft
from Screens.CustomLayout import create_floating_button, create_nav_bar, create_custom_button, create_title_bar
from Screens.TempFileRemoval import temp_file_removal
from Screens.FileEncryption import file_encryption
def file_encryptor(e: ft.FilePickerResultEvent, page: ft.Page):
    if e.files and len(e.files) > 0:
        file_encryption(page, e.files[0].path)
def protection(page: ft.Page):
    nav_bar = create_nav_bar(page, active="Protection")
    floating_button = create_floating_button()
    file_encrypt = ft.FilePicker(on_result=lambda e: file_encryptor(e, page))
    page.overlay.append(file_encrypt)
    return ft.View(
        route="/protection",
        padding=0,
        controls=[
            ft.Column(
                [
                    create_title_bar(page),
                    ft.Row(
                        [
                            nav_bar,
                            ft.Container(width=10),
                            ft.Column(
                                [
                                    create_custom_button(
                                        "File Encrypt",
                                        "Encrypts a file",
                                        icon=ft.Icons.LOCK,
                                        w=500,
                                        h=100,
                                        on_click=lambda _: file_encrypt.pick_files(allow_multiple=False),
                                    ),
                                ],
                            ),
                            ft.Container(width=10),
                            ft.Column(
                                [
                                    create_custom_button(
                                        "Temporary File Removal",
                                        "Removes files that are stored in device",
                                        icon=ft.Icons.INSERT_DRIVE_FILE_SHARP,
                                        w=500,
                                        h=100,
                                        on_click=lambda _: temp_file_removal(page),
                                    ),
                                ],
                            ),
                        ],
                        alignment=ft.MainAxisAlignment.START,
                        expand=True,
                        spacing=0,
                    ),
                ],
                expand=True,
                offset=ft.transform.Offset(0, 0),
                animate_offset=ft.animation.Animation(200,"easeOut"),
                spacing=0,
            ),
            floating_button,
        ],
    )