import flet as ft
from Screen.scan import Scan
import os
scanned=set()
def scan_directory(directory, file_set):
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.is_file():
                    file_set.add(entry.path)
                elif entry.is_dir(follow_symlinks=False):
                    scan_directory(entry.path, file_set)
    except (PermissionError, FileNotFoundError):
        pass
def on_folder_picked_for_quick_scan(e: ft.FilePickerResultEvent, page: ft.Page,rule,quickfiles):
    global scanned
    if e.path:
        try:
            quick_file_path = "src/Screen/quickpath.txt"
            os.makedirs(os.path.dirname(quick_file_path), exist_ok=True)
            try:
                with open(quick_file_path, "a") as quick_file:
                    quick_file.write(f"{e.path}\n")
                    scanned.add(e.path)
                for file in scanned:
                    scan_directory(file,quickfiles)
            except:
                pass
        except:
            pass
        if scanned:
            Scan(page,quickfiles,rule)
def HomeView(page: ft.Page,rule,quickfiles):
    file_picker_for_quick_scan = ft.FilePicker(on_result=lambda e: on_folder_picked_for_quick_scan(e, page,rule,quickfiles))
    page.overlay.append(file_picker_for_quick_scan)
    btn1 = ft.ElevatedButton(
        "Quick scan",
        on_click=lambda _:file_picker_for_quick_scan.get_directory_path() if not quickfiles else Scan(page,quickfiles,rule)
    )
    return ft.Container(
        expand=True,
        padding=10,
        content=ft.Column(
            [
                ft.Row([ft.Icon(name=ft.Icons.INFO_OUTLINED, size=200)], alignment=ft.MainAxisAlignment.CENTER),
                ft.Row([ft.Text(value="Perform a scan", size=20)], alignment=ft.MainAxisAlignment.CENTER),
                ft.Row([btn1], alignment=ft.MainAxisAlignment.CENTER)
            ],
            spacing=10,
            expand=True,
            alignment=ft.MainAxisAlignment.CENTER
        ),
    )