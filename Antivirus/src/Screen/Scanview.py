import flet as ft
import os
from Screen.scan import Scan
from Screen.Createbutton import create_custom_button
def on_folder_picked_for_custom_scan(e: ft.FilePickerResultEvent, page: ft.Page,rule):
    global scanned
    if e.path:
        try:
            with os.scandir(e.path) as entries:
                for entry in entries:
                    if entry.is_file():
                        scanned.add(entry.path)
        except (PermissionError, FileNotFoundError):
            pass
        if scanned:
            Scan(page,scanned,rule,False)
def ScanView(page: ft.Page,rule,files):
    file_picker_for_custom_scan = ft.FilePicker(on_result=lambda e: on_folder_picked_for_custom_scan(e, page,rule))
    page.overlay.append(file_picker_for_custom_scan)
    return ft.Container(
        expand=True,
        adaptive=True,
        padding=10,
        content=ft.Column(
            [
                create_custom_button(page,"Quick Scan","Quickly scans high-risk areas for threats",100,icon=ft.Icons.SAVED_SEARCH,on_click=lambda _:Scan(page,files,rule,False)),
                create_custom_button(page,"Deep Scan","A full threat inspection for your entire device",100,icon=ft.Icons.SCREEN_SEARCH_DESKTOP_SHARP,on_click=lambda _:Scan(page, files,rule,True)),
                create_custom_button(page,"Custom Scan","Allows you to scan specific folders on your device",100,icon=ft.Icons.DASHBOARD_CUSTOMIZE_SHARP,on_click=lambda _: file_picker_for_custom_scan.get_directory_path()),
            ],
            spacing=20,
        ),
    )