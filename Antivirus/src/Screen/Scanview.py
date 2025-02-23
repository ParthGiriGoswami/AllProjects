import flet as ft
import os
from Screen.scan import Scan
from Screen.Createbutton import create_custom_button
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
            Scan(page,scanned,rule)
def ScanView(page: ft.Page,rule,quickfiles,deepfiles):
    file_picker_for_custom_scan = ft.FilePicker(on_result=lambda e: on_folder_picked_for_custom_scan(e, page,rule,quickfiles))
    page.overlay.append(file_picker_for_custom_scan)
    file_picker_for_quick_scan = ft.FilePicker(on_result=lambda e: on_folder_picked_for_quick_scan(e, page,quickfiles))
    page.overlay.append(file_picker_for_quick_scan)
    return ft.Container(
        expand=True,
        adaptive=True,
        padding=10,
        content=ft.Column(
            [
                create_custom_button(page,"Quick Scan","Quickly scans high-risk areas for threats",100,icon=ft.Icons.SAVED_SEARCH,on_click=lambda _:file_picker_for_quick_scan.get_directory_path() if not quickfiles else Scan(page,quickfiles,rule)),
                create_custom_button(page,"Deep Scan","A full threat inspection for your entire device",100,icon=ft.Icons.SCREEN_SEARCH_DESKTOP_SHARP,on_click=lambda _:Scan(page, deepfiles,rule)),
                create_custom_button(page,"Custom Scan","Allows you to scan specific folders on your device",100,icon=ft.Icons.DASHBOARD_CUSTOMIZE_SHARP,on_click=lambda _: file_picker_for_custom_scan.get_directory_path()),
            ],
            spacing=20,
        ),
    )