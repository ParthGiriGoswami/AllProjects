import flet as ft
import os
from Screens.CustomLayout import create_floating_button, create_nav_bar, create_custom_button, create_title_bar
scanned = set()
def on_folder_picked_for_custom_scan(e: ft.FilePickerResultEvent, page: ft.Page):
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
            page.go("/customscan")
def on_folder_picked_for_quick_scan(e: ft.FilePickerResultEvent, page: ft.Page):
    global scanned
    if e.path:
        try:
            quick_file_path = "Major_Project/Screens/quickpath.txt"
            os.makedirs(os.path.dirname(quick_file_path), exist_ok=True)
            try:
                with open(quick_file_path, "a") as quick_file:
                    quick_file.write(f"{e.path}\n")
                    scanned.add(e.path)
            except:
                pass
        except:
            pass
        if scanned:
            page.go("/quickscan?from=/scan")
def scans(page: ft.Page):
    global scanned
    quick_list = set()
    quick_scan_path = "Major_Project/Screens/quickpath.txt"
    if os.path.exists(quick_scan_path):
        with open(quick_scan_path, 'r') as file:
            quick_list = set(line.strip() for line in file)
    file_picker_for_custom_scan = ft.FilePicker(on_result=lambda e: on_folder_picked_for_custom_scan(e, page))
    file_picker_for_quick_scan = ft.FilePicker(on_result=lambda e: on_folder_picked_for_quick_scan(e, page))
    page.overlay.append(file_picker_for_custom_scan)
    page.overlay.append(file_picker_for_quick_scan)
    if quick_list:
        scanned = quick_list
    nav_bar = create_nav_bar(page, active="Scan")
    floating_button = create_floating_button()
    return ft.View(
        route="/scan",
        padding=0,
        controls=[
            create_title_bar(page),
            ft.Row(
                [
                    nav_bar,
                    ft.Container(
                        content=ft.Column(
                            [
                                create_custom_button(
                                    "Quick Scan",
                                    "Quickly scans high-risk areas for threats",
                                    on_click=lambda _: file_picker_for_quick_scan.get_directory_path() if not quick_list else page.go("/quickscan?from=/scan"),
                                    icon=ft.Icons.SAVED_SEARCH,
                                    w=600,
                                    h=100
                                ),
                                create_custom_button(
                                    "Deep Scan",
                                    "A full threat inspection for your entire device",
                                    on_click=lambda _: page.go("/deepscan?from=/scan"),
                                    icon=ft.Icons.SCREEN_SEARCH_DESKTOP_SHARP,
                                    w=600,
                                    h=100
                                ),
                                create_custom_button(
                                    "Custom Scan",
                                    "Allows you to scan specific folders on your device",
                                    on_click=lambda _: file_picker_for_custom_scan.get_directory_path(),
                                    icon=ft.Icons.DASHBOARD_CUSTOMIZE_SHARP,
                                    w=600,
                                    h=100
                                ),
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.START,
                            expand=True,
                        ),
                        padding=0,
                        expand=True,
                    )
                ],
                alignment=ft.MainAxisAlignment.START,
                offset=ft.transform.Offset(0, 0),
                animate_offset=ft.animation.Animation(200,"easeOut"),
                expand=True,
            ),
            floating_button,
        ]
    ), scanned
