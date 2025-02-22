import flet as ft
import psutil
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from Screens.CustomLayout import create_floating_button, create_nav_bar, create_title_bar
count = 0
files = set()
scanned = set()
quick_list = set()
file_lock = threading.Lock()  
def on_folder_picked_for_quick_scan(e: ft.FilePickerResultEvent, page: ft.Page):
    global scanned
    if e.path:
        try:
            quick_file_path = "Antivirus/Screens/quickpath.txt"
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
            page.go("/quickscan?from=/home")
def get_count():
    global count, files
    return count, files
def get_drives(page, txt):
    global count, files
    if count == 0:
        txt.value = "Counting files..."
        page.update()
        partitions = psutil.disk_partitions()
        drive_letters = [partition.device for partition in partitions if partition.fstype]
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
        def scan_drive(drive):
            local_files = set()
            scan_directory(drive, local_files)
            with file_lock:
                files.update(local_files)
            return len(local_files)
        max_workers = min(len(drive_letters), os.cpu_count())
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(scan_drive, drive_letters))
        count = sum(results)
    txt.value = f"{len(files)} files found"
    page.update()
def main_screen(page: ft.Page):
    global scanned,quick_list
    txt = ft.Text(value="")
    quick_scan_path = "Antivirus/Screens/quickpath.txt"
    if os.path.exists(quick_scan_path):
        with open(quick_scan_path, 'r') as file:
            quick_list = set(line.strip() for line in file)
        scanned=quick_list
    file_picker_for_quick_scan = ft.FilePicker(on_result=lambda e: on_folder_picked_for_quick_scan(e, page))
    btn1 = ft.ElevatedButton("Quick scan",on_click=lambda _: file_picker_for_quick_scan.get_directory_path() if not quick_list else page.go("/quickscan?from=/home"))
    nav_bar = create_nav_bar(page, active="Home")
    floating_button = create_floating_button()
    return ft.View(
        route="/home",
        padding=0,
        controls=[
            ft.Column(
                [
                    create_title_bar(page),
                    file_picker_for_quick_scan,
                    ft.Row(
                        [
                            nav_bar,
                            ft.Column(
                                [
                                    ft.Row([ft.Icon(name=ft.Icons.INFO_OUTLINED, size=200)], alignment=ft.MainAxisAlignment.CENTER),
                                    ft.Row([ft.Text(value="Perform a scan", size=20)], alignment=ft.MainAxisAlignment.CENTER),
                                    ft.Row([btn1], alignment=ft.MainAxisAlignment.CENTER),
                                    ft.Row([txt], alignment=ft.MainAxisAlignment.CENTER),
                                ],
                                alignment=ft.MainAxisAlignment.CENTER,
                                expand=True,
                            ),
                        ],
                        alignment=ft.MainAxisAlignment.START,
                        expand=True,
                        spacing=0,
                    ),
                ],
                spacing=0,
                offset=ft.transform.Offset(0, 0),
                animate_offset=ft.animation.Animation(200,"easeOut"),
                expand=True,
            ),
            floating_button,
        ]
    ), txt, scanned
def start_scan(page, txt):
    thread = threading.Thread(target=get_drives, args=(page, txt), daemon=True)
    thread.start()