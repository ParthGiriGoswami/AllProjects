import flet as ft
from Screen.Protectionview import ProtectionView
from Screen.Settingsview import SettingsView
from Screen.Scanview import ScanView
from Screen.Homeview import HomeView
import yara, psutil, threading, os, time
from Screen.PendriveDetection import list_connected_devices
from concurrent.futures import ThreadPoolExecutor
file_lock = threading.Lock()  
count = 0
quickpath=set()
deepfiles = set()
quickfiles = set()
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
def get_drives():
    global count, deepfiles
    if count == 0:
        partitions = psutil.disk_partitions()
        drive_letters = [partition.device for partition in partitions if partition.fstype]
        def scan_drive(drive):
            local_files = set()
            scan_directory(drive, local_files)
            with file_lock:
                deepfiles.update(local_files)
            return len(local_files)
        max_workers = min(len(drive_letters), os.cpu_count())
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            list(executor.map(scan_drive, drive_letters))
        count = 1
def MainPage(page: ft.Page):
    global quickfiles
    rule = """
    rule ExampleMalware
    {
        strings:
            $ransomware_pattern = {50 53 51 52 56 57 55 41 54 41 55 41 56 41 57}
            $keylogger_pattern = {6A 00 68 00 30 00 00 64 FF 35 30 00 00 00}
            $suspicious_cmd = "cmd.exe /c"
            $powershell_script = "powershell.exe -nop -w hidden"
            $shellcode_pattern = {31 C0 50 68 2E 65 78 65 68 63 61 6C 63 54 5F 50 57 56 50 FF D0}
        condition:
            any of ($ransomware_pattern, $keylogger_pattern, $suspicious_cmd, $powershell_script, $shellcode_pattern)
    }
    """
    compiled_rule = yara.compile(source=rule)
    def device_monitor(page):
        while True:
            list_connected_devices(page,compiled_rule)
            time.sleep(1)
    threading.Thread(target=device_monitor,args=(page,) ,daemon=True).start()
    get_drives()
    quick_scan_path = "storage/data/quickpath.txt"
    if os.path.exists(quick_scan_path):
        with open(quick_scan_path, 'r') as file:
            scanned = {line.strip() for line in file}
        for file in scanned:
            quickpath.add(file)
            scan_directory(file, quickfiles)
    content_container = ft.Container(content=HomeView(page, compiled_rule, quickfiles,quickpath), expand=True)
    def change_page(index):
        if index == 0:
            new_view = HomeView(page,compiled_rule,quickfiles,quickpath)
        elif index == 1:
            new_view = ScanView(page,compiled_rule,quickfiles,quickpath,deepfiles)
        elif index == 2:
            new_view = ProtectionView(page)
        else:
            new_view = SettingsView(page,quickpath,quickfiles)
        content_container.content = new_view
        page.update()
    navigation_rail = ft.NavigationRail(
        selected_index=0,bgcolor=ft.Colors.BLUE_GREY_900,
        destinations=[ft.NavigationRailDestination(icon=ft.Icon(ft.Icons.HOME_OUTLINED, size=90),selected_icon=ft.Icon(ft.Icons.HOME, size=90),label_content=ft.Text("Home", size=20)),
            ft.NavigationRailDestination(icon=ft.Icon(ft.Icons.SEARCH, size=90),selected_icon=ft.Icon(ft.Icons.SEARCH, size=90),label_content=ft.Text("Scan", size=20)),
            ft.NavigationRailDestination(icon=ft.Icon(ft.Icons.SHIELD_OUTLINED, size=90),selected_icon=ft.Icon(ft.Icons.SHIELD, size=90),label_content=ft.Text("Protection", size=20)),
            ft.NavigationRailDestination(icon=ft.Icon(ft.Icons.SETTINGS_OUTLINED, size=90),selected_icon=ft.Icon(ft.Icons.SETTINGS, size=90),label_content=ft.Text("Settings", size=20)),],
        expand=True,on_change=lambda e: change_page(e.control.selected_index)
    )
    return ft.View(
        route="/home",
        controls=[
            ft.Row([
                ft.Container(navigation_rail, expand=False, width=120),  
                content_container  
            ], expand=True)],
        spacing=0,padding=0
    )