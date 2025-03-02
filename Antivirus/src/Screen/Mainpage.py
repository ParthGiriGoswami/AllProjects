import flet as ft
from Screen.Protectionview import ProtectionView
from Screen.Settingsview import SettingsView
from Screen.Scanview import ScanView
from Screen.Homeview import HomeView
import yara,psutil,threading,os,time
from Screen.PendriveDetection import list_connected_devices
from concurrent.futures import ThreadPoolExecutor
file_lock = threading.Lock()  
count=0
files=set()
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
def get_drives(page):
    global count,files
    if count == 0:
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
        max_workers = 1000
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            list(executor.map(scan_drive, drive_letters))
        count=1
def MainPage(page: ft.Page):
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
    def device_monitor():
        while True:
            list_connected_devices(compiled_rule)
            time.sleep(1)
    threading.Thread(target=device_monitor, daemon=True).start()
    get_drives(page)
    def change_page(index):
        if index == 0:
            new_view= HomeView(page,compiled_rule,files)
        elif index==1:
            new_view=ScanView(page,compiled_rule,files)
        elif index==2:
            new_view=ProtectionView(page)
        else:
            new_view=SettingsView(page)
        content_container.content = new_view
        page.update()
    page.navigation_bar = ft.NavigationBar(
        destinations=[
            ft.NavigationBarDestination(icon=ft.Icons.HOME_OUTLINED, selected_icon=ft.Icons.HOME, label="Home"),
            ft.NavigationBarDestination(icon=ft.Icons.SEARCH, selected_icon=ft.Icons.SEARCH, label="Scan"),
            ft.NavigationBarDestination(icon=ft.Icons.SHIELD_OUTLINED, selected_icon=ft.Icons.SHIELD, label="Protection"),
            ft.NavigationBarDestination(icon=ft.Icons.SETTINGS_OUTLINED, selected_icon=ft.Icons.SETTINGS, label="Settings"),
        ],
        adaptive=True,
        on_change=lambda e: change_page(e.control.selected_index)
    )
    content_container = ft.Container(content=HomeView(page,compiled_rule,files), expand=True, adaptive=True)
    return ft.View(
        route="/home",
        controls=[ft.Row(
            controls=[content_container],
            expand=True,
            spacing=0,
        )],
        navigation_bar=page.navigation_bar,
        spacing=0,
        padding=0
    )