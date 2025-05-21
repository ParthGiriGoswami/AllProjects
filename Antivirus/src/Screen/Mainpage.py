import flet as ft,yara,psutil,threading,os,time,platform
from Screen.Protectionview import ProtectionView
from Screen.Settingsview import SettingsView
from Screen.Scanview import ScanView
from Screen.Homeview import HomeView
from Screen.Notifier import list_connected_devices,DownloadHandler
from concurrent.futures import ThreadPoolExecutor
from Screen.ScanDir import scan_directory
from watchdog.observers import Observer
file_lock = threading.Lock()  
files=set()
SAFE_PATHS = [os.path.abspath(p) for p in ["C:/Windows","C:/Program Files","C:/Program Files (x86)"]]
def is_in_safe_path(file_path):
    file_path = os.path.abspath(file_path)
    return any(file_path.startswith(safe) for safe in SAFE_PATHS)
def get_drives(file):
    partitions = psutil.disk_partitions()
    drive_letters = [partition.device for partition in partitions if partition.fstype]
    def scan_drive(drive):
        local_files = set()
        local_files=scan_directory(drive, local_files)
        with file_lock:
            file.update(local_files)
        return len(local_files)
    max_workers = min(len(drive_letters), os.cpu_count())
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.map(scan_drive, drive_letters))
def MainPage(page: ft.Page):
    global files
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
    def get_download_dir():
        if platform.system() == "Windows":
            return os.path.join(os.environ["USERPROFILE"], "Downloads")
        elif platform.system() == "Darwin":
            return os.path.join(os.environ["HOME"], "Downloads")
        else:  
            return os.path.join(os.environ["HOME"], "Downloads")
    DOWNLOADS_DIR = get_download_dir()
    def download_monitor(page):
        event_handler=DownloadHandler(page,compiled_rule)
        observer = Observer()
        observer.schedule(event_handler, path=DOWNLOADS_DIR, recursive=False)
        observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join() 
    def new_files(files):
        while True:
            time.sleep(240)
            new_files=set()
            new_files=get_drives(new_files)
            if(files != new_files):
                files=new_files
    def device_monitor(page):
        while True:
            list_connected_devices(page,compiled_rule)
            time.sleep(1)
    def drive_monitor():
        global files
        while True:
            time.sleep(240)
            temp_files = set()
            get_drives(temp_files)
            with file_lock:
                if temp_files != files:
                    files.clear()
                    files.update(temp_files)
    threading.Thread(target=device_monitor,args=(page,) ,daemon=True).start()
    threading.Thread(target=download_monitor, args=(page,), daemon=True).start()
    files.clear()
    get_drives(files)
    if len(files)!=0:
        threading.Thread(target=drive_monitor, daemon=True).start()
    content_container = ft.Container(content=HomeView(page, compiled_rule,files), expand=True)
    def change_page(index):
        if index == 0:
            new_view = HomeView(page,compiled_rule,files)
        elif index == 1:
            new_view = ScanView(page,compiled_rule,files)
        elif index == 2:
            new_view = ProtectionView(page)
        else:
            new_view = SettingsView(page)
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