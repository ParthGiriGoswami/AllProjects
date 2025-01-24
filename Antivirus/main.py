import flet as ft
import threading, time, os
from Screens.MainScreen import main_screen, get_drives, get_count
from Screens.ScanScreen import scans
from Screens.ProtectionScreen import protection
from Screens.SettingScreen import setting
from Screens.ScanFileScreen import quickscan, deepscan, get_malware_count, scan_drives, result, customscan
from Screens.PendriveDetection import list_connected_devices
import screeninfo
files = set()
mal = set()
scanned = set()
from_route = ""
count = 0
def device_monitor():
    while True:
        list_connected_devices()
        time.sleep(1)
def main(page: ft.Page):
    screen = screeninfo.get_monitors()[0]
    page.title = "Kepler Antivirus"
    page.window.frameless = True
    page.window.left = screen.width / 16
    page.window.top = screen.height / 16
    page.theme_mode = "dark"
    if os.name == "nt":
        icon_path = os.path.abspath("Major_Project/icon.ico")
    else:
        icon_path = os.path.abspath("Major_Project/icon.png")
    if not os.path.exists(icon_path):
        icon_path = None
    page.window.icon = icon_path
    threading.Thread(target=device_monitor, daemon=True).start()
    def handle_home():
        global scanned, files, count
        view, txt, scanned = main_screen(page)
        page.views.append(view)
        get_drives(page, txt)
        count, files = get_count()
    def handle_scan():
        global scanned
        view, scanned = scans(page)
        page.views.append(view)
    def handle_protection():
        page.views.append(protection(page))
    def handle_settings():
        page.views.append(setting(page))
    def handle_quickscan():
        global mal, from_route
        from_route = page.route.split("from=")[1] if "from=" in page.route else "/home"
        view, txt, info, compiled_rule, malware_count, progress_ring, scanfile = quickscan(page, len(scanned), scanned)
        page.views.append(view)
        scan_drives(page, txt, info, len(scanfile), scanfile, progress_ring, malware_count, compiled_rule)
        mal = get_malware_count()
    def handle_deepscan():
        global mal, from_route
        from_route = page.route.split("from=")[1] if "from=" in page.route else "/home"
        view, txt, info, compiled_rule, malware_count, progress_ring = deepscan(page, count, files)
        page.views.append(view)
        scan_drives(page, txt, info, count, files, progress_ring, malware_count, compiled_rule)
        mal = get_malware_count()
    def handle_results():
        page.views.append(result(page, mal, previous_route=f"{from_route}"))
    def handle_customscan():
        view, txt, info, compiled_rule, malware_count, progress_ring = customscan(page, scanned)
        page.views.append(view)
        scan_drives(page, txt, info, len(scanned), scanned, progress_ring, malware_count, compiled_rule)
    route_handlers = {
        "/home": handle_home,
        "/scan": handle_scan,
        "/protection": handle_protection,
        "/settings": handle_settings,
        "/quickscan": handle_quickscan,
        "/deepscan": handle_deepscan,
        "/results": handle_results,
        "/customscan": handle_customscan,
    }
    def route_change(route_event):
        page.views.clear()
        route_path = route_event.route.split("?")[0]  
        handler = route_handlers.get(route_path)
        if handler:
            handler()
        page.update()
    def view_pop(view):
        page.views.pop()
        top_view = page.views[-1]
        page.go(top_view.route)
    page.on_route_change = route_change
    page.on_view_pop = view_pop
    page.go("/home")
ft.app(target=main)