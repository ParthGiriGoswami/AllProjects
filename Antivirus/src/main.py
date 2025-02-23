import flet as ft
import time,threading,os
from Screen.Mainpage import MainPage
from Screen.PendriveDetection import list_connected_devices
def device_monitor():
    while True:
        list_connected_devices()
        time.sleep(1)
def main(page: ft.Page):
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    threading.Thread(target=device_monitor, daemon=True).start()
    if os.name == "nt":
        icon_path = os.path.abspath("icon.ico")
    else:
        icon_path = os.path.abspath("icon.png")
    if not os.path.exists(icon_path):
        icon_path = None
    page.window.icon = icon_path
    page.title = "Antivirus"
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    def route_change(route):
        page.views.clear()  
        if page.route == "/home":
            view=MainPage(page)
            page.views.append(view)
        page.update()
    def view_pop(view):
        page.views.pop()
        top_view = page.views[-1]
        page.go(top_view.route)
    page.on_route_change = route_change
    page.on_view_pop = view_pop
    page.go("/home")
ft.app(target=main)