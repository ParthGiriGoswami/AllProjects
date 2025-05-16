import flet as ft
import os
from Screen.Mainpage import MainPage
def main(page: ft.Page):
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    if os.name == "nt":
        icon_path = os.path.abspath("icon.ico")
    else:
        icon_path = os.path.abspath("icon.png")
    if not os.path.exists(icon_path):
        icon_path = None
    page.window.icon = icon_path
    page.title = "Kepler Antivirus"
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    def route_change(route):
        page.views.clear()  
        if page.route == "/home":
            view=MainPage(page)
            page.views.append(view)
        page.update()
    page.on_route_change = route_change
    page.go("/home")
ft.app(target=main)