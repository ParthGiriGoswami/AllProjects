import flet as ft
from Screen.scan import Scan
scanned=set()
def HomeView(page: ft.Page,rule,files):
    btn1 = ft.ElevatedButton(
        "Quick scan",
        on_click=lambda _:Scan(page,files,rule,False)
    )
    return ft.Container(
        expand=True,
        padding=10,
        content=ft.Column(
            [
                ft.Row([ft.Icon(name=ft.Icons.INFO_OUTLINED, size=200)], alignment=ft.MainAxisAlignment.CENTER),
                ft.Row([ft.Text(value="Perform a scan", size=20)], alignment=ft.MainAxisAlignment.CENTER),
                ft.Row([btn1], alignment=ft.MainAxisAlignment.CENTER)
            ],
            spacing=10,expand=True,alignment=ft.MainAxisAlignment.CENTER
        ),)