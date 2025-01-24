import flet as ft
import os
def create_title_bar(page: ft.Page):
    if os.name == "nt":  
        icon_path = os.path.abspath("Major_Project/icon.ico")
    else:  
        icon_path = os.path.abspath("Major_Project/icon.png")
    if not os.path.exists(icon_path):
        icon_path = None
    def minimize_win(e):
        page.window.minimized = True
        page.update()
    def close_win(e):
        page.window.close()
    return ft.WindowDragArea(
        ft.Container(
            content=ft.Row(
                [
                    ft.Row(
                        [
                            ft.Image(src=icon_path, width=20, height=20) if icon_path else ft.Container(),
                            ft.Text("Kepler Antivirus", size=15),
                        ]
                    ),
                    ft.Container(
                        content=ft.Row(
                            [
                                ft.IconButton(ft.Icons.MINIMIZE, on_click=minimize_win),
                                ft.IconButton(ft.Icons.CLOSE, on_click=close_win),
                            ]
                        )
                    ),
                ],
                alignment="spaceBetween",
            ),
        )
    )
def create_nav_bar(page, active):
    def create_destination(outlined_icon,icon, text, button_name, route):
        return ft.NavigationRailDestination(
            icon=ft.Icon(name=outlined_icon,size=100),
            selected_icon=ft.Icon(name=icon, color=ft.Colors.WHITE,size=100),
            label_content=ft.Text(value=text,size=20)
        )
    rail_destinations = [
        create_destination(ft.Icons.HOME_OUTLINED,ft.Icons.HOME, "Home", "Home", "/home"),
        create_destination(ft.Icons.SEARCH,ft.Icons.SEARCH, "Scan", "Scan", "/scan"),
        create_destination(ft.Icons.SHIELD_OUTLINED,ft.Icons.SHIELD, "Protection", "Protection", "/protection"),
        create_destination(ft.Icons.SETTINGS_OUTLINED,ft.Icons.SETTINGS, "Settings", "Settings", "/settings"),
    ]
    def on_rail_change(e):
        routes = ["/home", "/scan", "/protection", "/settings"]
        selected_index = e.control.selected_index
        if routes[selected_index] != page.route:
            page.go(routes[selected_index])
    return ft.Container(
        content=ft.NavigationRail(
            min_width=150,
            group_alignment=-0.4,
            indicator_color=ft.Colors.BLUE_700,
            selected_index=["Home", "Scan", "Protection", "Settings"].index(active),
            destinations=rail_destinations,
            on_change=on_rail_change,
            extended=False,
            label_type=ft.NavigationRailLabelType.ALL,
            bgcolor=ft.Colors.BLUE_800,
        ),
        bgcolor=ft.Colors.BLUE_800,
    )
def create_floating_button():
    return ft.FloatingActionButton(icon=ft.Icons.SUPPORT_AGENT)
def create_custom_button(label, description,w,h,icon=None,on_click=None):
    return ft.TextButton(
        content=ft.Row(
            [
                ft.Container(
                    content=ft.Icon(icon,size=100),
                    alignment=ft.alignment.center_left,
                    width=100,
                ),
                ft.Column(
                    [
                        ft.Text(value=label, size=30),
                        ft.Text(value=description),
                    ],
                    alignment=ft.MainAxisAlignment.START,
                ),
            ],
            alignment=ft.MainAxisAlignment.START,
        ),
        on_click=on_click,
        width=w,
        height=h,
        style=ft.ButtonStyle(
            shape=ft.RoundedRectangleBorder(radius=8),
            alignment=ft.alignment.center,
        )
    )
