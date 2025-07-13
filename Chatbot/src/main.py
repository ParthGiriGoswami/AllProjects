import flet as ft
from Screens.Chat import Chatting
def main(page: ft.Page):
    page.title = "Chatting App"
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    def route_change(route):
        page.views.clear()
        if page.route == "/chat":
            view = Chatting(page)
            page.views.append(view)
        page.update()
    def view_pop(view):
        if len(page.views) > 1:
            page.views.pop()
            top_view = page.views[-1]
            page.go(top_view.route)
    page.on_route_change = route_change
    page.on_view_pop = view_pop
    page.go("/chat")
ft.app(target=main)