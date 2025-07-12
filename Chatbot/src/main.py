import flet as ft
import sqlite3 as sql
from Screens.Login import LoginPage, SignUpPage
from Screens.Chat import Chatting

# Initialize SQLite and user list
conn = sql.connect("data.db", check_same_thread=False)
conn.execute('''CREATE TABLE IF NOT EXISTS chat(email TEXT PRIMARY KEY, username TEXT)''')
cur = conn.cursor()

existing_users = []

def refresh_existing_users():
    existing_users.clear()
    cur.execute("SELECT * FROM chat")
    for row in cur.fetchall():
        existing_users.append([row[0], row[1]])

def main(page: ft.Page):
    page.title = "Chatting App"
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER

    def route_change(route):
        page.views.clear()
        if page.route == "/loginpage":
            view = LoginPage(page)
            page.views.append(view)

        elif page.route == "/signuppage":
            view = SignUpPage(page)
            page.views.append(view)

        elif page.route == "/chat":
            refresh_existing_users()
            if existing_users:
                view = Chatting(page, existing_users[0][0], existing_users[0][1])
                page.views.append(view)
            else:
                page.go("/loginpage")
                return

        page.update()

    def view_pop(view):
        if len(page.views) > 1:
            page.views.pop()
            top_view = page.views[-1]
            page.go(top_view.route)
        else:
            page.go("/loginpage")

    # Assign handlers
    page.on_route_change = route_change
    page.on_view_pop = view_pop

    # Start app based on user existence
    refresh_existing_users()
    if existing_users:
        page.go("/chat")
    else:
        page.go("/loginpage")

ft.app(target=main)
