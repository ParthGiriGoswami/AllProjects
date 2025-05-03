import flet as ft
from Screens.Login import LoginPage, SignUpPage
from Screens.Chat import Chatting
import sqlite3 as sql
existing_users=[]
conn = sql.connect("data.db",check_same_thread=False)
conn.execute('''CREATE TABLE IF NOT EXISTS chat(email TEXT PRIMARY KEY, username text)''')
cur=conn.cursor()
cur.execute("Select * from chat")
rows=cur.fetchall()
for row in rows:
    existing_users.append([row[0],row[1]])
def main(page: ft.Page):
    page.title = "Chatting App"
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    def route_change(route):
        page.views.clear()  
        if page.route == "/loginpage":
            view=LoginPage(page)
            page.views.append(view)
        elif page.route=="/signuppage":
            view=SignUpPage(page)
            page.views.append(view)
        elif page.route=="/chat":
            cur.execute("Select * from chat")
            rows=cur.fetchall()
            for row in rows:
                existing_users.append([row[0],row[1]])
            view=Chatting(page,existing_users[0][0],existing_users[0][1])
            page.views.append(view)
        page.update()
    def view_pop(view):
        page.views.pop()
        top_view = page.views[-1]
        page.go(top_view.route)
    page.on_route_change = route_change
    page.on_view_pop = view_pop
    if existing_users==[]:
        page.go("/loginpage")
    else:
        page.go("/chat")
ft.app(target=main)