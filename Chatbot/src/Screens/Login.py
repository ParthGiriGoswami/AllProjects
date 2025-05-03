import flet as ft
import smtplib
import random
import firebase_admin
from firebase_admin import credentials,db
import sqlite3 as sql
conn = sql.connect("data.db",check_same_thread=False)
conn.execute('''CREATE TABLE IF NOT EXISTS chat(email TEXT PRIMARY KEY, username text)''')
cur=conn.cursor()
if not firebase_admin._apps:
    cred = credentials.Certificate('cred.json')  
    firebase_admin.initialize_app(cred, {'databaseURL': "https://yourdb.firebaseio.com/"})
users_ref = db.reference('users')
def sendemail(email):
    s = smtplib.SMTP("smtp.gmail.com", 587)  
    s.starttls()
    s.login("email","password")
    otp = random.randint(1000, 9999)
    msg="Your otp is "+str(otp)
    s.sendmail("s9174213@gmail.com",email,msg)
    return otp
def VerifySignup(page,name ,email, password, confirmpassword):
    def handle_close(e):
        page.close(dlg)
    dlg=None
    if not email or not password or not confirmpassword:
        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("Error"),
            content=ft.Text("All fields are required"),
            actions=[
                ft.TextButton("Ok", on_click=handle_close),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )
    elif not email.endswith("@gmail.com"):
        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("Error"),
            content=ft.Text("Email should end with @gmail.com"),
            actions=[
                ft.TextButton("Ok", on_click=handle_close),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )
    elif password != confirmpassword:
        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("Error"),
            content=ft.Text("Password do not match"),
            actions=[
                ft.TextButton("Ok", on_click=handle_close),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )
    else:
        code=ft.TextField(label="Enter the code we have send to your email id")
        def verify_code(e):
            if code.value==str(otp):
                users_ref.push({"Email":email,"Password":password,"Name":name})
                page.go("/loginpage")
            else:
                code.error_text="Incorrect code"
                page.update()
        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("Code"),
            content=code,
            actions=[
                ft.TextButton("Ok", on_click=verify_code),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        otp=sendemail(email)
    page.open(dlg)
def SignUpPage(page: ft.Page):
    name=ft.TextField(label="Name")
    email=ft.TextField(label="Email Id")
    password=ft.TextField(label="Password", password=True, can_reveal_password=True)
    confirmpassword=ft.TextField(label="Confirm Password", password=True, can_reveal_password=True)
    return ft.View(
        route="/signuppage",
        controls=[
            ft.Row(
                controls=[
                    ft.Card(
                        content=ft.Container(
                            content=ft.Column(
                                [
                                    name,
                                    email,
                                    password,
                                    confirmpassword,
                                    ft.ElevatedButton(
                                        text="Signup",
                                        color=ft.Colors.WHITE,
                                        bgcolor=ft.Colors.BLUE_700,
                                        width=300,
                                        on_click=lambda _: VerifySignup(page,name.value,email.value,password.value,confirmpassword.value)
                                    )
                                ],
                                alignment=ft.MainAxisAlignment.CENTER,
                                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                                spacing=30,
                            ),
                            padding=30,
                            width=300,
                            alignment=ft.alignment.center,
                        )
                    )
                ],
                alignment=ft.MainAxisAlignment.CENTER  
            )
        ],
        vertical_alignment=ft.MainAxisAlignment.CENTER  
    )
def VerifyLogin(page, email, password):
    def handle_close(e):
        page.close(dlg)
    dlg = None  
    if not email or not password:
        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("Error"),
            content=ft.Text("All fields are required"),
            actions=[ft.TextButton("Ok", on_click=handle_close)],
            actions_alignment=ft.MainAxisAlignment.END,
        )
    elif not email.endswith("@gmail.com"):
        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("Error"),
            content=ft.Text("Email should end with @gmail.com"),
            actions=[ft.TextButton("Ok", on_click=handle_close)],
            actions_alignment=ft.MainAxisAlignment.END,
        )
    else:
        users = users_ref.get()
        if users:
            for key, value in users.items():
                if value.get('Email') == email and value.get('Password') == password:
                    cur.execute("INSERT OR REPLACE INTO chat (email, username) VALUES (?, ?)", (email, value.get('Name')))
                    conn.commit()
                    page.go("/chat")
                    return  
        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("Error"),
            content=ft.Text("Invalid email or password"),
            actions=[ft.TextButton("Ok", on_click=handle_close)],
            actions_alignment=ft.MainAxisAlignment.END,
        )

    if dlg:  
        page.open(dlg)
def ForgotPassword(page, email):
    def handle_close(e):
        page.close(dlg)
    if not email:
        dlg = ft.AlertDialog(title=ft.Text("Error"), content=ft.Text("Enter email to proceed"),
                             actions=[ft.TextButton("Ok", on_click=handle_close)])
    else:
        code = ft.TextField(label="Enter OTP sent to your email")

        def verify_code(e):
            if code.value == str(otp):
                new_password = ft.TextField(label="Enter new password")

                def update_password(e):
                    for key, value in users_ref.get().items():
                        if value.get('Email') == email:
                            users_ref.child(key).update({"Password": new_password.value})  
                            page.close(dlg)

                dlg.content = new_password
                dlg.actions = [ft.TextButton("Update Password", on_click=update_password)]
                page.update()
            else:
                code.error_text = "Incorrect OTP"
                page.update()
        otp = sendemail(email)
        dlg = ft.AlertDialog(title=ft.Text("OTP Verification"), content=code,
                             actions=[ft.TextButton("Verify", on_click=verify_code)])
    page.open(dlg)
def LoginPage(page: ft.Page):
    email=ft.TextField(label="Email Id")
    password=ft.TextField(label="Password", password=True, can_reveal_password=True)
    return ft.View(
        route="/loginpage",
        controls=[
            ft.Row(
                controls=[
                    ft.Card(
                        content=ft.Container(
                            content=ft.Column(
                                [
                                    email,
                                    password,
                                    ft.ElevatedButton(
                                        text="Login",
                                        color=ft.Colors.WHITE,
                                        bgcolor=ft.Colors.BLUE_700,
                                        width=300,
                                        on_click=lambda _: VerifyLogin(page,email.value,password.value)
                                    ),
                                    ft.Text(
                                        spans=[
                                            ft.TextSpan(
                                                "Forgotten Password?",
                                                ft.TextStyle(decoration=ft.TextDecoration.UNDERLINE, color=ft.Colors.BLUE_400),
                                                on_click=lambda _: ForgotPassword(page,email.value)
                                            ),
                                        ]
                                    ),
                                    ft.OutlinedButton(text="Create a new account", width=400,on_click= lambda _:page.go("/signuppage"))
                                ],
                                alignment=ft.MainAxisAlignment.CENTER,
                                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                                spacing=30,
                            ),
                            padding=30,
                            width=300,
                            alignment=ft.alignment.center,
                        )
                    )
                ],
                alignment=ft.MainAxisAlignment.CENTER  
            )
        ],
        vertical_alignment=ft.MainAxisAlignment.CENTER  
    )