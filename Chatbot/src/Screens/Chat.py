import flet as ft
import sqlite3 as sql
conn = sql.connect("chatbot.db", check_same_thread=False)
cur = conn.cursor()
import re
import ast
import operator
from word2number import w2n  
operators = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.USub: operator.neg
}
operator_words = {
    "plus": "+",
    "minus": "-",
    "times": "*",
    "multiplied by": "*",
    "divided by": "/",
    "over": "/",
    "power": "**"
}
def replace_operator_words(text):
    for word, symbol in operator_words.items():
        text = re.sub(rf"\b{word}\b", f" {symbol} ", text)
    return text
def convert_words_to_numbers(text):
    tokens = text.lower().split()
    converted = []
    for token in tokens:
        try:
            converted.append(str(w2n.word_to_num(token)))
        except:
            converted.append(token)
    return " ".join(converted)
def safe_eval(expr):
    def _eval(node):
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        elif isinstance(node, ast.Constant):  
            return node.value
        elif isinstance(node, ast.BinOp):
            return operators[type(node.op)](_eval(node.left), _eval(node.right))
        elif isinstance(node, ast.UnaryOp):
            return operators[type(node.op)](_eval(node.operand))
        else:
            raise ValueError("Unsupported expression")
    node = ast.parse(expr, mode='eval')
    return _eval(node.body)
def get_bot_response(message):
    message = message.lower().strip()
    try:
        original = message
        message = replace_operator_words(message)
        message = convert_words_to_numbers(message)
        if re.fullmatch(r"[0-9\.\+\-\*\/\(\)\s\**]+", message):
            result = safe_eval(message)
            return f"The result is: {result}"
    except Exception as e:
        return f"I couldn't evaluate that expression: {e}"
    cur.execute("SELECT response FROM chatbot_data WHERE keyword = ?", (original.capitalize(),))
    result = cur.fetchone()
    if result:
        return result[0]
    cur.execute("SELECT response FROM chatbot_data WHERE ? LIKE '%' || keyword || '%'", (original,))
    result = cur.fetchone()
    return result[0] if result else "I'm not sure how to respond to that."
def Chatting(page: ft.Page, email, username):
    page.title = "Chatbot"
    page.scroll = ft.ScrollMode.ADAPTIVE
    messages = ft.ListView(
        expand=True,
        spacing=10,
        padding=20,
        auto_scroll=True,
    )
    input_field = ft.TextField(
        hint_text="Type a message...",
        expand=True,
        autofocus=True,
        on_submit=lambda e: send_message(e.control.value)
    )
    def send_message(text):
        if not text.strip():
            return
        messages.controls.append(
            ft.Row(
                [
                    ft.Container(
                        content=ft.Text(text),
                        padding=10,
                        border_radius=ft.border_radius.all(10),
                        bgcolor=ft.Colors.GREEN_900,
                        border=ft.border.all(2, ft.Colors.GREEN_900),
                    )
                ],
                alignment=ft.MainAxisAlignment.END,
            )
        )
        bot_reply = get_bot_response(text)
        messages.controls.append(
            ft.Row(
                [
                    ft.Container(
                        content=ft.Text(bot_reply),
                        padding=10,
                        border_radius=ft.border_radius.all(10),
                        bgcolor=ft.Colors.BLUE_900,
                        border=ft.border.all(2, ft.Colors.BLUE_900),
                    )
                ],
                alignment=ft.MainAxisAlignment.START,
            )
        )
        input_field.value = ""
        input_field.focus()
        page.update()
    send_button = ft.IconButton(icon=ft.Icons.SEND, on_click=lambda e: send_message(input_field.value))
    chat_ui = ft.Container(
        content=ft.Column([
            ft.Container(messages, expand=True),
            ft.Row([input_field, send_button]),
        ], expand=True),
        expand=True,
        padding=10
    )
    page.appbar = ft.AppBar(title=ft.Text("Chatbot"), adaptive=True)
    return ft.View(route="/chat", controls=[chat_ui], appbar=page.appbar, adaptive=True)