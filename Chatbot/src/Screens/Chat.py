import flet as ft
import re, ast, operator, torch, requests
from word2number import w2n
from transformers import AutoTokenizer, AutoModelForCausalLM

# ----- Math Expression Support -----
operators = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.USub: operator.neg
}

operator_words = {
    "plus": "+", "minus": "-", "times": "*",
    "multiplied by": "*", "divided by": "/",
    "over": "/", "power": "**"
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

# ----- Weather Support -----
def detect_city() -> tuple[str, str] | None:
    try:
        response = requests.get("http://ip-api.com/json/")
        data = response.json()
        city = data.get("city")
        country_code = data.get("countryCode")  # e.g., 'IN', 'US'
        return (city, country_code) if city and country_code else None
    except Exception:
        return None

def get_weather(city: str = None) -> str:
    API_KEY = "0dc1ce7a2610d1c843803cef3319bbf1"  # Replace with your valid key
    if not city:
        city_code = detect_city()
        city = f"{city_code[0]},{city_code[1]}"
        if not city:
            return "Couldn't detect your city. Please mention it."
    try:
        url = f"https://api.openweathermap.org/data/2.5/weather?q={city}&appid={API_KEY}&units=metric"
        response = requests.get(url)
        data = response.json()
        print(data)
        if data["cod"] != 200:
            return f"Couldn't find weather for '{city}'. Try another city."
        temp = data["main"]["temp"]
        desc = data["weather"][0]["description"].capitalize()
        humidity = data["main"]["humidity"]
        wind = data["wind"]["speed"]
        return (
            f"🌤️ Weather in {city.title()}:\n"
            f"Temperature: {temp}°C\n"
            f"Condition: {desc}\n"
            f"Humidity: {humidity}%\n"
            f"Wind: {wind} m/s"
        )
    except Exception as e:
        return f"⚠️ Failed to fetch weather: {e}"

# ----- Load Model -----
tokenizer = AutoTokenizer.from_pretrained("microsoft/DialoGPT-large")
model = AutoModelForCausalLM.from_pretrained("microsoft/DialoGPT-large")
chat_history_ids = None

# ----- Bot Logic -----
def get_bot_response(message: str) -> str:
    global chat_history_ids

    msg = message.lower().strip()

    # Check for math expressions
    try:
        original = msg
        msg = replace_operator_words(msg)
        msg = convert_words_to_numbers(msg)
        if re.fullmatch(r"[0-9\.\+\-\*\/\(\)\s\**]+", msg):
            result = safe_eval(msg)
            return f"The result is: {result}"
    except Exception as e:
        pass  # fall back to chat if math fails

    # Check for weather
    if any(word in msg for word in ["weather", "temperature", "forecast"]):
        match = re.search(r"(in|at)\s+([a-zA-Z]+)", msg)
        city = match.group(2) if match else None
        return get_weather(city)

    # Chat with DialoGPT
    new_user_input_ids = tokenizer.encode(message + tokenizer.eos_token, return_tensors='pt')
    if chat_history_ids is not None:
        bot_input_ids = torch.cat([chat_history_ids, new_user_input_ids], dim=-1)
    else:
        bot_input_ids = new_user_input_ids

    attention_mask = torch.ones_like(bot_input_ids)

    chat_history_ids = model.generate(
        bot_input_ids,
        max_length=1000,
        pad_token_id=tokenizer.eos_token_id,
        attention_mask=attention_mask,
        do_sample=True,
        temperature=0.7,
        top_k=50,
        top_p=0.95
    )

    response = tokenizer.decode(chat_history_ids[:, bot_input_ids.shape[-1]:][0], skip_special_tokens=True)
    return response.strip() if response else "Hmm... I couldn't come up with a response."

# ----- Flet UI -----
def Chatting(page: ft.Page, email=None, username=None):
    page.title = "Chatbot"
    page.scroll = ft.ScrollMode.ADAPTIVE

    messages = ft.ListView(expand=True, spacing=10, padding=20, auto_scroll=True)

    input_field = ft.TextField(
        hint_text="Type a message...",
        expand=True,
        autofocus=True,
        on_submit=lambda e: send_message(e.control.value)
    )

    def send_message(text):
        if not text.strip():
            return

        # User message
        messages.controls.append(
            ft.Row([
                ft.Container(
                    content=ft.Text(text),
                    padding=10,
                    border_radius=ft.border_radius.all(10),
                    bgcolor=ft.Colors.GREEN_900,
                    border=ft.border.all(2, ft.Colors.GREEN_800)
                )
            ], alignment=ft.MainAxisAlignment.END)
        )

        # Bot response
        bot_reply = get_bot_response(text)
        messages.controls.append(
            ft.Row([
                ft.Container(
                    content=ft.Text(bot_reply),
                    padding=10,
                    border_radius=ft.border_radius.all(10),
                    bgcolor=ft.Colors.BLUE_900,
                    border=ft.border.all(2, ft.Colors.BLUE_800)
                )
            ], alignment=ft.MainAxisAlignment.START)
        )

        input_field.value = ""
        input_field.focus()
        page.update()

    send_button = ft.IconButton(
        icon=ft.Icons.SEND,
        on_click=lambda e: send_message(input_field.value)
    )

    chat_ui = ft.Container(
        content=ft.Column([
            ft.Container(messages, expand=True),
            ft.Row([input_field, send_button])
        ], expand=True),
        expand=True,
        padding=10
    )

    page.appbar = ft.AppBar(title=ft.Text("Chatbot"), adaptive=True)
    return ft.View(route="/chat", controls=[chat_ui], appbar=page.appbar, adaptive=True)
