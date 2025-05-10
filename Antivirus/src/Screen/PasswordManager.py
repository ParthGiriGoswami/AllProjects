import flet as ft
import re
import json
import os
def passwordmanager(page: ft.Page):
    def close_bs(e):
        bs.open = False
        page.update()
    def add_new_password(e):
        form.visible = not form.visible
        add_button.icon = ft.Icons.REMOVE if form.visible else ft.Icons.ADD
        cont.height = 300 if form.visible else 500
        page.update()
    def is_site_format_valid(site_value):
        pattern = r"^(http:\/\/|https:\/\/)?[a-zA-Z0-9]*(\.com)$"
        return not site_value or re.match(pattern, site_value.strip())
    def validate_site(e):
        site.error_text = "Invalid site format" if not is_site_format_valid(site.value) else None
        enable_disable_save_button()
        page.update()
    def on_change(e):
        enable_disable_save_button()
        page.update()
    def save_password(e):
        site_key = site.value.strip()
        new_entry = {"username": username.value, "password": password.value}
        
        if os.path.exists("storage/data/passwords.json"):
            with open("storage/data/passwords.json", "r") as f:
                try:
                    all_data = json.load(f)
                except json.JSONDecodeError:
                    all_data = {}
        else:
            all_data = {}
        if site_key in all_data:
            all_data[site_key].append(new_entry)
        else:
            all_data[site_key] = [new_entry]
        with open("storage/data/passwords.json", "w") as f:
            json.dump(all_data, f, indent=4)
        site.value = ""
        username.value = ""
        password.value = ""
        load_passwords_view()
        page.update()
    def enable_disable_save_button():
        save_button.disabled = not (
            site.value and username.value and password.value and is_site_format_valid(site.value)
        )
    def load_passwords_view():
        def create_credential_row(entry, site_name, entry_index):
            original_username = entry["username"]
            original_password = entry["password"]

            user = ft.TextField(
                label="Username",
                value=original_username,
                read_only=True,
                suffix=ft.IconButton(
                    icon=ft.Icons.CONTENT_COPY,
                    on_click=lambda e: page.set_clipboard(user.value),
                    icon_size=18,
                    style=ft.ButtonStyle(padding=0),
                ),
            )
            passw = ft.TextField(
                label="Password",
                value=original_password,
                read_only=True,
                password=True,
                can_reveal_password=True,
                suffix=ft.IconButton(
                    icon=ft.Icons.CONTENT_COPY,
                    tooltip="Copy Password",
                    on_click=lambda e: page.set_clipboard(passw.value),
                    icon_size=18,
                    style=ft.ButtonStyle(padding=0),
                ),
            )
            def cancel_edit(e):
                user.value = original_username
                passw.value = original_password
                toggle_edit(e)
            def save_edit(e):
                if os.path.exists("storage/data/passwords.json"):
                    with open("storage/data/passwords.json", "r") as f:
                        try:
                            all_data = json.load(f)
                        except json.JSONDecodeError:
                            all_data = {}
                else:
                    all_data = {}
                if site_name in all_data and len(all_data[site_name]) > entry_index:
                    all_data[site_name][entry_index]["username"] = user.value
                    all_data[site_name][entry_index]["password"] = passw.value
                    with open("storage/data/passwords.json", "w") as f:
                        json.dump(all_data, f, indent=4)
                toggle_edit(e)
            def toggle_edit(e):
                is_editing = user.read_only
                user.read_only = not is_editing
                passw.read_only = not is_editing
                edit_btn.text = "Save" if is_editing else "Edit"
                del_btn.text = "Cancel" if is_editing else "Delete"
                edit_btn.on_click = save_edit if is_editing else toggle_edit
                del_btn.on_click = cancel_edit if is_editing else delete_entry
                page.update()
            def delete_entry(e):
                if os.path.exists("storage/data/passwords.json"):
                    with open("storage/data/passwords.json", "r") as f:
                        try:
                            all_data = json.load(f)
                        except json.JSONDecodeError:
                            all_data = {}
                    if site_name in all_data and len(all_data[site_name]) > entry_index:
                        del all_data[site_name][entry_index]
                        if not all_data[site_name]:
                            del all_data[site_name]
                        with open("storage/data/passwords.json", "w") as f:
                            json.dump(all_data, f, indent=4)
                        load_passwords_view()
            edit_btn = ft.TextButton(text="Edit",on_click=toggle_edit)
            del_btn = ft.TextButton(text="Delete",on_click=delete_entry)
            return ft.Column([
                user,passw,
                ft.Row([edit_btn, del_btn], alignment=ft.MainAxisAlignment.END),
                ft.Divider()
            ])
        list_items = []
        if os.path.exists("storage/data/passwords.json"):
            with open("storage/data/passwords.json", "r") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = {}
        else:
            data = {}
        for site_name, credentials in data.items():
            expanded = ft.Column(visible=False)
            for i, entry in enumerate(credentials):
                expanded.controls.append(create_credential_row(entry, site_name, i))
            arrow_icon = ft.Icon(name=ft.Icons.KEYBOARD_ARROW_DOWN)
            def toggle_expand(e, section=expanded, icon=arrow_icon):
                section.visible = not section.visible
                icon.name = ft.Icons.KEYBOARD_ARROW_UP if section.visible else ft.Icons.KEYBOARD_ARROW_DOWN
                page.update()
            site_row = ft.Container(
                on_click=toggle_expand,padding=8,bgcolor=ft.Colors.BLACK12,
                content=ft.Row(
                    [ft.Text(site_name, size=16, weight=ft.FontWeight.BOLD),arrow_icon],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                ),
            )
            list_items.append(ft.Column([site_row, expanded]))
        cont.content = ft.ListView(list_items, expand=True, spacing=10, padding=8)
        page.update()
    site = ft.TextField(label="Site", on_blur=validate_site, on_change=on_change, hint_text="example.com")
    username = ft.TextField(label="Username", on_change=on_change)
    password = ft.TextField(label="Password", password=True, on_change=on_change)
    save_button = ft.ElevatedButton("Save", disabled=True, on_click=save_password)
    form = ft.Container(
        content=ft.Column([site,username,password,
            ft.Row([save_button], alignment=ft.MainAxisAlignment.END, spacing=3),
        ]),
        visible=False,
    )
    cont = ft.Container(width=page.width,height=500,
        content=ft.ListView(controls=[], spacing=10, padding=10, auto_scroll=False, expand=True),
    )
    add_button = ft.IconButton(icon=ft.Icons.ADD, tooltip="Add", on_click=add_new_password)
    bs = ft.AlertDialog(modal=True,
        title=ft.Row([
            ft.Text("Password", size=20, weight=ft.FontWeight.BOLD),
            ft.Container(expand=True),add_button,
            ft.IconButton(icon=ft.Icons.CLOSE, tooltip="Close", on_click=close_bs),
        ], alignment=ft.MainAxisAlignment.START, vertical_alignment=ft.CrossAxisAlignment.CENTER),
        actions_alignment=ft.CrossAxisAlignment.END,
        content=ft.Column([form,ft.Divider(),cont]),
    )
    page.open(bs)
    load_passwords_view()
    page.update()