import flet as ft
import os
def listfiles(page, idp, path, file=None):
    selected_files = {}
    def close_bs(e):
        bs.open = False
        page.update()
    def update_remove_button_state():
        remove.disabled = not any(selected_files.values())
        page.update()
    def on_checkbox_change(e, file_path):
        selected_files[file_path] = e.control.value
        update_remove_button_state()
    def scan_directory(directory, file_set):
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.is_file():
                        file_set.add(entry.path)
                    elif entry.is_dir(follow_symlinks=False):
                        scan_directory(entry.path, file_set)
        except (PermissionError, FileNotFoundError):
            pass
        return file_set
    def refresh_checkbox_list():
        cont.content.controls[:] = []
        selected_files.clear()
        for f in sorted(path):
            selected_files[f] = False
            cont.content.controls.append(ft.Checkbox(label=f, value=False, on_change=lambda e, file_path=f: on_checkbox_change(e, file_path)))
        page.update()
    def remove_selected_files(e):
        nonlocal path, cont, file
        to_remove = {f for f, selected in selected_files.items() if selected}
        file_set = set()
        path -= to_remove
        file_path = "storage/data/exclusion.txt" if idp == "Exclusion List" else "storage/data/quickpath.txt"
        with open(file_path, "w") as f:
            for line in path:
                f.write(f"{line}\n")
        if idp == "Quick List":
            for dir_path in path:
                file_set = scan_directory(dir_path, file_set)
            file.clear()
            file.update(file_set)
        refresh_checkbox_list()
        remove.disabled = True
        page.update()
    def add_file_result(e: ft.FilePickerResultEvent):
        nonlocal path
        if e.files:
            for f in e.files:
                path.add(f.path)
        with open("storage/data/exclusion.txt", "w") as f:
            for line in path:
                f.write(f"{line}\n")
        refresh_checkbox_list()
    def add_folder_result(e: ft.FilePickerResultEvent):
        nonlocal path, file
        if e.path:
            path.add(e.path)
            with open("storage/data/quickpath.txt", "w") as f:
                for line in path:
                    f.write(f"{line}\n")
            file_set = set()
            for dir_path in path:
                file_set = scan_directory(dir_path, file_set)
            file.clear()
            file.update(file_set)
            refresh_checkbox_list()
    file_picker = ft.FilePicker(on_result=add_file_result)
    folder_picker = ft.FilePicker(on_result=add_folder_result)
    page.overlay.append(file_picker)
    page.overlay.append(folder_picker)
    def add(e):
        if idp == "Exclusion List":
            file_picker.pick_files(allow_multiple=True)
        else:
            folder_picker.get_directory_path()
    checkbox_controls = []
    if path is not None:
        for f in path:
            selected_files[f] = False
            checkbox_controls.append(ft.Checkbox(label=f, value=False, on_change=lambda e, file_path=f: on_checkbox_change(e, file_path)))
    cont = ft.Container(
        width=page.width,height=500,
        content=ft.ListView(controls=checkbox_controls, spacing=10, padding=10, auto_scroll=False)
    )
    remove = ft.TextButton(f"Remove From {idp}", disabled=True, on_click=remove_selected_files)
    bs = ft.AlertDialog(
        modal=True,
        title=ft.Row([
            ft.Text(idp, size=20, weight=ft.FontWeight.BOLD),
            ft.Container(expand=True),
            ft.IconButton(icon=ft.Icons.CLOSE, tooltip="Close", on_click=close_bs),
        ]),
        content=cont,
        actions=[remove, ft.TextButton("Add", on_click=add)],
        actions_alignment=ft.CrossAxisAlignment.END,
    )
    page.open(bs)
    page.update()