import flet as ft
import os
def listfiles(page, idp, path=None, file=None):
    ITEMS_PER_PAGE = 500
    current_page = [0]
    all_files = [sorted(path)]
    total_files = [len(all_files[0])]
    selected_files_dict = {f: False for f in all_files[0]}
    file_list = ft.ListView(controls=[], spacing=10, padding=10, auto_scroll=False, height=430)
    page_label = ft.Text()
    prev_button = ft.ElevatedButton("Previous")
    next_button = ft.ElevatedButton("Next")
    remove = ft.TextButton(f"Remove From {idp}", disabled=True)
    select_all_button = ft.TextButton("Select All", visible=False)
    def update_remove_button_state():
        remove.disabled = not any(selected_files_dict.values())
        select_all_button.visible = total_files[0] > 100
        page.update()
    def on_checkbox_change(e, file_path):
        selected_files_dict[file_path] = e.control.value
        update_remove_button_state()
    def scan_directory(directory, file_set):
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.is_file():
                        file_set.add(entry.path)
                    elif  entry.is_dir(follow_symlinks=False):
                        scan_directory(entry.path, file_set)
        except (PermissionError, FileNotFoundError):
            pass
        return file_set
    def refresh_checkbox_list():
        total_files[0] = len(all_files[0])
        start_idx = current_page[0] * ITEMS_PER_PAGE
        end_idx = min(start_idx + ITEMS_PER_PAGE, total_files[0])
        file_list.controls.clear()
        for f in all_files[0][start_idx:end_idx]:
            file_list.controls.append(
                ft.Checkbox(
                    label=f,
                    value=selected_files_dict.get(f, False),
                    on_change=lambda e, file_path=f: on_checkbox_change(e, file_path)
                )
            )
        if total_files[0] > 100:
            any_unchecked = any(not selected_files_dict.get(f, False) for f in all_files[0][start_idx:end_idx])
            select_all_button.text = "Select All" if any_unchecked else "Deselect All"
        page_label.value = f"Page {current_page[0] + 1}/{(total_files[0] - 1) // ITEMS_PER_PAGE + 1 if total_files[0] else 1}"
        update_pagination_buttons()
        page.update() 
    def next_page(e=None):
        if (current_page[0] + 1) * ITEMS_PER_PAGE < total_files[0]:
            current_page[0] += 1
            refresh_checkbox_list()
    def prev_page(e=None):
        if current_page[0] > 0:
            current_page[0] -= 1
            refresh_checkbox_list()
    def update_pagination_buttons():
        prev_button.disabled = current_page[0] == 0
        next_button.disabled = ((current_page[0] + 1) * ITEMS_PER_PAGE >= total_files[0])
        page_label.visible = total_files[0] > ITEMS_PER_PAGE
        prev_button.visible = total_files[0] > ITEMS_PER_PAGE
        next_button.visible = total_files[0] > ITEMS_PER_PAGE
        update_remove_button_state()
    def remove_selected_files(e):
        nonlocal path
        to_remove = {f for f, selected in selected_files_dict.items() if selected}
        path -= to_remove
        file_path = "storage/data/exclusion.txt" if idp == "Exclusion List" else "storage/data/quickpath.txt"
        with open(file_path, "w") as f:
            for line in path:
                f.write(f"{line}\n")
        if idp == "Quick List":
            file_set = set()
            for dir_path in path:
                file_set = scan_directory(dir_path, file_set)
            file.clear()
            file.update(file_set)
        all_files[0] = sorted(path)
        selected_files_dict.clear()
        for f in all_files[0]:
            selected_files_dict[f] = False
        current_page[0] = 0
        refresh_checkbox_list()
    def add_file_result(e: ft.FilePickerResultEvent):
        if e.files:
            for f in e.files:
                path.add(f.path)
        with open("storage/data/exclusion.txt", "w") as f:
            for line in path:
                f.write(f"{line}\n")
        all_files[0] = sorted(path)
        selected_files_dict.clear()
        for f in all_files[0]:
            selected_files_dict[f] = False
        current_page[0] = 0
        refresh_checkbox_list()
    def add_folder_result(e: ft.FilePickerResultEvent):
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
            all_files[0] = sorted(path)
            selected_files_dict.clear()
            for f in all_files[0]:
                selected_files_dict[f] = False
            current_page[0] = 0
            refresh_checkbox_list()
    def toggle_select_all(e):
        start_idx = current_page[0] * ITEMS_PER_PAGE
        end_idx = min(start_idx + ITEMS_PER_PAGE, total_files[0])
        all_checked = all(
            selected_files_dict.get(f, False)
            for f in all_files[0][start_idx:end_idx]
        )
        for f in all_files[0][start_idx:end_idx]:
            selected_files_dict[f] = not all_checked
        select_all_button.text = "Deselect All" if not all_checked else "Select All"
        file_list.controls.clear()
        
        for f in all_files[0][start_idx:end_idx]:
            file_list.controls.append(
                ft.Checkbox(
                    label=f,
                    value=selected_files_dict.get(f, False),
                    on_change=lambda e, file_path=f: on_checkbox_change(e, file_path)
                )
            )
        update_remove_button_state()
        page.update()
    file_picker = ft.FilePicker(on_result=add_file_result)
    folder_picker = ft.FilePicker(on_result=add_folder_result)
    page.overlay.append(file_picker)
    page.overlay.append(folder_picker)
    def add(e):
        if idp == "Exclusion List":
            file_picker.pick_files(allow_multiple=True)
        else:
            folder_picker.get_directory_path()
    def close_bs(e):
        page.close(bs)
        page.update()
    prev_button.on_click = prev_page
    next_button.on_click = next_page
    remove.on_click = remove_selected_files
    select_all_button.on_click = toggle_select_all
    content_column = ft.Column([
        file_list,
        ft.Row([prev_button, page_label, next_button], alignment=ft.MainAxisAlignment.CENTER)
    ])
    cont = ft.Container(width=page.width,height=500,content=content_column)
    bs = ft.AlertDialog(
        modal=True,
        title=ft.Row([
            ft.Text(idp, size=20, weight=ft.FontWeight.BOLD),
            ft.Container(expand=True),
            ft.IconButton(icon=ft.Icons.CLOSE, tooltip="Close", on_click=close_bs),
        ]),
        content=cont,
        actions=[remove,select_all_button,ft.TextButton("Add", on_click=add)],
        actions_alignment=ft.CrossAxisAlignment.END,
    )
    refresh_checkbox_list()
    page.open(bs)
    page.update()