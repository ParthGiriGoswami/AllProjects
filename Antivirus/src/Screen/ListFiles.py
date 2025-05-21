import flet as ft,os
from Screen.ScanDir import scan_directory
def listfiles(page, idp, path=None, file=None):
    ITEMS_PER_PAGE = 500
    current_page = [0]
    all_files = [sorted(path)]
    total_files = [len(all_files[0])]
    selected_files_dict = {f: False for f in all_files[0]}
    h=150 if idp=="Result" else 430
    file_list = ft.ListView(controls=[], spacing=10, padding=10, auto_scroll=False, height=h)
    page_label = ft.Text()
    addbtn = ft.TextButton(text="Add to exclusion list",on_click=lambda e: on_add_to_exclusion_list(e,selected_files_dict,path,page),disabled=True)
    removebtn = ft.TextButton(text="Remove",on_click=lambda e: on_remove_files(e,selected_files_dict,path,page),disabled=True)
    prev_button = ft.ElevatedButton("Previous")
    next_button = ft.ElevatedButton("Next")
    remove = ft.TextButton(f"Remove From {idp}", disabled=True)
    select_all_button = ft.TextButton("Select All", visible=False)
    icon = ft.Icon(ft.Icons.CLOSE, color=ft.Colors.RED, size=150) if idp=="Result" else None
    files = ft.Text(value=f"{len(path)} files found", size=20) if idp=="Result" else None
    def on_add_to_exclusion_list(e, selected_files_dict,path, page):
        selected = [f for f, checked in selected_files_dict.items() if checked]
        path_file = "storage/data/exclusion.txt"
        os.makedirs(os.path.dirname(path_file), exist_ok=True)
        with open(path_file, "a") as f:
            for line in selected:
                f.write(f"{line}\n")
        for f in selected:
            path.discard(f)
            selected_files_dict.pop(f, None)
        all_files[0] = sorted(path)
        for f in all_files[0]:
            selected_files_dict[f] = False
        current_page[0] = 0
        refresh_checkbox_list()
    def on_remove_files(e, selected_files_dict,path,page):
        selected = [f for f, checked in selected_files_dict.items() if checked]
        exclusion_path = "storage/data/exclusion.txt"
        for file in selected:
            try:
                os.remove(file)
            except (PermissionError, FileNotFoundError):
                os.makedirs(os.path.dirname(exclusion_path), exist_ok=True)
                with open(exclusion_path, "a") as f:
                    f.write(f"{file}\n")
            path.discard(file)
            selected_files_dict.pop(file, None)
        all_files[0] = sorted(path)
        for f in all_files[0]:
            selected_files_dict[f] = False
        current_page[0] = 0
        refresh_checkbox_list()
    def update_remove_button_state():
        remove.disabled = not any(selected_files_dict.values())
        addbtn.disabled=not any(selected_files_dict.values())
        removebtn.disabled=not any(selected_files_dict.values())
        select_all_button.visible = total_files[0] > 100
        page.update()
    def on_checkbox_change(e, file_path):
        selected_files_dict[file_path] = e.control.value
        update_remove_button_state()
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
        if(idp=="Result"):
            if(total_files[0]==0):
                icon.name=ft.Icons.CHECK
                icon.color=ft.Colors.GREEN_400
                icon.size=200
                files.value="Scan Completed\nNo malware found"
                bs.actions=[]
                file_list.visible=False
            else:
                files.value=f"{total_files[0]} files found"
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
        with open("storage/data/exclusion.txt", "w") as f:
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
    def toggle_select_all(e):
        start_idx = current_page[0] * ITEMS_PER_PAGE
        end_idx = min(start_idx + ITEMS_PER_PAGE, total_files[0])
        all_checked = all(selected_files_dict.get(f, False)
            for f in all_files[0][start_idx:end_idx])
        for f in all_files[0][start_idx:end_idx]:
            selected_files_dict[f] = not all_checked
        select_all_button.text = "Deselect All" if not all_checked else "Select All"
        file_list.controls.clear()
        for f in all_files[0][start_idx:end_idx]:
            file_list.controls.append(
                ft.Checkbox(
                    label=f,value=selected_files_dict.get(f, False),
                    on_change=lambda e, file_path=f: on_checkbox_change(e, file_path)
                ))
        update_remove_button_state()
        page.update()
    file_picker = ft.FilePicker(on_result=add_file_result)
    page.overlay.append(file_picker)
    def close_bs(e):
        page.close(bs)
        page.update()
    prev_button.on_click = prev_page
    next_button.on_click = next_page
    remove.on_click = remove_selected_files
    select_all_button.on_click = toggle_select_all
    if(len(path)==0 and idp=="Result"):
        content_column=ft.Column([
                ft.Icon(ft.Icons.CHECK, color=ft.Colors.GREEN_400, size=200),
                ft.Text(value="Scan Completed", size=20),ft.Text(value="No malware found"),
            ],alignment=ft.MainAxisAlignment.CENTER,horizontal_alignment=ft.CrossAxisAlignment.CENTER)
        act=[]
    else:
        act=[select_all_button,addbtn,removebtn] if idp=="Result" else [remove,select_all_button,ft.TextButton("Add", on_click=file_picker.pick_files(allow_multiple=True))] 
        content_column = ft.Column([icon,files,file_list,
                ft.Row([prev_button, page_label, next_button])],alignment=ft.MainAxisAlignment.CENTER,horizontal_alignment=ft.CrossAxisAlignment.CENTER)
    cont = ft.Container(width=page.width,height=500,content=content_column)
    bs = ft.AlertDialog(
        modal=True,
        title=ft.Row([
            ft.Text(idp, size=20, weight=ft.FontWeight.BOLD),
            ft.Container(expand=True),
            ft.IconButton(icon=ft.Icons.CLOSE, tooltip="Close", on_click=close_bs)]),
        content=cont,actions=act,actions_alignment=ft.CrossAxisAlignment.END)
    refresh_checkbox_list()
    page.open(bs)
    page.update()