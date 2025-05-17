import flet as ft
from queue import Queue
import queue, concurrent.futures, threading, os
from Screen.HeuristicScan import analyze_file
exclusion_list = set()
if os.path.exists("storage/data/exclusion.txt"):
    with open("storage/data/exclusion.txt", "r") as file:
        exclusion_list = set(line.strip() for line in file)
def on_checkbox_change(e, selected_files):
    selected_files[e.control.label] = e.control.value
def get_selected_files(selected_files):
    return [file for file, selected in selected_files.items() if selected]
def on_add_to_exclusion_list(e, selected_files, malware_count, page, bs):
    selected = set(get_selected_files(selected_files))
    exclusion_file_path = "storage/data/exclusion.txt"
    os.makedirs(os.path.dirname(exclusion_file_path), exist_ok=True)
    try:
        with open(exclusion_file_path, "a") as exclude_file:
            for file in selected:
                exclude_file.write(f"{file}\n")
    except:
        pass
    for file in selected:
        malware_count.discard(file)
        del selected_files[file]
    malwarelist(page, malware_count, selected_files, bs)
def on_remove_files(e, selected_files, malware_count, page, bs):
    selected = get_selected_files(selected_files)
    for file in selected:
        try:
            os.remove(file)
        except (PermissionError, FileNotFoundError):
            exclusion_file_path = "storage/data/exclusion.txt"
            os.makedirs(os.path.dirname(exclusion_file_path), exist_ok=True)
            with open(exclusion_file_path, "a") as exclude_file:
                exclude_file.write(f"{file}\n")
        malware_count.discard(file)
        selected_files.pop(file, None)
    malwarelist(page, malware_count, selected_files, bs)
def update_checkboxes(select_all_value, malware_file_checkboxes, selected_files):
    for checkbox in malware_file_checkboxes.controls:
        checkbox.value = select_all_value
        selected_files[checkbox.label] = select_all_value
def on_select_all_change(e, malware_file_checkboxes, selected_files, page):
    select_all_value = e.control.value
    update_checkboxes(select_all_value, malware_file_checkboxes, selected_files)
    page.update()
def worker(file_queue, malware_count, compiled_rule, txt, info, progress_ring, count, page, lock, processed_count, flag):
    batch_size = 50 if compiled_rule is None else 50 if count < 100 else 100 if count < 500 else 2000 if not flag else 500
    with concurrent.futures.ThreadPoolExecutor(max_workers=batch_size) as executor:
        future_to_file = {}
        while not file_queue.empty():
            try:
                file_path = file_queue.get_nowait()
                if file_path in exclusion_list or file_path.endswith(os.path.join("src", "Screen", "Mainpage.py")):
                    file_queue.task_done()
                    continue
                with lock:
                    processed_count[0] += 1
                    index = processed_count[0]
                is_suspicious = compiled_rule.match(file_path) if compiled_rule else False
                if flag and not is_suspicious:
                    future = executor.submit(analyze_file, file_path)
                    future_to_file[future] = file_path
                    try:
                        is_suspicious = future.result()
                    except Exception:
                        pass
                if is_suspicious:
                    malware_count.add(file_path)
                if index % batch_size == 0 or index == count:
                    with lock:
                        progress = max(progress_ring.value, index / count)
                        progress_ring.value = progress
                        txt.value = f"Scanning: {file_path}"
                        info.value = f"{round(progress * 100, 2)}% scanned"
                        page.update()
                file_queue.task_done()
            except queue.Empty:
                break
            except:
                pass
ITEMS_PER_PAGE = 500
def malwarelist(page, malware_count, selected_files, bs):
    ITEMS_PER_PAGE = 1000
    malware_list = list(malware_count)
    total_pages = max((len(malware_list) - 1) // ITEMS_PER_PAGE + 1, 1)
    current_page = [0]
    selected_files_dict = {f: False for f in malware_list}
    text=ft.Text(f"{len(malware_list)} files found", size=18)
    malware_file_checkboxes = ft.ListView(height=160, auto_scroll=False)
    page_label = ft.Text()
    prev_button = ft.ElevatedButton("Previous", disabled=True)
    next_button = ft.ElevatedButton("Next", disabled=len(malware_list) <= ITEMS_PER_PAGE)

    select_all_checkbox = ft.Checkbox(
        label="Select All", value=False, visible=len(malware_list) > 100
    )
    pagination_row = ft.Row(
        [prev_button, page_label, next_button],
        alignment=ft.MainAxisAlignment.CENTER,
        visible=len(malware_list) > ITEMS_PER_PAGE
    )
    addbtn = ft.TextButton("Add to exclusion list", disabled=True)
    removebtn = ft.TextButton("Remove", disabled=True)
    def update_page_label():
        page_label.value = f"Page {current_page[0] + 1}/{total_pages}"
    def get_selected():
        return {f for f, selected in selected_files_dict.items() if selected}
    def update_action_buttons():
        has_selection = any(selected_files_dict.values())
        addbtn.disabled = not has_selection
        removebtn.disabled = not has_selection
        page.update()
    def on_checkbox_change(e, file):
        selected_files_dict[file] = e.control.value
        update_select_all_checkbox()
        update_action_buttons()
    def update_select_all_checkbox():
        start = current_page[0] * ITEMS_PER_PAGE
        end = min(start + ITEMS_PER_PAGE, len(malware_list))
        visible_items = malware_list[start:end]
        all_checked = all(selected_files_dict.get(f, False) for f in visible_items)
        select_all_checkbox.value = all_checked
        page.update()
    def toggle_select_all(e):
        value = e.control.value
        start = current_page[0] * ITEMS_PER_PAGE
        end = min(start + ITEMS_PER_PAGE, len(malware_list))
        for f in malware_list[start:end]:
            selected_files_dict[f] = value
        update_checkbox_list()
        update_action_buttons()
    def update_nav_buttons():
        prev_button.disabled = current_page[0] == 0
        next_button.disabled = current_page[0] + 1 >= total_pages
    def update_checkbox_list():
        start = current_page[0] * ITEMS_PER_PAGE
        end = min(start + ITEMS_PER_PAGE, len(malware_list))
        malware_file_checkboxes.controls.clear()
        for file in malware_list[start:end]:
            malware_file_checkboxes.controls.append(
                ft.Checkbox(
                    label=file,
                    value=selected_files_dict.get(file, False),
                    on_change=lambda e, f=file: on_checkbox_change(e, f)
                )
            )
        select_all_checkbox.visible = len(malware_list) > 100
        pagination_row.visible = len(malware_list) > ITEMS_PER_PAGE
        update_page_label()
        update_nav_buttons()
        update_select_all_checkbox()
        update_action_buttons()
        page.update()
    def next_page(e=None):
        if (current_page[0] + 1) < total_pages:
            current_page[0] += 1
            update_checkbox_list()
    def prev_page(e=None):
        if current_page[0] > 0:
            current_page[0] -= 1
            update_checkbox_list()
    def add_to_exclusion(e):
        selected = get_selected()
        path = "storage/data/exclusion.txt"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as f:
            for line in selected:
                f.write(f"{line}\n")
        malware_count.difference_update(selected)
        for f in selected:
            selected_files_dict.pop(f, None)
        malware_list.clear()
        malware_list.extend(malware_count)
        update_checkbox_list()
        text.value=f"{len(malware_list)} files found"
        page.update()
    def remove_files(e):
        selected = get_selected()
        for file in selected:
            try:
                os.remove(file)
            except (PermissionError, FileNotFoundError):
                with open("storage/data/exclusion.txt", "a") as f:
                    f.write(f"{file}\n")
            malware_count.discard(file)
            selected_files_dict.pop(file, None)
        malware_list.clear()
        malware_list.extend(malware_count)
        update_checkbox_list()
        text.value=f"{len(malware_list)} files found"
        page.update()
    def close_bs(e):
        page.close(bs)
        page.update()
    prev_button.on_click = prev_page
    next_button.on_click = next_page
    select_all_checkbox.on_change = toggle_select_all
    addbtn.on_click = add_to_exclusion
    removebtn.on_click = remove_files
    if not malware_list:
        icon = ft.Icon(ft.Icons.CHECK, color=ft.Colors.GREEN_400, size=150)
        content = ft.Column([
            icon,
            ft.Text("Scan Completed", size=20),
            ft.Text("No malware found.")
        ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER)
        bs.content = ft.Container(content=content, width=page.width, expand=True, alignment=ft.alignment.center)
        bs.actions = []
    else:
        icon = ft.Icon(ft.Icons.CLOSE, color=ft.Colors.RED, size=150)
        content = ft.Column([
            icon,
            ft.Text("Scan Completed", size=20),
            text,
            select_all_checkbox,
            malware_file_checkboxes,
            pagination_row
        ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER)
        bs.content = ft.Container(content=content, width=page.width, expand=True, alignment=ft.alignment.center)
        bs.actions = [addbtn, removebtn]
    bs.title = ft.Row([
        ft.Text("Scan Results", size=20, weight=ft.FontWeight.BOLD),
        ft.Container(expand=True),
        ft.IconButton(icon=ft.Icons.CLOSE, on_click=close_bs)
    ])
    update_checkbox_list()
    page.open(bs)
    page.update()
def scan_drives(page: ft.Page, txt, info, count, files, progress_ring, malware_count, compiled_rule, bs, flag):
    file_queue = Queue()
    for file in files:
        file_queue.put(file)
    num_threads = 50 if compiled_rule is None else 50 if count < 100 else 100 if count < 500 else 2000 if not flag else 500
    threads = []
    processed_count = [0]
    lock = threading.Lock()
    for _ in range(num_threads):
        thread = threading.Thread(
            target=worker,
            args=(file_queue, malware_count, compiled_rule, txt, info, progress_ring, count, page, lock, processed_count, flag)
        )
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    progress_ring.value = 1
    info.value = "100.00% scanned"
    page.update()
    selected_files = {file: False for file in malware_count}
    malwarelist(page, malware_count, selected_files, bs)