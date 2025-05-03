import flet as ft
from queue import Queue
import queue,concurrent.futures,threading,os
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
            malware_count.discard(file)
            del selected_files[file]
        except (PermissionError,KeyError):
            exclusion_file_path = "storage/data/exclusion.txt"
            os.makedirs(os.path.dirname(exclusion_file_path), exist_ok=True)
            with open(exclusion_file_path, "a") as exclude_file:
                for file in selected:
                    exclude_file.write(f"{file}\n")
                    malware_count.discard(file)
                    del selected_files[file]
        except Exception:
            pass
    malwarelist(page, malware_count, selected_files, bs)
def update_checkboxes(select_all_value, malware_file_checkboxes, selected_files):
    for checkbox in malware_file_checkboxes:
        checkbox.value = select_all_value
        selected_files[checkbox.label] = select_all_value
def on_select_all_change(e, malware_file_checkboxes, selected_files, page):
    select_all_value = e.control.value
    update_checkboxes(select_all_value, malware_file_checkboxes, selected_files)
    page.update()
def worker(file_queue, malware_count, compiled_rule, txt, info, progress_ring, count, page, lock, processed_count,flag):
    batch_size = 50 if compiled_rule is None else 50 if count < 100 else 100 if count < 500 else 2000 if not flag else 500
    with concurrent.futures.ThreadPoolExecutor(max_workers=batch_size) as executor:
        future_to_file = {}
        while not file_queue.empty():
            try:
                file_path = file_queue.get_nowait()
                if file_path in exclusion_list:
                    file_queue.task_done()
                    continue
                with lock:
                    processed_count[0] += 1
                    index = processed_count[0]
                is_suspicious = compiled_rule.match(file_path) if compiled_rule else False
                if flag:
                    if not is_suspicious:
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
ITEMS_PER_PAGE = 1000  
def malwarelist(page, malware_count, selected_files, bs):
    malware_found = len(malware_count)
    current_page = 0  
    malware_list = list(malware_count)
    selected_files_dict = {file: False for file in malware_list}
    malware_file_checkboxes = ft.ListView(
        controls=[],
        height=100,  
        auto_scroll=False
    )
    page_label = ft.Text(f"Page {current_page + 1}/{(malware_found // ITEMS_PER_PAGE) + 1}")
    prev_button = ft.ElevatedButton("Previous", on_click=lambda e: prev_page(), disabled=True)
    next_button = ft.ElevatedButton("Next", on_click=lambda e: next_page(), disabled=(ITEMS_PER_PAGE >= malware_found))
    def close_bs(e):
        page.close(bs)
        page.update()
    def update_list_view():
        nonlocal malware_file_checkboxes, page_label
        start_idx = current_page * ITEMS_PER_PAGE
        end_idx = min(start_idx + ITEMS_PER_PAGE, malware_found)
        malware_file_checkboxes.controls = [
            ft.Checkbox(
                label=file,
                value=selected_files_dict[file],
                on_change=lambda e, f=file: on_checkbox_change(e, f)
            ) for file in malware_list[start_idx:end_idx]
        ]
        page_label.value = f"Page {current_page + 1}/{(malware_found // ITEMS_PER_PAGE) + 1}"
        update_pagination_buttons()
        page.update()
    def on_checkbox_change(e, file):
        selected_files_dict[file] = e.control.value
    def on_select_all_change(e):
        select_all = e.control.value  
        for key in selected_files_dict.keys():
            selected_files_dict[key] = select_all
        update_list_view()
    def next_page():
        nonlocal current_page
        if (current_page + 1) * ITEMS_PER_PAGE < malware_found:
            current_page += 1
            update_list_view()
    def prev_page():
        nonlocal current_page
        if current_page > 0:
            current_page -= 1
            update_list_view()
    def update_pagination_buttons():
        prev_button.disabled = (current_page == 0)
        next_button.disabled = ((current_page + 1) * ITEMS_PER_PAGE >= malware_found)
        page.update()
    if malware_found == 0:
        icon = ft.Icon(ft.Icons.CHECK, color=ft.Colors.GREEN_400, size=200)
        cont = ft.Container(
            padding=50,
            width=page.width * 0.9,
            height=page.height * 0.8,
            content=ft.Column(
                [
                    icon,
                    ft.Text(value="Scan Completed", size=20),
                    ft.Text(value="No malware found"),
                    ft.ElevatedButton("Close", on_click=close_bs)
                ],
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            alignment=ft.alignment.center,
        )
    else:
        icon = ft.Icon(ft.Icons.CLOSE, color=ft.Colors.RED, size=200)
        files = f"{malware_found} files found"
        cont = ft.Container(
            width=page.width * 0.9,
            height=page.height * 0.8,
            content=ft.Column(
                [
                    icon,
                    ft.Text(value="Scan Completed", size=20),
                    ft.Text(value=files, size=20),
                    ft.Checkbox(
                        label="Select All",
                        value=False,
                        on_change=on_select_all_change
                    ),
                    malware_file_checkboxes,  
                    ft.Row(
                        [prev_button, page_label, next_button],
                        alignment=ft.MainAxisAlignment.CENTER,
                    ),
                    ft.Row(
                        [
                            ft.ElevatedButton(
                                text="Add to exclusion list",
                                on_click=lambda e: on_add_to_exclusion_list(e, selected_files_dict, malware_count, page, bs)
                            ),
                            ft.ElevatedButton(
                                text="Remove",
                                on_click=lambda e: on_remove_files(e, selected_files_dict, malware_count, page, bs)
                            ),
                        ],
                        alignment=ft.MainAxisAlignment.CENTER,
                    ),
                    ft.ElevatedButton("Close", on_click=close_bs)
                ],
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            alignment=ft.alignment.center,
        )
    bs.content = cont
    page.update()
    update_list_view()
def scan_drives(page:ft.Page, txt, info, count, files, progress_ring, malware_count, compiled_rule,bs,flag):
    file_queue = Queue()
    for file in files:
        file_queue.put(file)
    num_threads =  50 if compiled_rule is None else 50 if count < 100 else 100 if count < 500 else 2000 if not flag else 500
    threads = []
    processed_count = [0]  
    lock = threading.Lock()
    for _ in range(num_threads):
        thread = threading.Thread(
            target=worker, 
            args=(file_queue, malware_count, compiled_rule, txt, info, progress_ring, count, page, lock, processed_count,flag)
        )
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    progress_ring.value = 1  
    info.value = "100.00% scanned"
    page.update()
    selected_files = {file: False for file in malware_count}
    malwarelist(page,malware_count,selected_files,bs)