import flet as ft
from queue import Queue
import queue,concurrent.futures,threading,os
from datetime import datetime
from Screen.HeuristicScan import analyze_file  # Ensure analyze_file is imported correctly
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
        except:
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
    batch_size = 50 if compiled_rule is None else 50 if count < 100 else 100 if count < 500 else 2000 if not flag else 200
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
def malwarelist(page, malware_count, selected_files, bs):
    malware_found = len(malware_count)
    def close_bs(e):
        page.close(bs)
        page.update()
    if(malware_found==0):
        icon = ft.Icon(ft.Icons.CHECK, color=ft.Colors.GREEN_400, size=200)
        cont=ft.Container(
            padding=50,
            width=page.width * 0.9,
            height=page.height * 0.8,
            content=ft.Column(
                [
                    icon,
                    ft.Text(value="Scan Completed", size=20),
                    ft.Text(value="No malware found"),
                    ft.ElevatedButton("Close",on_click=close_bs)
                ],
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            alignment=ft.alignment.center,
        )
    else:
        icon = ft.Icon(ft.Icons.CLOSE, color=ft.Colors.RED, size=200)
        files=f"{malware_found} files found"
        malware_file_checkboxes = [
            ft.Checkbox(
                label=file,
                value=False,
                on_change=lambda e: on_checkbox_change(e, selected_files)
            ) for file in malware_count
        ]
        cont=ft.Container(
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
                        on_change=lambda e: on_select_all_change(e, malware_file_checkboxes, selected_files, page)
                    ),
                    ft.ListView(
                        controls=malware_file_checkboxes,
                        height=150,
                    ),
                    ft.Row(
                        [
                            ft.Column(
                                [
                                    ft.ElevatedButton(
                                        text="Add to exclusion list",
                                        on_click=lambda e: on_add_to_exclusion_list(e,  selected_files, malware_count, page, bs)
                                    )
                                ],
                                alignment=ft.CrossAxisAlignment.CENTER,
                            ),
                            ft.Column(
                                [
                                    ft.ElevatedButton(
                                        text="Remove",
                                        on_click=lambda e: on_remove_files(e,  selected_files, malware_count, page, bs)
                                    )
                                ],
                                alignment=ft.MainAxisAlignment.CENTER,
                            ),
                        ],
                        alignment=ft.MainAxisAlignment.CENTER,
                    ),
                    ft.ElevatedButton("Close",on_click=close_bs)
                ],
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            alignment=ft.alignment.center,
        )
    bs.content=cont
    page.update()
def scan_drives(page:ft.Page, txt, info, count, files, progress_ring, malware_count, compiled_rule,bs,flag):
    file_queue = Queue()
    for file in files:
        file_queue.put(file)
    num_threads =  50 if compiled_rule is None else 50 if count < 100 else 100 if count < 500 else 2000 if not flag else 4000
    threads = []
    processed_count = [0]  
    lock = threading.Lock()
    a=datetime.now()
    for _ in range(num_threads):
        thread = threading.Thread(
            target=worker, 
            args=(file_queue, malware_count, compiled_rule, txt, info, progress_ring, count, page, lock, processed_count,flag)
        )
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    print(datetime.now()-a)
    progress_ring.value = 1  
    info.value = "100.00% scanned"
    page.update()
    selected_files = {file: False for file in malware_count}
    malwarelist(page,malware_count,selected_files,bs)