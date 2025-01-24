import flet as ft
import time
import yara
import threading
from queue import Queue
import os
rule = """
rule ExampleMalware
{
    strings:
        $ransomware_pattern = {50 53 51 52 56 57 55 41 54 41 55 41 56 41 57}
        $keylogger_pattern = {6A 00 68 00 30 00 00 64 FF 35 30 00 00 00}
        $suspicious_cmd = "cmd.exe /c"
        $powershell_script = "powershell.exe -nop -w hidden"
        $shellcode_pattern = {31 C0 50 68 2E 65 78 65 68 63 61 6C 63 54 5F 50 57 56 50 FF D0}
    condition:
        any of ($ransomware_pattern, $keylogger_pattern, $suspicious_cmd, $powershell_script, $shellcode_pattern)
}
"""
malware_count=set()
def build_header(page: ft.Page, previous_route=None):
    return ft.Row(
        [
            ft.IconButton(
                icon=ft.Icons.CLOSE, 
                on_click=lambda _: page.go(previous_route) if previous_route else page.go("/scan")
            )
        ],
        alignment=ft.MainAxisAlignment.END,
    )
def on_checkbox_change(e, selected_files):
    selected_files[e.control.label] = e.control.value
def get_selected_files(selected_files):
    return [file for file, selected in selected_files.items() if selected]
def on_add_to_exclusion_list(e, selected_files, count, page):
    selected = set(get_selected_files(selected_files))
    exclusion_file_path = "Major_Project/Screens/exclusion.txt"
    os.makedirs(os.path.dirname(exclusion_file_path), exist_ok=True)
    try:
        with open(exclusion_file_path, "a") as exclude_file:
            for file in selected:
                exclude_file.write(f"{file}\n")
    except:
        pass
    count = [file for file in count if file not in selected]
    page.views[-1] = result(page,count)
    page.update()
def on_remove_files(e, selected_files):
    selected = get_selected_files(selected_files)
    for file in selected:
        try:
            os.remove(file)
        except:
            pass
def update_checkboxes(select_all_value, malware_file_checkboxes, selected_files):
    for checkbox in malware_file_checkboxes:
        checkbox.value = select_all_value
        selected_files[checkbox.label] = select_all_value
def on_select_all_change(e, malware_file_checkboxes, selected_files, page):
    select_all_value = e.control.value
    update_checkboxes(select_all_value, malware_file_checkboxes, selected_files)
    page.update()
def result(page, count, previous_route=None):
    malware_found = len(count)
    selected_files = {file: False for file in count}
    if malware_found == 0:
        icon = ft.Icon(ft.Icons.CHECK, color=ft.Colors.GREEN_400, size=200)
        page.update()
        return ft.View(
            route="/results",
            padding=0,
            controls=[
                build_header(page, previous_route),
                ft.Column(
                    [
                        ft.Row(
                            [icon],
                            alignment=ft.MainAxisAlignment.CENTER,
                        ),
                        ft.Row(
                            [ft.Text(value="Scan Completed", size=20)],
                            alignment=ft.MainAxisAlignment.CENTER,
                        ),
                        ft.Row(
                            [ft.Text(value="No malware found")],
                            alignment=ft.MainAxisAlignment.CENTER,
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    expand=True,
                ),
            ],
        )
    else:
        icon = ft.Icon(ft.Icons.CLOSE, color=ft.Colors.RED, size=200)
        files=f"{malware_found} files found"
        malware_file_checkboxes = [
            ft.Checkbox(
                label=file,
                value=False,
                on_change=lambda e: on_checkbox_change(e, selected_files)
            ) for file in count
        ]
        page.update()
        return ft.View(
            route="/results",
            padding=0,
            controls=[
                build_header(page, previous_route),
                ft.Column(
                    [
                        ft.Row(
                            [icon],
                            alignment=ft.MainAxisAlignment.CENTER,
                        ),
                        ft.Row(
                            [ft.Text(value="Scan Completed", size=20)],
                            alignment=ft.MainAxisAlignment.CENTER,
                        ),
                        ft.Row(
                            [ft.Text(value=files, size=20)],
                            alignment=ft.MainAxisAlignment.CENTER,
                        ),
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
                                            on_click=lambda e: on_add_to_exclusion_list(e, selected_files, count, page)
                                        )
                                    ],
                                    alignment=ft.CrossAxisAlignment.CENTER,
                                ),
                                ft.Column(
                                    [
                                        ft.ElevatedButton(
                                            text="Remove",
                                            on_click=lambda e: on_remove_files(e, selected_files)
                                        )
                                    ],
                                    alignment=ft.MainAxisAlignment.CENTER,
                                ),
                            ],
                            alignment=ft.MainAxisAlignment.CENTER,
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    expand=True,
                ),
            ],
        )
def get_malware_count():
    return malware_count
def worker(file_queue, malware_count, compiled_rule, txt, info, progress_ring, count, page, lock, local_count):
    if compiled_rule==None:
        batch_size=100
    elif count<100:
        batch_size=10
    elif count<500:
        batch_size=100
    elif count<100:
        batch_size=200
    elif count<2000:
        batch_size=1000
    else:
        batch_size = 3000
    if os.path.exists("Major_Project/Screens/exclusion.txt"):
        with open("Major_Project/Screens/exclusion.txt", 'r') as file:
            exclusion_list=set(line.strip() for line in file)
    else:
        exclusion_list=set()
    while not file_queue.empty():
        try:
            file = file_queue.get_nowait()
            with lock:
                local_count[0] += 1
                index = local_count[0]
            if compiled_rule is not None:
                matches = compiled_rule.match(file)
                if matches and file not in exclusion_list:
                    with lock:
                        malware_count.add(file)
            if index % batch_size == 0 or index == count:
                with lock:
                    txt.value = f"Scanning: {file}"
                    info.value = f"{round(((index / count) * 100), 2)}% scanned"
                    progress_ring.value = index / count if count > 0 else 0
                    page.update()
        except:
            pass
        finally:
            file_queue.task_done()
def scan_drives(page, txt, info, count, files, progress_ring, malware_count, compiled_rule):
    file_queue = Queue()
    for file in files:
        file_queue.put(file)
    if compiled_rule==None:
        num_threads=100
    elif count<100:
        num_threads=10
    elif count<500:
        num_threads=100
    elif count<100:
        num_threads=200
    elif count<2000:
        num_threads=1000
    else:
        num_threads =2000
    threads = []
    local_count = [0]
    lock = threading.Lock()
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(file_queue, malware_count, compiled_rule, txt, info, progress_ring, count, page, lock, local_count))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    progress_ring.value = 1
    info.value = "100.00% scanned"
    page.update()
    page.go('/results')
def build_centered_header(page: ft.Page, count, files,txt,info,progress_ring ,malware_count=None, rule=None):
    icons = [
        ft.Icon(ft.Icons.FAVORITE, size=200),
        ft.Icon(ft.Icons.HOME, size=200),
        ft.Icon(ft.Icons.PERSON, size=200)
    ]
    icon_display = ft.Container(content=icons[0])
    def update_icon():
        index = 0
        while True:
            time.sleep(5)
            index = (index + 1) % len(icons)
            icon_display.content = icons[index]
            page.update()
    thread = threading.Thread(target=update_icon, daemon=True)
    thread.start()
    return ft.Row(
        [
            ft.Column(
                [
                    ft.Row(
                        [
                            ft.Stack(
                                [
                                    progress_ring,
                                    icon_display,
                                ],
                                width=200,
                                height=200,
                            )
                        ],
                        alignment=ft.MainAxisAlignment.CENTER,
                    ),
                    ft.Row(
                        [txt],
                        alignment=ft.MainAxisAlignment.CENTER,
                    ),
                    ft.Row(
                        [info],
                        alignment=ft.MainAxisAlignment.CENTER,
                    ),
                ],
                alignment=ft.MainAxisAlignment.CENTER,
                expand=True,
            ),
        ],
        alignment=ft.MainAxisAlignment.CENTER,
        expand=True,
        spacing=0,
    )
def quickscan(page: ft.Page, count, files):
    global malware_count
    global rule
    scanfiles=set()
    malware_count.clear()
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
    for file in files:
        scan_directory(file,scanfiles)
    if rule:
        compiled_rule = yara.compile(source=rule)
    else:
        compiled_rule = None 
    txt = ft.Text(value="",width=600,max_lines=1,overflow=ft.TextOverflow.ELLIPSIS,text_align=ft.TextAlign.CENTER)
    info = ft.Text(value="")
    progress_ring = ft.ProgressRing(width=200, height=200, value=0.0) 
    page.update()
    return ft.View(
        route="/quickscan",
        padding=0,
        controls=[
            build_centered_header(page,len(scanfiles),scanfiles,txt,info,progress_ring ,malware_count ,rule),
        ],
        
    ),txt,info,compiled_rule,malware_count,progress_ring,scanfiles
def deepscan(page: ft.Page, count, files):
    global rule
    global malware_count
    malware_count.clear()
    if rule:
        compiled_rule = yara.compile(source=rule)
    else:
        compiled_rule = None 
    txt = ft.Text(value="",width=600,max_lines=1,overflow=ft.TextOverflow.ELLIPSIS,text_align=ft.TextAlign.CENTER)
    info = ft.Text(value="")
    progress_ring = ft.ProgressRing(width=200, height=200, value=0.0) 
    page.update()
    return ft.View(
        route="/deepscan",
        padding=0,
        controls=[
            build_centered_header(page, count, files,txt,info,progress_ring,malware_count, rule),  
        ]
    ),txt,info,compiled_rule,malware_count,progress_ring
def customscan(page: ft.Page,scanned):
    global rule
    count=len(scanned)
    global malware_count
    malware_count.clear()
    if rule:
        compiled_rule = yara.compile(source=rule)
    else:
        compiled_rule = None 
    txt = ft.Text(value="",width=600,max_lines=1,overflow=ft.TextOverflow.ELLIPSIS,text_align=ft.TextAlign.CENTER)
    info = ft.Text(value="")
    progress_ring = ft.ProgressRing(width=200, height=200, value=0.0) 
    page.update()
    return ft.View(
        route="/customscan",
        padding=0,
        controls=[
            build_centered_header(page,count,scanned,txt,info,progress_ring,malware_count,rule),  
        ]
    ),txt,info,compiled_rule,malware_count,progress_ring