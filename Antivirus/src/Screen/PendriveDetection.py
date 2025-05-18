import psutil
import flet as ft
import os, sys
import notifypy
files = set()
flag = False
def list_connected_devices(page, compiled_rule):
    global flag
    devices = []
    partitions = psutil.disk_partitions()
    def scan_devices(path, compiled_rule):
        try:
            with os.scandir(path) as entries:
                for entry in entries:
                    if entry.is_file():
                        matches = compiled_rule.match(entry.path)
                        if matches:
                            files.add(entry.path)
                    elif entry.is_dir(follow_symlinks=False):
                        scan_devices(entry.path, compiled_rule)
        except:
            pass
    def notify_results(page):
        def resource_path(relative_path):
            base_path = getattr(sys, '_MEIPASS', os.path.abspath("."))
            return os.path.join(base_path, relative_path)
        if os.name == "nt":
            icon_path = resource_path("src/assets/icon.ico")
        else:
            icon_path = resource_path("src/assets/icon.png")
        if not os.path.exists(icon_path):
            icon_path = None
        if len(files) == 0:
            notification = notifypy.Notify()
            notification.application_name = "Kepler Antivirus"
            notification.title = "Information"
            notification.message = "No malware files found!"
            notification.urgency = "critical"
            notification.icon = icon_path
            notification.send(block=False)
            return
        notification = notifypy.Notify()
        notification.application_name = "Kepler Antivirus"
        notification.title = "Information"
        notification.message = f"{len(files)} malware files found. Open your app for more details!"
        notification.urgency = "critical"
        notification.icon = icon_path
        notification.send(block=False)
        selected_files = set()
        checkboxes = []
        file_list_view = ft.ListView(expand=True, spacing=10)
        def remove_selected_files(e):
            removed_count = 0
            to_remove_controls = []
            for cb in checkboxes:
                if cb.label in selected_files:
                    try:
                        os.remove(cb.label)
                        files.discard(cb.label)
                        removed_count += 1
                        to_remove_controls.append(cb)
                    except:
                        pass
            for cb in to_remove_controls:
                file_list_view.controls.remove(cb)
                checkboxes.remove(cb)
            selected_files.clear()
            remove_button.disabled = True
            page.update()
        def on_checkbox_change(e, file_path):
            if e.control.value:
                selected_files.add(file_path)
            else:
                selected_files.discard(file_path)
            remove_button.disabled = len(selected_files) == 0
            page.update()
        for file_path in sorted(files):
            cb = ft.Checkbox(
                label=file_path,
                on_change=lambda e, fp=file_path: on_checkbox_change(e, fp)
            )
            checkboxes.append(cb)
            file_list_view.controls.append(cb)
        cont = ft.Container(content=file_list_view, width=page.width, height=420, padding=10)
        malware_snackbar = ft.Container(
            theme_mode=ft.ThemeMode.DARK,
            bgcolor="#272A2F",
            border_radius=10,
            padding=15,
            margin=10,
            alignment=ft.alignment.bottom_center,
            content=ft.Column([
                ft.Row([
                    ft.Text("Malware List", size=16, weight=ft.FontWeight.BOLD),
                    ft.Container(expand=True),  
                    ft.IconButton(
                        icon=ft.Icons.CLOSE,
                        tooltip="Close",
                        on_click=lambda e: close_bs()
                    )
                ]),
                cont,
                ft.Row([
                    ft.TextButton("Remove Selected", disabled=True, on_click=remove_selected_files),
                ])
            ], spacing=10, tight=True),
            width=page.width,
            height=550
        )
        remove_button = malware_snackbar.content.controls[2].controls[0]
        def close_bs():
            if malware_snackbar in page.overlay:
                page.overlay.remove(malware_snackbar)
                page.update()
        page.overlay.append(malware_snackbar)
        page.update()
    for partition in partitions:
        if 'removable' in partition.opts or partition.fstype in ['vfat', 'exfat', 'ntfs']:
            devices.append(partition.device)
    if devices and not flag:
        flag = True
        for device in devices:
            scan_devices(device, compiled_rule)
        notify_results(page)
    elif not devices and flag:
        flag = False
        page.overlay.clear()
        page.update()