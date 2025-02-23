import psutil
import os
import notifypy
files = set()
flag = False  
def list_connected_devices(compiled_rule):
    global flag
    devices = []
    partitions = psutil.disk_partitions()
    for partition in partitions:
        if 'removable' in partition.opts or partition.fstype in ['vfat', 'exfat', 'ntfs']:
            devices.append(partition.device)
    if devices and not flag:
        flag = True
        scan_devices(devices,compiled_rule)
        notify_results()
    elif not devices and flag:
        flag = False
def scan_devices(devices,compiled_rule):
    for device in devices:
        try:
            with os.scandir(device) as entries:
                for entry in entries:
                    if entry.is_file():
                        matches = compiled_rule.match(entry.path)
                        if matches:
                            files.add(entry.path)
                    elif entry.is_dir(follow_symlinks=False):
                        scan_devices([entry.path])  
        except:
            pass
def notify_results():
    if os.name == "nt":  
        icon_path = os.path.abspath("icon.ico")
    else:
        icon_path = os.path.abspath("icon.png")
    if not os.path.exists(icon_path):
        icon_path = None
    if len(files) == 0:
        notification = notifypy.Notify() 
        notification.application_name = "Kepler Antivirus"
        notification.title = "Information"
        notification.message ="No malware found!"
        notification.urgency = "critical"
        notification.icon = icon_path
        notification.send(block=False)
    else:
        notification = notifypy.Notify() 
        notification.application_name = "Kepler Antivirus"
        notification.title = "Information"
        notification.message =f"{len(files)} malware files found!",
        notification.urgency = "critical"
        notification.icon = icon_path
        notification.send(block=False)