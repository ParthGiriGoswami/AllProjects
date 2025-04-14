import flet as ft
import threading
from Screen.Commonscan import scan_drives
import math
malware_count = set()
def Scan(page: ft.Page, scanned, rule,flag):
    count=len(scanned)
    malware_count.clear()
    txt = ft.Text(value="",width=600,max_lines=1,overflow=ft.TextOverflow.ELLIPSIS,text_align=ft.TextAlign.CENTER)
    info = ft.Text(value="")
    progress = ft.ProgressBar(value=0.0,width=300,height=300)
    circular_progress = ft.Container(content=progress,width=300,height=300,border_radius=150,alignment=ft.alignment.center)
    progress_ring = ft.Container(content=circular_progress,rotate=math.radians(-90),alignment=ft.alignment.center)
    cont=ft.Container(
        padding=50,
        width=page.width,
        height=page.height,
        content=ft.Column(
            [progress_ring,txt,info],
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        alignment=ft.alignment.center,
    )
    bs = ft.AlertDialog(modal=True,content=cont)
    page.open(bs)
    page.update()
    threading.Thread(target=scan_drives,args=(page, txt, info,count, scanned, progress, malware_count,rule,bs,flag),daemon=True).start()