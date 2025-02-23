import flet as ft
import threading
from Screen.Commonscan import scan_drives
malware_count = set()
def Scan(page: ft.Page, scanned, rule):
    count=len(scanned)
    malware_count.clear()
    txt = ft.Text(value="",width=600,max_lines=1,overflow=ft.TextOverflow.ELLIPSIS,text_align=ft.TextAlign.CENTER)
    info = ft.Text(value="")
    progress_ring = ft.ProgressRing(width=200, height=200, value=0.0) 
    cont=ft.Container(
        padding=50,
        width=page.width,
        height=page.height,
        content=ft.Column(
            [
                progress_ring,
                txt,
                info
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        alignment=ft.alignment.center,
    )
    bs = ft.AlertDialog(
        modal=True,
        content=cont,
    )
    page.open(bs)
    page.update()
    threading.Thread(
        target=scan_drives, 
        args=(page, txt, info,count, scanned, progress_ring, malware_count, rule,bs),
        daemon=True
    ).start()