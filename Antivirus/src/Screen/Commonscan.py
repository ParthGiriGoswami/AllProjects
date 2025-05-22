import flet as ft,queue,concurrent.futures,threading,os
from queue import Queue
from Screen.HeuristicScan import analyze_file
from Screen.ListFiles import listfiles
exclusion_list = set()
def worker(file_queue, malware_count, compiled_rule, txt, info, progress_ring, count, page, lock, processed_count, flag):
    batch_size = 100 if compiled_rule is None else 10 if count < 100 else 100 if count < 500 else 200 if count<1000 else 1500 if not flag else 500
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
def scan_drives(page: ft.Page, txt, info, count, files, progress_ring, malware_count, compiled_rule, bs, flag):
    global exclusion_list
    if os.path.exists("storage/data/exclusion.txt"):
        with open("storage/data/exclusion.txt", "r") as file:
            exclusion_list = set(line.strip() for line in file)
    else:
        exclusion_list = set()
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
    listfiles(page,idp="Result",path=malware_count)