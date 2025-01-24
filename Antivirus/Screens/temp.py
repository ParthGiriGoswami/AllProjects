import schedule
def job():
    print("Task running")
schedule.every(3).minutes.do(job)
while True:
    schedule.run_pending()