import time
import datetime

import lib.settings as settings

from apscheduler.schedulers.background import BackgroundScheduler

from lib.jobs import (
    release_reports
)


logger = settings.setup_rotating_logger("scheduled-task-runner", "scheduled-tasks.runner.log")


def process_report_release():
    logger.info("Processing report releases")
    release_reports.run_job()


def start_scheduler():
    scheduler = BackgroundScheduler(timezone="UTC")
    logger.info(f"Starting all scheduled tasks at: {datetime.datetime.now(tz=datetime.timezone.utc).isoformat()}")
    scheduler.add_job(
        process_report_release,
        trigger="cron",
        hour=0,
        minute=0,
        id="release-reports-process",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
    )
    scheduler.start()
    return scheduler


if __name__ == "__main__":
    scheduler = start_scheduler()
    try:
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        logger.info("Stoping scheduled tasks")
        scheduler.shutdown()
