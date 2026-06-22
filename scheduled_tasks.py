import time
import datetime

import lib.settings as settings

from apscheduler.schedulers.background import BackgroundScheduler

from lib.jobs import (
    release_reports,
    add_badges,
    remove_unverified_users,
)


logger = settings.setup_rotating_logger("scheduled-task-runner", "scheduled-tasks.runner.log")


def process_report_release():
    logger.info("Processing report releases")
    release_reports.run_job()


def process_badge_additions():
    logger.info("Processing badge additions")
    add_badges.run_job()


def process_unverified_users():
    logger.info("Processing unverified user removals")
    remove_unverified_users.run_job()


def start_scheduler():
    scheduler = BackgroundScheduler(timezone="UTC")
    run_now = datetime.datetime.now(datetime.timezone.utc)
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
        next_run_time=run_now
    )
    scheduler.add_job(
        process_badge_additions,
        trigger="cron",
        hour=0,
        minute=0,
        id="badge-addition-process",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
        next_run_time=run_now
    )
    scheduler.add_job(
        process_unverified_users,
        trigger="cron",
        hour=0,
        minute=0,
        id="unverified-users-process",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
        next_run_time=run_now
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
