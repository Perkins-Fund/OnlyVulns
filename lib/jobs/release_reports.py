import datetime

import lib.settings as settings
import lib.connectors.sql as sql


logger = settings.setup_rotating_logger("release-reports-logger", "report-releases.log")


def get_all_reports():
    logger.info("Gathering all reports")
    return sql.get_reports_that_are_not_released()


def change_reports_status(reports):
    embargo_end = 0
    waiting_end = 0
    total_reports = len(reports)
    logger.info("Running through reports to see what needs to be changed")
    for report in reports:
        report_id = report['report_id']
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        if report['current_status'] == "embargo":
            embargo_end_date = report['metadata']['embargo_end_date']
            target_date = datetime.datetime.fromisoformat(embargo_end_date)
            if target_date < now:
                logger.info(f"Report: {report_id} ready to update from embargo status")
                is_updated = sql.start_report_waiting_period(report_id)
                if is_updated:
                    embargo_end += 1
                    logger.info(f"Report: {report_id} updated from embargo status successfully")
                else:
                    logger.error(f"Report: {report_id} not updated from embargo status")
        if report["current_status"] == "waiting":
            wait_end_date = report['metadata']['wait_end_date']
            target_date = datetime.datetime.fromisoformat(wait_end_date)
            if target_date < now:
                logger.info(f"Report: {report_id} ready to update from waiting status")
                is_updated = sql.release_report(report_id)
                if is_updated:
                    waiting_end += 1
                    logger.info(f"Report: {report_id} released successfully")
                else:
                    logger.error(f"Report: {report_id} not released")
    logger.info(f"Snapshot recap:\n\t{total_reports} total report(s)\n\t{embargo_end} embargo moved to waiting\n\t{waiting_end} waiting moved to released")


def run_job():
    logger.info(f"Starting report release job at: {datetime.datetime.now(tz=datetime.timezone.utc).isoformat()}")
    reports = get_all_reports()
    change_reports_status(reports)
    logger.info(f"Ending report release job at: {datetime.datetime.now(tz=datetime.timezone.utc).isoformat()}")
