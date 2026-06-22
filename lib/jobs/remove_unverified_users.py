import datetime

import lib.connectors.sql as sql
import lib.settings as settings


UTC = datetime.timezone.utc
logger = settings.setup_rotating_logger("inactive-account-removal", "removed-accounts.log")


def get_all_users():
    logger.info("Gathering all accounts")
    return sql.get_all_researchers()


def find_unverified_users(accounts):
    logger.info("Finding unverified user accounts")
    return [account for account in accounts if not account.get("is_verified", False)]


def parse_datetime(value):
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        dt = value
    else:
        dt = datetime.datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def remove_unverified_users(unverified, grace_period=7):
    now = datetime.datetime.now(tz=UTC)

    for account in unverified:
        registered_at = parse_datetime(account['registered_at'])
        if registered_at is None:
            pass
        cutoff = now - datetime.timedelta(days=grace_period)
        if registered_at <= cutoff:
            logger.warning(f"Account ID: {account['user_id']} is inactive, removing account (email hash: {settings.get_string_hash(account['email_address'])})")
            is_deleted = sql.delete_user_account(account['user_id'])
            if is_deleted:
                logger.info("Account deleted successfully")
            else:
                logger.info("Account no deleted, will try next run")


def run_job():
    start = datetime.datetime.now(tz=UTC).isoformat()
    logger.info(f"Starting account removal job at: {start}")
    all_users = get_all_users()
    unverified_users = find_unverified_users(all_users)
    remove_unverified_users(unverified_users)
    stop = datetime.datetime.now(tz=UTC).isoformat()
    logger.info(f"Stopping account removal job at: {stop}")
