import datetime

import gridfs
import pymongo

from bson import ObjectId
from pymongo import UpdateOne
from mongo_secure import sanitize

import lib.settings as settings


class ClientError(Exception): pass


def get_client():
    conf = settings.load_env()
    database_conf = conf['database']
    connection_string = (
        f"mongodb://{database_conf['username']}:{database_conf['password']}@"
        f"{database_conf['host']}:{database_conf['port']}/{database_conf['db_name']}"
        f"?authSource={database_conf['auth_source']}"
    )
    client = pymongo.MongoClient(connection_string)
    try:
        _ = client[database_conf['db_name']]
        return client
    except Exception as e:
        raise ClientError(f"unable to create client connection: {str(e)}")


def gridfs_client():
    client = get_client()
    conf = settings.load_env()
    db = client[conf['database']['db_name']]
    return gridfs.GridFS(db, collection=conf['database']['collections']['users']['files'])


@sanitize("report_id")
def get_report_by_report_id(report_id, remove_data=False):
    client = get_client()
    conf = settings.load_env()
    db = client[conf['database']['db_name']]
    collection = db[conf['database']['collections']['users']['reports']]
    try:
        if not remove_data:
            return collection.find_one({"report_id": report_id})
        else:
            return collection.find_one(
                {"report_id": report_id},
                {
                    "_id": 0,
                    "report_files.attached_files.file_upload_id": 0,
                    "report_files.attached_files.upload_error": 0,
                    "report_files.attached_files.uploaded": 0
                }
            )
    except:
        return None


def get_report_files(report_data):
    client = gridfs_client()
    files = []
    report_files = report_data["report_files"]
    for file_ in report_files['attached_files']:
        try:
            uuid = file_['file_upload_id']
            file_data = client.get(ObjectId(uuid))
            bytes_ = file_data.read()
            filename = file_data.filename
            metadata = file_data.metadata
            files.append({
                "filename": filename,
                "raw_bytes": bytes_.decode('utf-8', errors="ignore"),
                "sha256": metadata["integrity_hash"],
                "file_byte_size": metadata["file_upload_size"],
                "upload_date": metadata["file_uploaded_on"]
            })
        except:
            pass
    return files


@sanitize("report_id", "researcher_id", "filename", "content_type")
def store_report_files(report_id, researcher_id, fh, filename, content_type, **kwargs):
    original_filename = kwargs.get("original_filename", None)
    file_size = kwargs.get("file_size", None)
    file_integrity_hash = kwargs.get("file_integrity_hash", None)
    file_id = kwargs.get("file_id", None)

    client = gridfs_client()
    try:
        file_id = client.put(
            fh.stream,
            filename=filename,
            content_type=content_type,
            metadata={
                "associated_researcher": researcher_id,
                "associated_report": report_id,
                "file_id": file_id,
                "file_uploaded_on": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
                "original_filename": original_filename,
                "file_upload_size": file_size,
                "integrity_hash": file_integrity_hash,
                "quarantined": True
            },
        )
        return file_id
    except:
        return None


def get_reports(limit=200):
    client = get_client()
    conf = settings.load_env()
    db = client[conf['database']['db_name']]
    collection = db[conf['database']['collections']['users']['reports']]
    try:
        reports = collection.find({}, {
            "_id": 0,
            "report_files.attached_files.file_upload_id": 0,
            "report_files.attached_files.upload_error": 0,
            "report_files.attached_files.uploaded": 0
        }).sort("_id", -1).limit(limit)
        return list(reports)
    except:
        return []


@sanitize("researcher_id", "report_title", "report_cvss", "report_vendor", "report_write_up")
def add_report(researcher_id, wait_time, release_days, report_title, report_cvss, report_vendor, report_files, report_id, report_write_up):
    client = get_client()
    conf = settings.load_env()
    db = client[conf['database']['db_name']]
    collection = db[conf['database']['collections']['users']['reports']]

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    embargo_ends = now + datetime.timedelta(days=release_days)
    wait_ends = embargo_ends + datetime.timedelta(days=wait_time)

    try:
        collection.insert_one({
            "report_id": report_id,
            "associated_researcher": researcher_id,
            "release_wait_time": wait_time,
            "total_release_days": release_days,
            "report_title": report_title,
            "cvss_score": report_cvss,
            "associated_vendor": report_vendor,
            "report_write_up": report_write_up,
            "current_status": "embargo",
            "report_files": {
                "total_files": len(report_files),
                "attached_files": report_files
            },
            "metadata": {
                "date_reported_on": now.isoformat(),
                "embargo_end_date": embargo_ends.isoformat(),
                "wait_end_date": wait_ends.isoformat()
            }
        })
        return True
    except:
        return False



@sanitize("email_address")
def change_researcher_reputation(email_address, amount=1, downvote=False):
    client = get_client()
    conf = settings.load_env()
    db = client[conf['database']['db_name']]
    collection = db[conf['database']['collections']['users']['accounts']]
    try:
        results = collection.update_one(
            {"email_address": email_address},
            {"$inc": {"reputation": +amount if not downvote else -amount}},
        )
        return results.modified_count == 1
    except:
        return False


@sanitize("researcher_id")
def find_researcher_by_id(researcher_id):
    client = get_client()
    conf = settings.load_env()
    db = client[conf['database']['db_name']]
    collection = db[conf['database']['collections']['users']['accounts']]
    try:
        results = collection.find_one({"user_id": researcher_id})
    except:
        results = None
    return results


@sanitize("email_address", "magic_link_data")
def update_magic_link(email_address, magic_link_data):
    client = get_client()
    conf = settings.load_env()
    db = client[conf['database']['db_name']]
    collection = db[conf['database']['collections']['users']['accounts']]
    _filter = {"email_address": email_address}
    update = {"$set": {"magic_link_info": {"token_hash": magic_link_data['token_hash'], "expires_at": magic_link_data['expires_at']}}}
    try:
        collection.update_one(filter=_filter, update=update)
        return True
    except:
        return False


@sanitize("email_address")
def verify_user(email_address):
    client = get_client()
    conf = settings.load_env()
    db = client[conf['database']['db_name']]
    collection = db[conf['database']['collections']['users']['accounts']]
    operations = [
        UpdateOne(
            {"email_address": email_address},
            {"$set": {"is_verified": True}},
        ),
        UpdateOne(
            {"email_address": email_address},
            {"$set": {"account_verified_at": datetime.datetime.now(tz=datetime.timezone.utc).isoformat()}},
        )
    ]
    try:
        collection.bulk_write(operations)
        return True
    except:
        return False


@sanitize("email_address")
def find_user_by_email(email_address):
    client = get_client()
    conf = settings.load_env()
    db = client[conf['database']['db_name']]
    collection = db[conf['database']['collections']['users']['accounts']]
    try:
        results = collection.find_one({"email_address": email_address})
    except:
        results = None
    return results


@sanitize("user_email")
def register_user(user_email, magic_link):
    client = get_client()
    conf = settings.load_env()
    db = client[conf['database']['db_name']]
    collection = db[conf['database']['collections']['users']['accounts']]
    try:
        collection.insert_one({
            "email_address": user_email,
            "user_id": settings.build_id(is_user_id=True),
            "registered_at": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
            "reputation": 0,
            "total_reports": 0,
            "is_verified": False,
            "account_verified_at": None,
            "magic_link_info": {
                "token_hash": magic_link['token_hash'],
                "expires_at": magic_link['expires_at']
            },
            "researcher_tips": {
                "accepted_by_researcher": False,
                "is_researcher_eligible": False,
                "started_accepting_on": None,
                "last_payout_on": None,
                "stripe_onboarding_complete": False,
                "stripe_account_id": None
            }
        })
        return True
    except:
        return False
