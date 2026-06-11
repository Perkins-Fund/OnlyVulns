import datetime

import pymongo

from pymongo import UpdateOne

import lib.settings as settings
import lib.connectors.security as security


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


@security.sanitize_mongo_args("researcher_id")
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


@security.sanitize_mongo_args("email_address", "magic_link_data")
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


@security.sanitize_mongo_args("email_address")
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


@security.sanitize_mongo_args("email_address")
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


@security.sanitize_mongo_args("user_email")
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
