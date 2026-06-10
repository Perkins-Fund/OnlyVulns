import pymongo

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

