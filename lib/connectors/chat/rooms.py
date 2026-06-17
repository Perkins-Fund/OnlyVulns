import time
import json
import secrets

import redis

import lib.settings as settings


conf = settings.load_env()
client = redis.Redis(
    host=conf['redis']['host'],
    port=conf['redis']['port'],
    db=conf['redis']['chatroom_database'],
    decode_responses=True
)


CHAT_TTL = 60 * 60 * 48
CHAT_MAX_RETURN = 350
CHAT_ROOM_KEY = "onlyvulns:chat:main"
CHAT_USER_PREFIX = "onlyvulns:chatuser:"
CHAT_USERNAME_PREFIX = "onlyvulns:chatname:"


def _get_user_key(token):
    return f"{CHAT_USER_PREFIX}{token}"


def _get_username_key(username):
    return f"{CHAT_USERNAME_PREFIX}{username}"


def _get_rate_violation_key(token):
    return f"onlyvulns:chatviolations:{token}"


def revoke_chat_user(token, reason="kicked"):
    if not token:
        return None

    user_key = _get_user_key(token)
    user = client.hgetall(user_key)

    if not user:
        client.delete(_get_rate_violation_key(token))
        return None

    username = user.get("username")

    pipe = client.pipeline()
    pipe.delete(user_key)
    pipe.delete(_get_rate_violation_key(token))

    if username:
        pipe.delete(_get_username_key(username))

    pipe.execute()

    return user


def register_send_rate_violation(token):
    if not token:
        return {
            "violations": 0,
            "kicked": False,
            "user": None,
        }

    violation_key = _get_rate_violation_key(token)
    pipe = client.pipeline()
    pipe.incr(violation_key)
    pipe.expire(violation_key, CHAT_TTL)
    violations, _ = pipe.execute()
    violations = int(violations)

    if violations >= 4:
        user = revoke_chat_user(token, reason="send_rate_limit")
        return {
            "violations": violations,
            "kicked": True,
            "user": user,
        }

    return {
        "violations": violations,
        "kicked": False,
        "user": get_chat_user(token),
    }


def _get_room_key():
    return CHAT_ROOM_KEY


def _prune_expired_chats(key, now_ts):
    client.zremrangebyscore(key, 0, now_ts)


def create_chat_user():
    username = settings.generate_username()
    token = secrets.token_urlsafe(32)
    now_ts = int(time.time())
    expires_at = now_ts + CHAT_TTL
    user_key = _get_user_key(token)
    pipe = client.pipeline()
    pipe.hset(user_key, mapping={
        "username": username,
        "created_at": now_ts,
        "expires_at": expires_at,
    })
    pipe.expire(user_key, CHAT_TTL)
    pipe.execute()
    return {
        "username": username,
        "chat_token": token,
        "expires_at": expires_at,
    }


def get_chat_user(token):
    if not token:
        return None
    user_key = _get_user_key(token)
    user = client.hgetall(user_key)
    if not user:
        return None
    now_ts = int(time.time())
    expires_at = int(user.get("expires_at", 0))
    if expires_at <= now_ts:
        client.delete(user_key)
        return None
    client.expire(user_key, CHAT_TTL)
    return user


def add_message(payload, expires_at_ts):
    key = _get_room_key()
    now_ts = int(time.time())
    payload = dict(payload)
    payload["id"] = payload.get("id") or secrets.token_urlsafe(12)
    member = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    pipe = client.pipeline()
    pipe.zadd(key, {member: expires_at_ts})
    pipe.zremrangebyscore(key, 0, now_ts)
    pipe.expire(key, CHAT_TTL * 2)
    pipe.execute()


def get_messages(limit=CHAT_MAX_RETURN):
    key = _get_room_key()
    now_ts = int(time.time())
    _prune_expired_chats(key, now_ts)
    raw = client.zrangebyscore(
        key,
        now_ts + 1,
        "+inf",
        start=0,
        num=max(1, min(limit, CHAT_MAX_RETURN))
    )
    out = []
    for s in raw:
        try:
            out.append(json.loads(s))
        except Exception:
            continue
    return out


def prune_all_expired_chats(delete_empty=True, scan_count=500, max_passes=200):
    now_ts = int(time.time())
    cursor = 0
    pattern = "onlyvulns:chat:*"

    for _ in range(max_passes):
        cursor, keys = client.scan(cursor=cursor, match=pattern, count=scan_count)

        if keys:
            pipe = client.pipeline()
            for k in keys:
                if not k.startswith(CHAT_USER_PREFIX):
                    pipe.zremrangebyscore(k, 0, now_ts)
            pipe.execute()

            if delete_empty:
                pipe = client.pipeline()
                zset_keys = [k for k in keys if not k.startswith(CHAT_USER_PREFIX)]

                for k in zset_keys:
                    pipe.zcard(k)

                cards = pipe.execute()
                empty_keys = [k for k, c in zip(zset_keys, cards) if int(c) == 0]

                if empty_keys:
                    try:
                        client.unlink(*empty_keys)
                    except Exception:
                        client.delete(*empty_keys)
        if cursor == 0:
            break