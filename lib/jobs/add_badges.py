import datetime

import lib.connectors.sql as sql
import lib.settings as settings


logger = settings.setup_rotating_logger("badge-addition-logger", "badge_additions.log")
BADGE_TABLE = {
    "Under Review": {
        "required_rep": -5,
        "max_rep": -5,
        "description": "Researcher has received enough negative community feedback to require closer review.",
        "additional_requirements": [],
    },
    "Low Signal": {
        "required_rep": -10,
        "max_rep": -10,
        "description": "Researcher has reached the lowest reputation tier due to repeated negative community feedback.",
        "additional_requirements": [],
    },
    "Verified Researcher": {
        "required_rep": 0,
        "description": "Researcher has verified their email address.",
        "additional_requirements": ["is_verified"],
    },
    "New Researcher": {
        "required_rep": 0,
        "description": "Researcher has created an OnlyVulns account.",
        "additional_requirements": [],
    },
    "First Signal": {
        "required_rep": 1,
        "description": "Researcher has earned their first reputation point.",
        "additional_requirements": [],
    },
    "Signal Starter": {
        "required_rep": 10,
        "description": "Researcher has started earning reputation from community feedback.",
        "additional_requirements": [],
    },
    "Recognized Researcher": {
        "required_rep": 25,
        "description": "Researcher has earned 25 reputation.",
        "additional_requirements": [],
    },
    "Trusted Researcher": {
        "required_rep": 50,
        "description": "Researcher has earned 50 reputation.",
        "additional_requirements": [],
    },
    "High-Signal Researcher": {
        "required_rep": 100,
        "description": "Researcher has earned 100 reputation.",
        "additional_requirements": [],
    },
    "Elite Researcher": {
        "required_rep": 250,
        "description": "Researcher has earned 250 reputation.",
        "additional_requirements": [],
    },
    "Community Authority": {
        "required_rep": 500,
        "description": "Researcher has earned 500 reputation.",
        "additional_requirements": [],
    },
    "Public-Interest Authority": {
        "required_rep": 1000,
        "description": "Researcher has earned 1,000 reputation.",
        "additional_requirements": [],
    },
    "First Disclosure": {
        "required_rep": 0,
        "description": "Researcher has submitted their first report.",
        "additional_requirements": ["total_reports:1"],
    },
    "Active Researcher": {
        "required_rep": 0,
        "description": "Researcher has submitted at least 5 reports.",
        "additional_requirements": ["total_reports:5"],
    },
    "Consistent Contributor": {
        "required_rep": 25,
        "description": "Researcher has submitted at least 10 reports and earned community reputation.",
        "additional_requirements": ["total_reports:10"],
    },
    "Research Veteran": {
        "required_rep": 100,
        "description": "Researcher has submitted at least 25 reports and built meaningful reputation.",
        "additional_requirements": ["total_reports:25"],
    },
    "Disclosure Archivist": {
        "required_rep": 250,
        "description": "Researcher has submitted at least 50 reports.",
        "additional_requirements": ["total_reports:50"],
    },
    "Tip Eligible": {
        "required_rep": 50,
        "description": "Researcher is eligible to receive tips.",
        "additional_requirements": ["researcher_tips.is_researcher_eligible"],
    },
    "Accepts Tips": {
        "required_rep": 50,
        "description": "Researcher has enabled tip acceptance.",
        "additional_requirements": ["researcher_tips.accepted_by_researcher"],
    },
    "Payout Ready": {
        "required_rep": 50,
        "description": "Researcher has completed payout onboarding.",
        "additional_requirements": ["researcher_tips.stripe_onboarding_complete"],
    },
}


def get_nested_value(data, path, default=None):
    current = data
    for part in path.split("."):
        if not isinstance(current, dict):
            return default
        current = current.get(part)
        if current is None:
            return default
    return current


def requirement_met(researcher, requirement):
    if ":" in requirement:
        key, raw_required_value = requirement.split(":", 1)
        actual_value = get_nested_value(researcher, key, 0)
        try:
            required_value = float(raw_required_value)
            actual_value = float(actual_value or 0)
        except (TypeError, ValueError):
            return str(actual_value) == raw_required_value
        return actual_value >= required_value
    return bool(get_nested_value(researcher, requirement, False))


def has_badge_requirements(researcher, badge_config):
    reputation = researcher.get("reputation", 0) or 0
    if reputation < badge_config["required_rep"]:
        return False
    max_rep = badge_config.get("max_rep")
    if max_rep is not None and reputation > max_rep:
        return False
    for requirement in badge_config.get("additional_requirements", []):
        if not requirement_met(researcher, requirement):
            return False
    return True


def get_existing_badge_names(existing_badges):
    badge_names = set()
    for badge in existing_badges or []:
        if isinstance(badge, dict):
            badge_name = badge.get("name")
        else:
            badge_name = badge
        if badge_name:
            badge_names.add(badge_name)
    return badge_names


def get_earned_badges(researcher):
    existing_badges = researcher.get("badges", [])
    existing_badge_names = get_existing_badge_names(existing_badges)
    earned_badges = list(existing_badges)
    for badge_name, badge_config in BADGE_TABLE.items():
        if badge_name in existing_badge_names:
            continue
        if not has_badge_requirements(researcher, badge_config):
            continue
        logger.info(f"Adding badge: {badge_name} to account: {researcher['user_id']}")
        earned_badges.append({
            "name": badge_name,
            "description": badge_config["description"],
            "earned_on": datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
        })
        existing_badge_names.add(badge_name)
    return earned_badges


def run_job():
    start = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
    logger.info(f"Starting badge additions at: {start}")
    researchers = sql.get_all_researchers()
    for researcher in researchers:
        badges = get_earned_badges(researcher)
        sql.update_user_badges(researcher['user_id'], badges)
    end = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
    logger.info(f"Finished badge additions at: {end}")
