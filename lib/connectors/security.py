import inspect

from functools import wraps


MONGO_OPERATOR_REPLACEMENTS = {
    "$all",
    "$elemMatch",
    "$size",
    "$bitsAllClear",
    "$bitsAllSet",
    "$bitsAnyClear",
    "$bitsAnySet",
    "$eq",
    "$ne",
    "$gt",
    "$gte",
    "$lt",
    "$lte",
    "$in",
    "$nin",
    "$exists",
    "$type",
    "$expr",
    "$jsonSchema",
    "$mod",
    "$regex",
    "$where",
    "$and",
    "$not",
    "$nor",
    "$or",
    "$geoIntersects",
    "$geoWithin",
    "$near",
    "$nearSphere",
    "$meta",
    "$slice",
    "$currentDate",
    "$inc",
    "$min",
    "$max",
    "$mul",
    "$rename",
    "$set",
    "$setOnInsert",
    "$unset",
    "$[]",
    "$addToSet",
    "$pop",
    "$pull",
    "$push",
    "$pullAll",
    "$each",
    "$position",
    "$sort",
    "$bit",
    "$text",
    "$search",
    "$comment",
    "$options",
    "$rand",
    "$natural",
    "$",
    "$setField",
    "$unsetField",
    "$replaceRoot",
    "$replaceWith",
    "$match",
    "$project",
    "$addFields",
    "$group",
    "$limit",
    "$skip",
    "$lookup",
    "$graphLookup",
    "$unwind",
    "$facet",
    "$bucket",
    "$bucketAuto",
    "$count",
    "$sortByCount",
    "$sample",
    "$unionWith",
    "$documents",
    "$densify",
    "$fill",
    "$geoNear",
    "$indexStats",
    "$listLocalSessions",
    "$listSessions",
    "$planCacheStats",
    "$redact",
    "$searchMeta",
    "$setWindowFields",
    "$collStats",
    "$out",
    "$merge",
    "$abs",
    "$add",
    "$ceil",
    "$divide",
    "$exp",
    "$floor",
    "$ln",
    "$log",
    "$log10",
    "$multiply",
    "$pow",
    "$round",
    "$sqrt",
    "$subtract",
    "$trunc",
    "$arrayElemAt",
    "$arrayToObject",
    "$concatArrays",
    "$filter",
    "$first",
    "$firstN",
    "$indexOfArray",
    "$isArray",
    "$last",
    "$lastN",
    "$map",
    "$maxN",
    "$minN",
    "$objectToArray",
    "$range",
    "$reduce",
    "$reverseArray",
    "$sortArray",
    "$zip",
    "$cond",
    "$ifNull",
    "$switch",
    "$cmp",
    "$allElementsTrue",
    "$anyElementTrue",
    "$setDifference",
    "$setEquals",
    "$setIntersection",
    "$setIsSubset",
    "$setUnion",
    "$concat",
    "$dateFromString",
    "$indexOfBytes",
    "$indexOfCP",
    "$ltrim",
    "$regexFind",
    "$regexFindAll",
    "$regexMatch",
    "$replaceOne",
    "$replaceAll",
    "$rtrim",
    "$split",
    "$strLenBytes",
    "$strLenCP",
    "$strcasecmp",
    "$substr",
    "$substrBytes",
    "$substrCP",
    "$toLower",
    "$toString",
    "$trim",
    "$toUpper",
    "$dateAdd",
    "$dateDiff",
    "$dateFromParts",
    "$dateSubtract",
    "$dateToParts",
    "$dateToString",
    "$dateTrunc",
    "$dayOfMonth",
    "$dayOfWeek",
    "$dayOfYear",
    "$hour",
    "$isoDayOfWeek",
    "$isoWeek",
    "$isoWeekYear",
    "$millisecond",
    "$minute",
    "$month",
    "$second",
    "$week",
    "$year",
    "$convert",
    "$toBool",
    "$toDate",
    "$toDecimal",
    "$toDouble",
    "$toInt",
    "$toLong",
    "$toObjectId",
    "$let",
    "$literal",
    "$function",
    "$accumulator",
    "$getField",
    "$mergeObjects",
    "$bsonSize",
}


def replace_blocked_mongo_operators(value):
    """
    basically just turns any mongo operator that's above into _OPERATION instead of $OPERATION
    """
    try:
        if isinstance(value, dict):
            cleaned = {}
            for key, nested_value in value.items():
                cleaned_key = replace_blocked_mongo_operators(key)
                cleaned_value = replace_blocked_mongo_operators(nested_value)
                cleaned[cleaned_key] = cleaned_value
            return cleaned
        if isinstance(value, list):
            return [replace_blocked_mongo_operators(item) for item in value]
        if isinstance(value, tuple):
            return tuple(replace_blocked_mongo_operators(item) for item in value)
        if isinstance(value, set):
            return {replace_blocked_mongo_operators(item) for item in value}
        if isinstance(value, str):
            if value in MONGO_OPERATOR_REPLACEMENTS:
                return value.replace("$", "_", 1)
            return value
        return value
    except Exception:
        return value


def sanitize_mongo_args(*arg_names):
    """
    decorator that can be used on functions to take an argument name and replace the operators

    for example:

        @sanitize_mongo_args("name")
        def hello_world(name):
            print(f"hello {name}")

       hello_world("$toInt") -> hello _toInt
       hello_world("$dateFromParts") -> hello _dateFromParts
    """
    arg_names = set(arg_names)
    def decorator(func):
        sig = inspect.signature(func)
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                bound = sig.bind_partial(*args, **kwargs)
                bound.apply_defaults()

                for name in arg_names:
                    if name in bound.arguments:
                        bound.arguments[name] = replace_blocked_mongo_operators(
                            bound.arguments[name]
                        )
                return func(*bound.args, **bound.kwargs)
            except Exception:
                return None
        return wrapper
    return decorator