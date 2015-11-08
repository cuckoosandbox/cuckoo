from django.template.defaultfilters import register

@register.filter("mongo_id")
def mongo_id(value):
    """Retrieve _id value.
    @todo: it will be removed in future.
    """
    if isinstance(value, dict):
        return value.get("_id", value)

    # Return value
    return unicode(value)

@register.filter("is_dict")
def is_dict(value):
    """Checks if value is an instance of dict"""
    return isinstance(value, dict)

@register.filter
def get_item(dictionary, key):
    return dictionary.get(key, "")

@register.filter
def filter_key_if_has(l, key):
    for x in l:
        if key not in x or x[key]:
            yield x

@register.filter
def custom_length(dictionary, keys):
    ret = 0
    for key in keys.split():
        ret += len(dictionary.get(key, []))
    return ret
