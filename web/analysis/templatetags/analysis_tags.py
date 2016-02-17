from django.template.defaultfilters import register

@register.filter
def mongo_id(value):
    """Retrieve _id value.
    @todo: it will be removed in future.
    """
    if isinstance(value, dict):
        return value.get("_id", value)

    # Return value
    return unicode(value)

@register.filter
def is_dict(value):
    """Checks if value is an instance of dict"""
    return isinstance(value, dict)

@register.filter
def get_item(dictionary, key):
    return dictionary.get(key, "")

@register.filter
def filter_key_if_has(l, key):
    ret = []
    for x in l:
        if key not in x or x[key]:
            ret.append(x)
    return ret

@register.filter
def custom_length(dictionary, keys):
    if not dictionary:
        return 0

    ret = 0
    for key in keys.split():
        ret += len(dictionary.get(key, []))
    return ret

@register.filter
def volsort(l):
    """Sort baselined Volatility results. Results with `class_` set have a
    higher priority over the regular results."""
    if not l:
        return

    for x in l:
        if x.get("class_"):
            yield x

    for x in l:
        if not x.get("class_"):
            yield x

@register.filter
def isdeadip(ipaddr, analysis):
    # It doesn't make much sense to report a dead IP address when the analysis
    # didn't have internet access in the first place.
    if analysis.get("info", {}).get("route") == "none":
        return

    for ip, port in analysis.get("network", {}).get("dead_hosts", []):
        if ip == ipaddr:
            return True

@register.filter
def sigsort(l):
    """Sort signatures entries. Generic explanations come first, followed by
    IOCs, followed by API calls."""
    if not l:
        return

    for x in l:
        if x.get("type", x.get("_type")) == "generic":
            yield x

    for x in l:
        if x.get("type", x.get("_type")) == "ioc":
            yield x

    first = True
    for x in l:
        if x.get("type", x.get("_type")) == "call":
            if first:
                x["first"] = True
                first = False
            yield x

@register.filter
def ensurelist(o):
    if isinstance(o, (tuple, list)):
        return o
    return o,
