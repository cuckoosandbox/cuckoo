from django import template

register = template.Library()

@register.filter("mongo_id")
def mongo_id(value):
    """Retrieve _id value.
    @todo: it will be removed in future.
    """
    if isinstance(value, dict):
        if value.has_key("_id"):
            value = value["_id"]

    # Return value
    return unicode(value)