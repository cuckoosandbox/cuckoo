from datetime import datetime
from django import template
from django.utils.timezone import utc

register = template.Library()

@register.filter("timestamp_to_datetime")
def timestamp_to_datetime(value):
    try:
        return datetime.fromtimestamp(value).replace(tzinfo=utc)
    except AttributeError:
        return ''
