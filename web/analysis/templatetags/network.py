# Copyright (C) 2013 David Maciejak
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django import template

register = template.Library()

@register.filter(name="icmp_type_to_str")
def icmp_type_to_str (value): 
    if value == 0:
        return "Echo"
    elif value == 5:
        return "Redirect"
    elif value == 8:
        return "Echo Reply"
    elif value == 11:
        return "Time Exceeded"
    return value 
