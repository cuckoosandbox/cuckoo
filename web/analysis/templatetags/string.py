# Copyright (C) 2013 David Maciejak
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

import re 

from django import template
from django.template.defaultfilters import stringfilter

register = template.Library()

@register.filter(name="replace")
@stringfilter
def replace (string, args): 
    search  = args.split(args[0])[1]
    replace = args.split(args[0])[2]

    return re.sub(search, replace, string)
