from django.template.defaultfilters import register

@register.filter("is_list")
def is_dict(value):
	"""Checks if value is an instance of list"""
	return isinstance(value, list)
