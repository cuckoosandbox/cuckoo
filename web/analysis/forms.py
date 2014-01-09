# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django import forms

from submission.models import Comment, Tag

class CommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        fields = ["message"]

class TagForm(forms.ModelForm):
    class Meta:
        model = Tag
        fields = ["name"]
