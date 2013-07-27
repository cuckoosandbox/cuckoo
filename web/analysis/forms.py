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
