from django import forms
from django.core.validators import MinLengthValidator
from .models import Video, Genres

class SignInForm(forms.Form):
    mobile_number = forms.CharField(max_length=20)
    password = forms.CharField(widget=forms.PasswordInput)

class SignUpForm(forms.Form):
    username = forms.CharField(max_length=150)
    mobile_number = forms.CharField(max_length=20)
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)

    def clean_password(self):
        password = self.cleaned_data.get('password')
        if len(password) < 8:
            raise forms.ValidationError("Password must be at least 8 characters long.")
        return password

    def clean_mobile_number(self):
        mobile_number = self.cleaned_data.get('mobile_number')
        if len(mobile_number) < 10:
            raise forms.ValidationError("Mobile number must be at least 10 characters long.")
        elif len(mobile_number) > 10:
            raise forms.ValidationError("Mobile number must not be greater than 10 characters")
        return mobile_number

class VideoUploadForm(forms.ModelForm):
    genres = forms.ModelChoiceField(queryset=Genres.objects.all(), widget=forms.Select(attrs={'class': 'form-control'}))
    
    class Meta:
        model = Video
        fields = ('title', 'description', 'video_file', 'thumbnail', 'scheduled_time', 'category', 'genres', 'content_age_rating')
