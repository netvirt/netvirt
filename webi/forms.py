from django import forms
from django_countries.countries import COUNTRIES
from captcha.fields import CaptchaField

class ClientRegisterForm(forms.Form):
    firstname = forms.CharField(required=True, label="")
    firstname.widget.attrs['class'] = 'form-signin'
    firstname.widget.attrs['type'] = 'text'
    firstname.widget.attrs['placeholder'] = 'Firstname'

    lastname = forms.CharField(required=True, label="")
    lastname.widget.attrs['class'] = 'form-signin'
    lastname.widget.attrs['type'] = 'text'
    lastname.widget.attrs['placeholder'] = 'Lastname'

    country = forms.ChoiceField(COUNTRIES, required=True, initial='CA', label="")

    email = forms.EmailField(required=True, label="")
    email.widget.attrs['class'] = 'form-signin'
    email.widget.attrs['type'] = 'text'
    email.widget.attrs['placeholder'] = 'Email address'

    passwd = forms.CharField(required=True, label="")
    passwd.widget.attrs['class'] = 'form-signin'
    passwd.widget.attrs['type'] = 'password'
    passwd.widget.attrs['placeholder'] = 'Password'

    captcha = CaptchaField(required=True, label="")
    captcha.widget.attrs['class'] = 'form-signin'
    captcha.widget.attrs['placeholder'] = 'Captcha'

class ClientLoginForm(forms.Form):
    email = forms.EmailField(required=True, label="")
    email.widget.attrs['class'] = 'form-signin'
    email.widget.attrs['type'] = 'text'
    email.widget.attrs['placeholder'] = 'Email address'

    passwd = forms.CharField(required=True, label="")
    passwd.widget.attrs['class'] = 'form-signin'
    passwd.widget.attrs['type'] = 'password'
    passwd.widget.attrs['placeholder'] = 'Password'

    captcha = CaptchaField(required=True, label="")
    captcha.widget.attrs['class'] = 'form-signin'
    captcha.widget.attrs['placeholder'] = 'Captcha'


class ContextAddForm(forms.Form):
    desc = forms.CharField(required=True, label="")
    desc.widget.attrs['class'] = 'form-signin'
    desc.widget.attrs['type'] = 'text'
    desc.widget.attrs['placeholder'] = 'Description'

    captcha = CaptchaField(required=True, label="")
    captcha.widget.attrs['class'] = 'form-signin'
    captcha.widget.attrs['placeholder'] = 'Captcha'

class NodeAddForm(forms.Form):
    desc = forms.CharField(required=True, label="")
    desc.widget.attrs['class'] = 'form-signin'
    desc.widget.attrs['type'] = 'text'
    desc.widget.attrs['placeholder'] = 'Description'

    captcha = CaptchaField(required=True, label="")
    captcha.widget.attrs['class'] = 'form-signin'
    captcha.widget.attrs['placeholder'] = 'Captcha'
