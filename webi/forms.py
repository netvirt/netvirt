from django import forms
from django_countries.countries import COUNTRIES

class ClientNewForm(forms.Form):
    firstname = forms.CharField(required=True)
    lastname = forms.CharField(required=True)
    country = forms.ChoiceField(COUNTRIES, required=True, initial='CA')
    email = forms.EmailField(required=True)
    passwd = forms.CharField(required=True, label="Password")

class ClientLoginForm(forms.Form):
    email = forms.EmailField(required=True)
    passwd = forms.CharField(required=True, label="Password")
