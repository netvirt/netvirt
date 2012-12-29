from django.http import HttpResponse
from django.shortcuts import render
from dnds.forms import ClientNewForm, ClientLoginForm
from dsctl import *
from time import sleep

def welcome(request):
    html = "<html><body> Welcome ! </body></html>"
    return HttpResponse(html)

def client_new(request):
    if request.method == 'POST':
        form = ClientNewForm(request.POST)
        if form.is_valid():
            cd = form.cleaned_data
            strclient = cd['firstname']+","+cd['lastname']+","+cd['email']+","+cd['passwd']+",none,none,"+cd['country']+",none,none,none"

            conn = Connection()
            connect(conn, '127.0.0.1')
            addClient(conn, strclient)
            sleep(2)
            disconnect(conn)

            return HttpResponse(strclient)
    else:
        form = ClientNewForm()
    return render(request, 'client_new_form.html', {'form': form})

def client_login(request):
    if request.method == 'POST':
        form = ClientLoginForm(request.POST)
        if form.is_valid():
            cd = form.cleaned_data
            strlogin = cd['email'] + "," + cd['passwd']


            conn = Connection()
            connect(conn, '127.0.0.1')
            login(conn, strlogin)
            sleep(2)

            if conn.loggedin == True:
                strlogin = strlogin + " -> Logged in !"
            else:
                strlogin = strlogin + " -> Logging failed !"

            return HttpResponse(strlogin)

    form = ClientLoginForm
    return render(request, 'client_login_form.html', {'form': form})

