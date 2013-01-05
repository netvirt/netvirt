from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from dnds.forms import *
from dsctl import *
from time import sleep

def welcome(request):
    html = "<html><body> Welcome ! </body></html>"
    return HttpResponse(html)

def client_register(request):

    if request.method == 'POST':

        form = ClientRegisterForm(request.POST)

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
        form = ClientRegisterForm()
    return render(request, 'client_register_form.html', {'form': form})

def client_login(request):

    try:
        if request.session['logged'] == True:
            return HttpResponseRedirect("/dnds/client/logoff/")
    except KeyError:
        pass

    if request.method == 'POST':

        form = ClientLoginForm(request.POST)

        if form.is_valid():

            cd = form.cleaned_data
            strlogin = cd['email'] + "," + cd['passwd']

            conn = Connection()
            connect(conn, '127.0.0.1')
            login(conn, strlogin)
            request.session['client_id'] = conn.ClientId
            sleep(2)
            disconnect(conn)

            if conn.loggedin == True:
                request.session['logged'] = True
                return HttpResponseRedirect("/dnds/client/dashboard/")
            else:
                strlogin = strlogin + " -> Logging failed !"

            return HttpResponse(strlogin)

    form = ClientLoginForm
    return render(request, 'client_login_form.html', {'form': form})

def client_logoff(request):

    try:
        del request.session['logged']
    except KeyError:
        pass

    return HttpResponseRedirect("/dnds/client/login/")

class Context:
    cid = ""
    desc = ""
    nodes = []

def client_dashboard(request):

    logged = request.session.get('logged', '')
    if logged != True:
            return HttpResponseRedirect("/dnds/client/login/")

    conn = Connection()
    connect(conn, '127.0.0.1')
    conn.ClientId = request.session.get('client_id', '0')
    t = showContext(conn)
    sleep(1)

    ctx_list = []
    for d in t:
        ctx = Context()
        ctx.cid = str(d['id'])
        ctx.desc = str(d['desc'])
        ctx.nodes = showNode(conn, str(d['id']))
        ctx_list.append(ctx)
        sleep(1)

    disconnect(conn)

    return render(request, 'client_dashboard.html',
        {'client_id': conn.ClientId, 'context': ctx_list})

def context_add(request):

    logged = request.session.get('logged', '')
    if logged != True:
            return HttpResponseRedirect("/dnds/client/login/")

    if request.method == 'POST':

        form = ContextAddForm(request.POST)

        if form.is_valid():

            cd = form.cleaned_data
            conn = Connection()
            connect(conn, '127.0.0.1')
            conn.ClientId = request.session.get('client_id', '0')
            addContext(conn, cd['desc'])
            sleep(2)
            disconnect(conn)

            return HttpResponseRedirect("/dnds/client/dashboard/")

    else:
        form = ContextAddForm()

    return render(request, 'context_add_form.html', {'form': form})


def node_add(request, cid):

    logged = request.session.get('logged', '')
    if logged != True:
            return HttpResponseRedirect("/dnds/client/login/")

    if request.method == 'POST':

        form = NodeAddForm(request.POST)

        if form.is_valid():

            cd = form.cleaned_data
            conn = Connection()
            connect(conn, '127.0.0.1')
            conn.ClientId = request.session.get('client_id', '0')
            addNode(conn, cid, cd['desc'])
            sleep(1)
            disconnect(conn)

            return HttpResponseRedirect("/dnds/client/dashboard/")

    else:
        form = ContextAddForm()

    return render(request, 'node_add_form.html', {'form': form})


