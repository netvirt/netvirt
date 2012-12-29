from django.conf.urls.defaults import patterns, url
from dnds.views import welcome, client_new, client_login

urlpatterns = patterns('',
    (r'^$', welcome),
    ('^client/new', client_new),
    ('^client/login', client_login),
)
