from django.conf.urls.defaults import patterns, url
from dnds.views import *

urlpatterns = patterns('',
    (r'^$', welcome),
    url('^media/(?P<path>.*)$', 'django.views.static.serve',
        {'document_root': '/media'}),
    url('^client/register', client_register),
    url('^client/login', client_login),
    url('^client/logoff', client_logoff, name='client_logoff'),
    url('^client/dashboard', client_dashboard),
    url('^client/context_add', context_add, name='context_add'),
    url('^client/node_add/(\d+)/$', node_add, name='node_add'),
)
