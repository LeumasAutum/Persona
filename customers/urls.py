

from django.urls import path
from . import views
from django.conf.urls import include


urlpatterns = [
    path('', views.vulnerability_summary, name='vulnerability_summary'),
    path('Dashboard', views.company, name='company'),
    path('delete', views.delete, name='delete'),
    path('edit', views.edit, name='edit'),
    path('add', views.add, name='add'),
    path('customer/', views.customer, name='customer'),
    path('customer/delete', views.customerdelete, name='customerdelete'),
    path('customer/edit', views.customeredit, name='customeredit'),
    path('customer/add', views.customeradd, name='customeradd'),
    path('openvulns/', views.open_vulnerabilities,name='open_vulnerabilities'),


    
    

]


