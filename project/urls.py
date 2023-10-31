

from django.urls import path
from . import views
from django.conf.urls import include



urlpatterns = [
    path('', views.project, name='project'),
    path('add/', views.projectadd, name='projectadd'),
    path('delete/<str:pk>/', views.projectdelete, name='projectdelete'),
    path('<str:pk>/', views.projectView, name='projectView'),
    path('edit/<str:pk>/', views.projectedit, name='projectedit'),
    path('vulnerability/delete/<str:pk>/', views.projectvulndelete, name='projectvulndelete'),
    path('newvulnerability/<str:pk>/', views.projectnewvuln, name='projectnewvuln'),
    path('fetch/vulnerability', views.fetchvuln, name='fetchvuln'),
    path('editvulnerability/<str:pk>/', views.projecteditvuln, name='projecteditvuln'),
    path('report/addurl/<str:pk>/', views.addurl, name='addurl'),
    path('delete/instace/<str:pk>/', views.deleteinstace, name='deleteinstace'),
    path('report/pdf/<str:pk>/', views.pdf),
    path('upload/', views.upload_excel_file, name='upload_excel_file'),
    path('report/report_csv/<int:pk>/', views.report_csv, name='report_csv'),
    path('project/<str:filter_param>/', views.project, name='project'),
]
                                
