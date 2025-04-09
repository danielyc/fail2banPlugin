from django.urls import path, re_path
from . import views

urlpatterns = [
    path('', views.fail2banPlugin, name='fail2banPlugin'),
    re_path(r'^installFail2ban$', views.install_fail2ban, name='installFail2ban'),
    re_path(r'^createConfig$', views.create_fail2ban_config, name='createConfig'),
    re_path(r'^deleteConfig$', views.delete_fail2ban_config, name='deleteConfig'),
    re_path(r'^getConfig$', views.get_fail2ban_config, name='getConfig'),
]
