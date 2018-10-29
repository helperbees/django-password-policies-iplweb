from django.conf.urls import url
from django.urls import path

try:
    # patterns was deprecated in Django 1.8
    from django.conf.urls import patterns
except ImportError:
    # patterns is unavailable in Django 1.10+
    patterns = False

from password_policies.views import PasswordChangeFormView
from password_policies.views import PasswordChangeDoneView
from password_policies.views import PasswordResetCompleteView
from password_policies.views import PasswordResetConfirmView
from password_policies.views import PasswordResetFormView
from password_policies.views import PasswordResetDoneView


urlpatterns = [
    url(r'^change/done/$',
        PasswordChangeDoneView.as_view(),
        name="password_change_done"),
    url(r'^change/$',
        PasswordChangeFormView.as_view(),
        name="password_change"),
    url(r'^reset/$',
        PasswordResetFormView.as_view(),
        name="password_reset"),
    url(r'^reset/complete/$',
        PasswordResetCompleteView.as_view(),
        name="password_reset_complete"),
    path('reset/confirm/<uidb64>/<token>/',
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm"),
    url(r'^reset/done/$',
        PasswordResetDoneView.as_view(),
        name="password_reset_done"),
]

if patterns:
    # Django 1.7
    urlpatterns = patterns('', *urlpatterns)
