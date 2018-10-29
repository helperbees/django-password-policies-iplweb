from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.core import signing
from django.urls.base import reverse
from django.shortcuts import resolve_url
from django.utils.decorators import method_decorator
from django.utils.encoding import force_text
from django.utils.http import urlsafe_base64_decode
from django.views.defaults import permission_denied
from django.views.generic import TemplateView
from django.views.generic.base import View
from django.views.generic.edit import FormView
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.tokens import default_token_generator
from django.http import HttpResponseRedirect

from password_policies.conf import settings
from password_policies.forms import PasswordPoliciesForm
from password_policies.forms import PasswordPoliciesChangeForm
from password_policies.forms import PasswordResetForm

UserModel = get_user_model()

class LoggedOutMixin(View):
    """
A view mixin which verifies that the user has not authenticated.

.. note::
    This should be the left-most mixin of a view.
"""

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            template_name = settings.TEMPLATE_403_PAGE
            return permission_denied(request, template_name=template_name)
        return super(LoggedOutMixin, self).dispatch(request, *args, **kwargs)


class PasswordChangeDoneView(TemplateView):
    """
A view to redirect to after a successfull change of a user's password.
"""
    #: The template used by this view. Defaults to
    #: the same template used
    #: by :func:`django.contrib.views.password_change_done`.
    template_name = 'registration/password_change_done.html'

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(PasswordChangeDoneView, self).dispatch(*args, **kwargs)


class PasswordChangeFormView(FormView):
    """
A view that allows logged in users to change their password.
"""
    #: The form used by this view.
    form_class = PasswordPoliciesChangeForm
    #: An URL to redirect to after the form has been successfully
    #: validated.
    success_url = None
    #: The template used by this view. Defaults to
    #: the same template used
    #: by :func:`django.contrib.views.password_change`.
    template_name = 'registration/password_change_form.html'
    #: doc
    redirect_field_name = settings.REDIRECT_FIELD_NAME

    # @method_decorator(sensitive_post_parameters)
    @method_decorator(csrf_protect)
    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        redirect_field_name = kwargs.pop('redirect_field_name', None)
        if redirect_field_name:
            self.redirect_field_name = redirect_field_name
        return super(PasswordChangeFormView, self).dispatch(*args, **kwargs)

    def form_valid(self, form):
        form.save()
        return super(PasswordChangeFormView, self).form_valid(form)

    def get_form(self, form_class=None):
        if form_class is None:
            form_class = self.get_form_class()
        return form_class(self.request.user, **self.get_form_kwargs())

    def get_success_url(self):
        """
Returns a query string field with a previous URL if available (Mimicing
the login view. Used on forced password changes, to know which URL the
user was requesting before the password change.)
If not returns the :attr:`~PasswordChangeFormView.success_url` attribute
if set, otherwise the URL to the :class:`PasswordChangeDoneView`.
"""
        checked = '_password_policies_last_checked'
        last = '_password_policies_last_changed'
        required = '_password_policies_change_required'
        now = timezone.now()
        self.request.session[checked] = now
        self.request.session[last] = now
        self.request.session[required] = False
        redirect_to = self.request.POST.get(self.redirect_field_name, '')
        if redirect_to:
            url = redirect_to
        elif self.success_url:
            url = self.success_url
        else:
            url = reverse('password_change_done')
        return url

    def get_context_data(self, **kwargs):
        name = self.redirect_field_name
        kwargs[name] = self.request.GET.get(name, '')
        return super(PasswordChangeFormView, self).get_context_data(**kwargs)


class PasswordResetCompleteView(LoggedOutMixin, TemplateView):
    """
A view to redirect to after a password reset has been successfully
confirmed.
"""
    #: The template used by this view. Defaults to
    #: the same template used
    #: by :func:`django.contrib.views.password_reset_complete`.
    template_name = 'registration/password_reset_complete.html'

    def get_context_data(self, **kwargs):
        """
Adds the login URL to redirect to (defaults to the LOGIN_URL setting
in Django) to the view's context.
"""
        kwargs['login_url'] = resolve_url(settings.LOGIN_URL)
        return super(PasswordResetCompleteView, self).get_context_data(**kwargs)


INTERNAL_RESET_URL_TOKEN = 'set-password'
INTERNAL_RESET_SESSION_TOKEN = '_password_reset_token'
class PasswordResetConfirmView(LoggedOutMixin, FormView):
    #: The form used by this view.
    form_class = PasswordPoliciesForm
    #: An URL to redirect to after the form has been successfully
    #: validated.
    success_url = None
    #: The template used by this view. Defaults to
    #: the same template used
    #: by :func:`django.contrib.views.password_reset_confirm`.
    template_name = 'registration/password_reset_confirm.html'
    token_generator = default_token_generator

    # @method_decorator(sensitive_post_parameters)
    @method_decorator(never_cache)
    def dispatch(self, *args, **kwargs):
        assert 'uidb64' in kwargs and 'token' in kwargs

        self.validlink = False
        self.user = self.get_user(kwargs['uidb64'])

        if self.user is not None:
            token = kwargs['token']
            if token == INTERNAL_RESET_URL_TOKEN:
                session_token = self.request.session.get(INTERNAL_RESET_SESSION_TOKEN)
                if self.token_generator.check_token(self.user, session_token):
                    # If the token is valid, display the password reset form.
                    self.validlink = True
                    return super().dispatch(*args, **kwargs)
            else:
                if self.token_generator.check_token(self.user, token):
                    # Store the token in the session and redirect to the
                    # password reset form at a URL without the token. That
                    # avoids the possibility of leaking the token in the
                    # HTTP Referer header.
                    self.request.session[INTERNAL_RESET_SESSION_TOKEN] = token
                    redirect_url = self.request.path.replace(token, INTERNAL_RESET_URL_TOKEN)
                    return HttpResponseRedirect(redirect_url)

        # Display the "Password reset unsuccessful" page.
        return self.render_to_response(self.get_context_data())


    def get_user(self, uidb64):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist, ValidationError):
            user = None
        return user

    def form_valid(self, form):
        form.save()
        return super(PasswordResetConfirmView, self).form_valid(form)

    def get(self, request, *args, **kwargs):
        if self.validlink:
            return super(PasswordResetConfirmView, self).get(request,
                                                             *args,
                                                             **kwargs)
        return self.render_to_response(self.get_context_data())

    def get_context_data(self, **kwargs):
        kwargs['user'] = self.user
        kwargs['validlink'] = self.validlink
        return super(PasswordResetConfirmView, self).get_context_data(**kwargs)

    def get_form(self, form_class=None):
        if form_class is None:
            form_class = self.get_form_class()
        return form_class(self.user, **self.get_form_kwargs())

    def get_success_url(self):
        """
Redirects to :attr:`~PasswordResetConfirmView.success_url`
if set, otherwise to the :class:`PasswordResetCompleteView`.
"""    
        if self.success_url:
            url = self.success_url
        else:
            url = reverse('password_reset_complete')
        return url

    def post(self, request, *args, **kwargs):
        if self.validlink:
            return super(PasswordResetConfirmView, self).post(request,
                                                              *args,
                                                              **kwargs)
        return self.render_to_response(self.get_context_data())


class PasswordResetDoneView(LoggedOutMixin, TemplateView):
    """
A view to redirect to after a password reset has been requested.
"""
    #: The template used by this view. Defaults to
    #: the same template used
    #: by :func:`django.contrib.views.password_reset_done`.
    template_name = 'registration/password_reset_done.html'


class PasswordResetFormView(LoggedOutMixin, FormView):
    """
A view that allows registered users to change their password.
"""
    #: A relative path to a template in the root of a template directory
    #: to generate the body of the mail.
    email_template_name = 'registration/password_reset_email.html'
    #: The form used by this view.
    form_class = PasswordResetForm
    #: The email address to use as sender of the email.
    from_email = None
    #: Determines wether this view is used by an admin site.
    #: Overrides domain and site name if set to ``True``.
    is_admin_site = False
    #: A relative path to a template in the root of a template directory to
    #: generate the subject of the mail.
    subject_template_name = 'registration/password_reset_subject.txt'
    #: An URL to redirect to after the form has been successfully
    #: validated.
    success_url = None
    #: The template used by this view. Defaults to
    #: the same template used
    #: by :func:`django.contrib.views.password_reset`.
    template_name = 'registration/password_reset_form.html'

    def form_valid(self, form):
        opts = {
            'use_https': self.request.is_secure(),
            'from_email': self.from_email,
            'email_template_name': self.email_template_name,
            'subject_template_name': self.subject_template_name,
            'request': self.request,
        }
        if self.is_admin_site:
            opts = dict(opts, domain_override=self.request.META['HTTP_HOST'])
        form.save(**opts)
        return super(PasswordResetFormView, self).form_valid(form)

    @method_decorator(csrf_protect)
    def dispatch(self, request, *args, **kwargs):
        return super(PasswordResetFormView, self).dispatch(request,
                                                           *args,
                                                           **kwargs)

    def get_success_url(self):
        """
Redirects to :attr:`~PasswordResetFormView.success_url`
if set, otherwise to the :class:`PasswordResetDoneView`.
"""
        if self.success_url:
            url = self.success_url
        else:
            url = reverse('password_reset_done')
        return url
