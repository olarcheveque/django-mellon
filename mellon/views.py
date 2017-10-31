import logging
import requests
import lasso
import uuid
from requests.exceptions import RequestException
from xml.sax.saxutils import escape

from django.core.urlresolvers import reverse
from django.views.generic import View
from django.http import HttpResponseBadRequest, HttpResponseRedirect, HttpResponse
from django.contrib import auth
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, resolve_url
from django.utils.http import urlencode
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.db import transaction
from django.utils.translation import ugettext as _

from . import app_settings, utils


lasso.setFlag('thin-sessions')


class LogMixin(object):
    """Initialize a module logger in new objects"""
    def __init__(self, *args, **kwargs):
        self.log = logging.getLogger(__name__)
        super(LogMixin, self).__init__(*args, **kwargs)


class ProfileMixin(object):
    profile = None

    def set_next_url(self, next_url):
        if not next_url:
            return
        if not utils.is_nonnull(next_url):
            self.log.warning('next parameter ignored, as it contains null characters')
            return
        try:
            next_url.encode('ascii')
        except UnicodeDecodeError:
            self.log.warning('next parameter ignored, as is\'s not an ASCII string')
            return
        if not utils.same_origin(next_url, self.request.build_absolute_uri()):
            self.log.warning('next parameter ignored as it is not of the same origin')
            return
        self.set_state('next_url', next_url)

    def set_state(self, name, value):
        assert self.profile
        relay_state = self.get_relay_state(create=True)
        self.request.session['mellon_%s_%s' % (name, relay_state)] = value

    def get_state(self, name, default=None):
        if self.profile:
            relay_state = self.get_relay_state()
            key = 'mellon_%s_%s' % (name, relay_state)
            return self.request.session.get(key, default)
        return default

    def get_relay_state(self, create=False):
        if self.profile and self.profile.msgRelayState:
            try:
                return uuid.UUID(self.profile.msgRelayState)
            except ValueError:
                pass
        if create:
            assert self.profile
            self.profile.msgRelayState = str(uuid.uuid4())
            return self.profile.msgRelayState

    def get_next_url(self, default=None):
        return self.get_state('next_url', default=default)

    def show_message_status_is_not_success(self, profile, prefix):
        status_codes, idp_message = utils.get_status_codes_and_message(profile)
        args = [u'%s: status is not success codes: %r', prefix, status_codes]
        if idp_message:
            args[0] += u' message: %s'
            args.append(idp_message)
        self.log.warning(*args)


class LoginView(ProfileMixin, LogMixin, View):
    def get_idp(self, request):
        entity_id = request.POST.get('entityID') or request.GET.get('entityID')
        if not entity_id:
            for idp in utils.get_idps():
                return idp
            else:
                return None
        else:
            return utils.get_idp(entity_id)

    def post(self, request, *args, **kwargs):
        '''Assertion consumer'''
        if 'SAMLart' in request.POST:
            return self.continue_sso_artifact(request, lasso.HTTP_METHOD_ARTIFACT_POST)
        if 'SAMLResponse' not in request.POST:
            return self.get(request, *args, **kwargs)
        if not utils.is_nonnull(request.POST['SAMLResponse']):
            return HttpResponseBadRequest('SAMLResponse contains a null character')
        self.log.info('Got SAML Response', extra={'saml_response': request.POST['SAMLResponse']})
        self.profile = login = utils.create_login(request)
        idp_message = None
        status_codes = []
        # prevent null characters in SAMLResponse
        try:
            login.processAuthnResponseMsg(request.POST['SAMLResponse'])
            login.acceptSso()
        except lasso.ProfileCannotVerifySignatureError:
            self.log.warning('SAML authentication failed: signature validation failed for %r',
                             login.remoteProviderId)
        except lasso.ParamError:
            self.log.exception('lasso param error')
        except (lasso.LoginStatusNotSuccessError,
                lasso.ProfileStatusNotSuccessError,
                lasso.ProfileRequestDeniedError):
            self.show_message_status_is_not_success(login, 'SAML authentication failed')
        except lasso.Error, e:
            return HttpResponseBadRequest('error processing the authentication response: %r' % e)
        else:
            if 'RelayState' in request.POST and utils.is_nonnull(request.POST['RelayState']):
                login.msgRelayState = request.POST['RelayState']
            return self.sso_success(request, login)
        return self.sso_failure(request, login, idp_message, status_codes)

    def sso_failure(self, request, login, idp_message, status_codes):
        '''show error message to user after a login failure'''
        idp = utils.get_idp(login.remoteProviderId)
        error_url = utils.get_setting(idp, 'ERROR_URL')
        error_redirect_after_timeout = utils.get_setting(idp, 'ERROR_REDIRECT_AFTER_TIMEOUT')
        if error_url:
            error_url = resolve_url(error_url)
        next_url = error_url or login.msgRelayState or resolve_url(settings.LOGIN_REDIRECT_URL)
        return render(request, 'mellon/authentication_failed.html',
                      {
                          'debug': settings.DEBUG,
                          'idp_message': idp_message,
                          'status_codes': status_codes,
                          'issuer': login.remoteProviderId,
                          'next_url': next_url,
                          'error_url': error_url,
                          'relaystate': login.msgRelayState,
                          'error_redirect_after_timeout': error_redirect_after_timeout,
                      })

    def sso_success(self, request, login):
        attributes = {}
        attribute_statements = login.assertion.attributeStatement
        for ats in attribute_statements:
            for at in ats.attribute:
                values = attributes.setdefault(at.name, [])
                for value in at.attributeValue:
                    content = [any.exportToXml() for any in value.any]
                    content = ''.join(content)
                    values.append(content.decode('utf8'))
        attributes['issuer'] = login.remoteProviderId
        if login.nameIdentifier:
            name_id = login.nameIdentifier
            name_id_format = unicode(name_id.format
                                     or lasso.SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED)
            attributes.update({
                'name_id_content': name_id.content.decode('utf8'),
                'name_id_format': name_id_format
            })
            if name_id.nameQualifier:
                attributes['name_id_name_qualifier'] = unicode(name_id.nameQualifier)
            if name_id.spNameQualifier:
                attributes['name_id_sp_name_qualifier'] = unicode(name_id.spNameQualifier)
        authn_statement = login.assertion.authnStatement[0]
        if authn_statement.authnInstant:
            attributes['authn_instant'] = utils.iso8601_to_datetime(authn_statement.authnInstant)
        if authn_statement.sessionNotOnOrAfter:
            attributes['session_not_on_or_after'] = utils.iso8601_to_datetime(
                authn_statement.sessionNotOnOrAfter)
        if authn_statement.sessionIndex:
            attributes['session_index'] = authn_statement.sessionIndex
        attributes['authn_context_class_ref'] = ()
        if authn_statement.authnContext:
            authn_context = authn_statement.authnContext
            if authn_context.authnContextClassRef:
                attributes['authn_context_class_ref'] = \
                    authn_context.authnContextClassRef
        self.log.debug('trying to authenticate with attributes %r', attributes)
        return self.authenticate(request, login, attributes)

    def authenticate(self, request, login, attributes):
        user = auth.authenticate(saml_attributes=attributes)
        next_url = self.get_next_url(default=resolve_url(settings.LOGIN_REDIRECT_URL))
        if user is not None:
            if user.is_active:
                utils.login(request, user)
                self.log.info('user %r (NameID is %r) logged in using SAML', unicode(user),
                              attributes['name_id_content'])
                request.session['mellon_session'] = utils.flatten_datetime(attributes)
                if ('session_not_on_or_after' in attributes and
                        not settings.SESSION_EXPIRE_AT_BROWSER_CLOSE):
                    request.session.set_expiry(
                        utils.get_seconds_expiry(
                            attributes['session_not_on_or_after']))
            else:
                self.log.warning('user %r (NameID is %r) is inactive, login refused', unicode(user),
                                 attributes['name_id_content'])
                return render(request, 'mellon/inactive_user.html', {
                    'user': user,
                    'saml_attributes': attributes})
        else:
            self.log.warning('no user found for NameID %r', attributes['name_id_content'])
            return render(request, 'mellon/user_not_found.html',
                          {'saml_attributes': attributes})
        if login.session:
            request.session['lasso_session_dump'] = login.session.dump()

        return HttpResponseRedirect(next_url)

    def retry_login(self):
        '''Retry login if it failed for a temporary error'''
        url = reverse('mellon_login')
        next_url = self.get_next_url()
        if next_url:
            url = '%s?%s' % (url, urlencode({REDIRECT_FIELD_NAME: next_url}))
        return HttpResponseRedirect(url)

    def continue_sso_artifact(self, request, method):
        idp_message = None
        status_codes = []

        if method == lasso.HTTP_METHOD_ARTIFACT_GET:
            message = request.META['QUERY_STRING']
            artifact = request.GET['SAMLart']
            relay_state = request.GET.get('RelayState')
        else:  # method == lasso.HTTP_METHOD_ARTIFACT_POST:
            message = request.POST['SAMLart']
            artifact = request.POST['SAMLart']
            relay_state = request.POST.get('RelayState')

        self.profile = login = utils.create_login(request)
        if relay_state and utils.is_nonnull(relay_state):
            login.msgRelayState = relay_state
        try:
            login.initRequest(message, method)
        except lasso.ProfileInvalidArtifactError:
            self.log.warning(u'artifact is malformed %r', artifact)
            return HttpResponseBadRequest(u'artifact is malformed %r' % artifact)
        except lasso.ServerProviderNotFoundError:
            self.log.warning('no entity id found for artifact %s', artifact)
            return HttpResponseBadRequest(
                'no entity id found for this artifact %r' % artifact)
        idp = utils.get_idp(login.remoteProviderId)
        if not idp:
            self.log.warning('entity id %r is unknown', login.remoteProviderId)
            return HttpResponseBadRequest(
                'entity id %r is unknown' % login.remoteProviderId)
        verify_ssl_certificate = utils.get_setting(
            idp, 'VERIFY_SSL_CERTIFICATE')
        login.buildRequestMsg()
        try:
            result = requests.post(login.msgUrl, data=login.msgBody,
                                   headers={'content-type': 'text/xml'},
                                   timeout=app_settings.ARTIFACT_RESOLVE_TIMEOUT,
                                   verify=verify_ssl_certificate)
        except RequestException, e:
            self.log.warning('unable to reach %r: %s', login.msgUrl, e)
            return self.sso_failure(request, login, _('IdP is temporarily down, please try again '
                                                      'later.'), status_codes)
        if result.status_code != 200:
            self.log.warning('SAML authentication failed: IdP returned %s when given artifact: %r',
                             result.status_code, result.content)
            return self.sso_failure(request, login, idp_message, status_codes)

        self.log.info('Got SAML Artifact Response', extra={'saml_response': result.content})
        try:
            login.processResponseMsg(result.content)
            login.acceptSso()
        except lasso.ProfileMissingResponseError:
            # artifact is invalid, idp returned no response
            self.log.warning('ArtifactResolveResponse is empty: dead artifact %r', artifact)
            return self.retry_login()
        except lasso.ProfileInvalidMsgError:
            self.log.warning('ArtifactResolveResponse is malformed %r', result.content[:200])
            if settings.DEBUG:
                return HttpResponseBadRequest('ArtififactResolveResponse is malformed\n%r' %
                                              result.content)
            else:
                return HttpResponseBadRequest('ArtififactResolveResponse is malformed')
        except lasso.ProfileCannotVerifySignatureError:
            self.log.warning('SAML authentication failed: signature validation failed for %r',
                             login.remoteProviderId)
        except lasso.ParamError:
            self.log.exception('lasso param error')
        except (lasso.LoginStatusNotSuccessError,
                lasso.ProfileStatusNotSuccessError,
                lasso.ProfileRequestDeniedError):
            status = login.response.status
            a = status
            while a.statusCode:
                status_codes.append(a.statusCode.value)
                a = a.statusCode
            args = ['SAML authentication failed: status is not success codes: %r', status_codes]
            if status.statusMessage:
                idp_message = status.statusMessage.decode('utf-8')
                args[0] += ' message: %r'
                args.append(status.statusMessage)
            self.log.warning(*args)
        except lasso.Error, e:
            self.log.exception('unexpected lasso error')
            return HttpResponseBadRequest('error processing the authentication response: %r' % e)
        else:
            return self.sso_success(request, login)
        return self.sso_failure(request, login, idp_message, status_codes)

    def request_discovery_service(self, request, is_passive=False):
        self_url = request.build_absolute_uri(request.path)
        url = app_settings.DISCOVERY_SERVICE_URL
        params = {
            # prevent redirect loops with the discovery service
            'entityID': request.build_absolute_uri(reverse('mellon_metadata')),
            'return': self_url + '?nodisco=1',
        }
        if is_passive:
            params['isPassive'] = 'true'
        url += '?' + urlencode(params)
        return HttpResponseRedirect(url)

    def get(self, request, *args, **kwargs):
        '''Initialize login request'''
        if 'SAMLart' in request.GET:
            return self.continue_sso_artifact(request, lasso.HTTP_METHOD_ARTIFACT_GET)

        # redirect to discovery service if needed
        if (not 'entityID' in request.GET
                and not 'nodisco' in request.GET
                and app_settings.DISCOVERY_SERVICE_URL):
            return self.request_discovery_service(
                request, is_passive=request.GET.get('passive') == '1')

        next_url = request.GET.get(REDIRECT_FIELD_NAME)
        idp = self.get_idp(request)
        if idp is None:
            return HttpResponseBadRequest('no idp found')
        self.profile = login = utils.create_login(request)
        self.log.debug('authenticating to %r', idp['ENTITY_ID'])
        try:
            login.initAuthnRequest(idp['ENTITY_ID'], lasso.HTTP_METHOD_REDIRECT)
            authn_request = login.request
            # configure NameID policy
            policy = authn_request.nameIdPolicy
            policy.allowCreate = utils.get_setting(idp, 'NAME_ID_POLICY_ALLOW_CREATE')
            policy.format = utils.get_setting(idp, 'NAME_ID_POLICY_FORMAT')
            force_authn = utils.get_setting(idp, 'FORCE_AUTHN')
            if force_authn:
                authn_request.forceAuthn = True
            if request.GET.get('passive') == '1':
                authn_request.isPassive = True
            # configure requested AuthnClassRef
            authn_classref = utils.get_setting(idp, 'AUTHN_CLASSREF')
            if authn_classref:
                authn_classref = tuple([str(x) for x in authn_classref])
                req_authncontext = lasso.Samlp2RequestedAuthnContext()
                authn_request.requestedAuthnContext = req_authncontext
                req_authncontext.authnContextClassRef = authn_classref

            authn_request.extensions = lasso.Samlp2Extensions()
            authn_request.extensions.setOriginalXmlnode(
                    '''<samlp:Extensions
                            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                            xmlns:eo="https://www.entrouvert.com/">
                          <eo:next_url>%s</eo:next_url>
                       </samlp:Extensions>''' %
                   escape(request.build_absolute_uri(next_url or '/')))
            self.set_next_url(next_url)
            login.buildAuthnRequestMsg()
        except lasso.Error, e:
            return HttpResponseBadRequest('error initializing the authentication request: %r' % e)
        self.log.debug('sending authn request %r', authn_request.dump())
        self.log.debug('to url %r', login.msgUrl)
        return HttpResponseRedirect(login.msgUrl)

# we need fine control of transactions to prevent double user creations
login = transaction.non_atomic_requests(csrf_exempt(LoginView.as_view()))


class LogoutView(ProfileMixin, LogMixin, View):
    def get(self, request):
        if 'SAMLRequest' in request.GET:
            return self.idp_logout(request)
        elif 'SAMLResponse' in request.GET:
            return self.sp_logout_response(request)
        else:
            return self.sp_logout_request(request)

    def idp_logout(self, request):
        '''Handle logout request emitted by the IdP'''
        self.profile = logout = utils.create_logout(request)
        try:
            logout.processRequestMsg(request.META['QUERY_STRING'])
        except lasso.Error, e:
            return HttpResponseBadRequest('error processing logout request: %r' % e)
        try:
            logout.validateRequest()
        except lasso.Error, e:
            self.log.warning('error validating logout request: %r' % e)
        issuer = request.session.get('mellon_session', {}).get('issuer')
        if issuer == logout.remoteProviderId:
            self.log.info(u'user logged out by IdP SLO request')
            auth.logout(request)
        try:
            logout.buildResponseMsg()
        except lasso.Error, e:
            return HttpResponseBadRequest('error processing logout request: %r' % e)
        return HttpResponseRedirect(logout.msgUrl)

    def sp_logout_request(self, request):
        '''Launch a logout request to the identity provider'''
        next_url = request.GET.get(REDIRECT_FIELD_NAME)
        referer = request.META.get('HTTP_REFERER')
        if not referer or utils.same_origin(referer, request.build_absolute_uri()):
            if request.user.is_authenticated():
                logout = None
                try:
                    issuer = request.session.get('mellon_session', {}).get('issuer')
                    if issuer:
                        self.profile = logout = utils.create_logout(request)
                        try:
                            if 'lasso_session_dump' in request.session:
                                logout.setSessionFromDump(request.session['lasso_session_dump'])
                            else:
                                self.log.error('unable to find lasso session dump')
                            logout.initRequest(issuer, lasso.HTTP_METHOD_REDIRECT)
                            logout.buildRequestMsg()
                        except lasso.Error, e:
                            self.log.error('unable to initiate a logout request %r', e)
                        else:
                            self.log.debug('sending LogoutRequest %r', logout.request.dump())
                            self.log.debug('to URL %r', logout.msgUrl)
                            return HttpResponseRedirect(logout.msgUrl)
                finally:
                    auth.logout(request)
                    # set next_url after local logout, as the session is wiped by auth.logout
                    if logout:
                        self.set_next_url(next_url)
                    self.log.info(u'user logged out, SLO request sent to IdP')
        else:
            self.log.warning('logout refused referer %r is not of the same origin', referer)
        return HttpResponseRedirect(next_url)

    def sp_logout_response(self, request):
        '''Launch a logout request to the identity provider'''
        self.profile = logout = utils.create_logout(request)
        # the user shouldn't be logged anymore at this point but it may happen
        # that a concurrent SSO happened in the meantime, so we do another
        # logout to make sure.
        auth.logout(request)
        try:
            logout.processResponseMsg(request.META['QUERY_STRING'])
        except lasso.ProfileStatusNotSuccessError:
            self.show_message_status_is_not_success(logout, 'SAML logout failed')
        except lasso.LogoutPartialLogoutError:
            self.log.warning('partial logout')
        except lasso.Error, e:
            self.log.warning('unable to process a logout response: %s', e)
            return HttpResponseRedirect(resolve_url(settings.LOGIN_REDIRECT_URL))
        next_url = self.get_next_url(default=resolve_url(settings.LOGIN_REDIRECT_URL))
        return HttpResponseRedirect(next_url)


logout = LogoutView.as_view()


def metadata(request):
    metadata = utils.create_metadata(request)
    return HttpResponse(metadata, content_type='text/xml')
