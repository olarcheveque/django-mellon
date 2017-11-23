import sys


class AppSettings(object):
    __PREFIX = 'MELLON_'
    __DEFAULTS = {
        'DISCOVERY_SERVICE_URL': None,
        'PUBLIC_KEYS': (),
        'PRIVATE_KEY': None,
        'PRIVATE_KEYS': (),
        'PRIVATE_KEY_PASSWORD': None,
        'NAME_ID_FORMATS': (),
        'NAME_ID_POLICY_FORMAT': None,
        'NAME_ID_POLICY_ALLOW_CREATE': True,
        'FORCE_AUTHN': False,
        'ADD_AUTHNREQUEST_NEXT_URL_EXTENSION': False,
        'ADAPTER': (
            'mellon.adapters.DefaultAdapter',
        ),
        'REALM': 'saml',
        'PROVISION': True,
        'USERNAME_TEMPLATE': '{attributes[name_id_content]}@{realm}',
        'ATTRIBUTE_MAPPING': {},
        'SUPERUSER_MAPPING': {},
        'AUTHN_CLASSREF': (),
        'GROUP_ATTRIBUTE': None,
        'CREATE_GROUP': True,
        'ERROR_URL': None,
        'ERROR_REDIRECT_AFTER_TIMEOUT': 120,
        'DEFAULT_ASSERTION_CONSUMER_BINDING': 'post',  # or artifact
        'VERIFY_SSL_CERTIFICATE': True,
        'OPENED_SESSION_COOKIE_NAME': None,
        'OPENED_SESSION_COOKIE_DOMAIN': None,
        'ORGANIZATION': None,
        'CONTACT_PERSONS': [],
        'TRANSIENT_FEDERATION_ATTRIBUTE': None,
        'LOGIN_URL': 'mellon_login',
        'LOGOUT_URL': 'mellon_logout',
        'ARTIFACT_RESOLVE_TIMEOUT': 10.0,
    }

    @property
    def IDENTITY_PROVIDERS(self):
        from django.conf import settings
        try:
            idps = settings.MELLON_IDENTITY_PROVIDERS
        except AttributeError:
            from django.core.exceptions import ImproperlyConfigured
            raise ImproperlyConfigured('The MELLON_IDENTITY_PROVIDERS setting is mandatory')
        if isinstance(idps, dict):
            idps = [idps]
        return idps

    def __getattr__(self, name):
        from django.conf import settings
        if name not in self.__DEFAULTS:
            raise AttributeError
        return getattr(settings, self.__PREFIX + name, self.__DEFAULTS[name])

app_settings = AppSettings()
app_settings.__name__ = __name__
sys.modules[__name__] = app_settings
