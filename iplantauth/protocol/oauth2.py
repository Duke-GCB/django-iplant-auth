import requests

from django.http import HttpResponseRedirect
from django.utils import timezone

from oauth2client.client import OAuth2WebServerFlow
from oauth2client.client import Error as OAuthError
from base64 import b64encode
from iplantauth.models import (
    get_or_create_user, create_token, destroy_tokens)
from iplantauth.settings import auth_settings
import logging
logger = logging.getLogger(__name__)

# Modeled after globus.py

def _oauth2_initFlow():
    userAndPass = "%s:%s" % (auth_settings.OAUTH2_CLIENT_ID, auth_settings.OAUTH2_CLIENT_SECRET)
    b64_userAndPass = b64encode(userAndPass)
    auth_header = "Basic %s" % b64_userAndPass
    flow = OAuth2WebServerFlow(
        client_id=auth_settings.OAUTH2_CLIENT_ID,
        scope=auth_settings.OAUTH2_SCOPE,
        authorization_header=auth_header,
        redirect_uri=auth_settings.OAUTH2_REDIRECT_URI,
        auth_uri=auth_settings.OAUTH2_AUTHORIZE_URI,
        token_uri=auth_settings.OAUTH2_TOKEN_URI)
    return flow

def _get_state():
    return 'abec00c92b3499501fcbaace639579a0dd09d7ff' #TODO: make dynamic and track

def oauth2_authorize():
    flow = _oauth2_initFlow()
    auth_uri = flow.step1_get_authorize_url(state=_get_state())
    return HttpResponseRedirect(auth_uri)

def oauth2_profile_for_token(token):
    resource_url = 'https://oauth.oit.duke.edu/oauth/resource'
    try:
        resource = requests.get(resource_url, params={'access_token':token}).json()
    except requests.RequestException as err:
        logger.exception("Error getting user resource with access token", err)
    username = resource['eppn']
    # TODO: Get real email/first/last
    email = resource['eppn']
    first_name = ''
    last_name = ''
    if not username:
        logger.info("User %s is not part of the 'valid mapping' and will be skipped!" % resource)
        return None

    user_profile = {
        'username':username,
        'firstName':first_name,
        'lastName':last_name,
        'email': email,
    }

    return user_profile

def oauth2_validate_code(request):
    code = request.GET['code']
    if not code:
        return None
    flow = _oauth2_initFlow()
    try:
        # Exchange the code for credentials
        credentials = flow.step2_exchange(code)
        logger.info(credentials.__dict__)
    except OAuthError as err:
        logger.exception("Error exchanging code w/ OAuth2 provider")
        return None

    # Sample JSON payload from code
    # {u'access_token': u'',
    #  u'expires_at': 1465232138.685905,
    #  u'expires_in': 3600,
    #  u'refresh_token': u'',
    #  u'scope': [u'basic'],
    #  u'token_type': u'Bearer'}

    # This token doesn't have any identity/profile, just token, expiration, refresh,
    user_access_token = credentials.access_token
    # TODO: Save the refresh token and implement refresh.
    expiry_date = credentials.token_expiry
    user_profile = oauth2_profile_for_token(user_access_token)
    _ = get_or_create_user(user_profile['username'], user_profile)
    auth_token = create_token(user_profile['username'], user_access_token, expiry_date, None) # issuer = None
    return auth_token

def _extract_expiry_date(epoch_secs):
    if type(epoch_secs) != int:
        try:
            epoch_secs = int(epoch_secs)
        except:
            logger.exception("Expected date to be an integer (Seconds from epoch). This method should be modified to the new use case for globus 'exp'")
            return None
    epoch = timezone.datetime(month=1, day=1, year=1970)
    return epoch + timezone.timedelta(seconds=epoch_secs)


def create_user_token_from_oauth2_profile(profile, access_token):
    logger.info(profile)
    expiry = profile['exp'] # This is an 'epoch-int'
    expiry = _extract_expiry_date(expiry)
    issued_at = profile['iat']
    raw_username = profile['username']  # username@login_auth.com
    raw_name = profile['name']
    email = profile['email']
    username = raw_username
    # TODO: Get real email/first/last

    # TODO: why is this distinct from oauth2_profile_for_token?
    # These should be refactored together

    first_name, last_name = ('','')
    profile_dict = {
        'username':username,
        'firstName':first_name,
        'lastName':last_name,
        'email': email,
    }
    user = get_or_create_user(username, profile_dict)
    user_token = create_token(user.username, access_token, expiry)
    return user_token


def oauth2_delete_tokens(request):
    destroy_tokens(request.user.username)