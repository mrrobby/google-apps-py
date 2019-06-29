import logging
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient import errors

# pylint: disable=E1103

logger = logging.getLogger(__name__)

GOOGLE_APP_CREDS_PATH = os.environ.get('GOOGLE_APP_CREDS_PATH', None)
DEFAULT_USER_EMAIL = os.environ.get('DEFAULT_USER_EMAIL', None)
GSUITE_DOMAIN = os.environ.get('GSUITE_DOMAIN', None)

def _auth_with_creds(credentials):
    """
    Call API build commands with Google Credentials object.
    Use this method to catch various login errors and handle
    appropriately.

    :param credentials: service_account.Credentials instance
    """
    service = build(
        'admin',
        'directory_v1',
        credentials=credentials,
        cache_discovery=False)

    if service:
        logger.info('gsuite directory service active')
        return service
    else:
        logger.info('gsuite directory service failed')
        raise Exception  # check kg error domain for appropes


def init_gsuite_admin_service(user_id=None, scopes=None):
    """
    General service login for server-to-server Google API requests.
    :param scopes: list of google API scope URIs for which the server
        attempts authorization for
    """
    logger.info('building gsuite service')

    try:
        if not scopes:
            scopes = [
                'https://www.googleapis.com/auth/admin.directory.user.readonly']
        if not user_id:
            user_id = DEFAULT_USER_EMAIL

        # Change this to be google_delegated
        creds = service_account.Credentials.from_service_account_file(
            GOOGLE_APP_CREDS_PATH, scopes=scopes)

        if user_id:
            creds = creds.with_subject(user_id)

        service = _auth_with_creds(credentials=creds)

        logger.info('gsuite admin service built')
        return service
    except errors.HttpError as error:
        logger.exception('gsuite admin http setup error %s', error)
        return None
    except Exception as error:
        logger.exception('gsuite admin setup error: %s', error)
        return None


def generate_gsuite_users(service, is_admin=False, max_results=50):
    """
    Generate admin only or non-admin users from directory
    :param service: required authenticated service object
    :param is_admin: true if admin only, false for non-admins
    :param max_results: per page for pagination, default is 50
        and max is 500

    :return array: array of user dictionaries
    [
        {
           "kind": "admin#directory#user",
           "id": bigint,
           "etag": string,
           "primaryEmail": user-email-string,
           "name": {
            "givenName": string,
            "familyName": string,
            "fullName": string
           },
           "isAdmin": bool,
           "isDelegatedAdmin": bool,
           "lastLoginTime": iso8601 datetime,
           "creationTime": iso8601 datetime,
           "agreedToTerms": bool,
           "suspended": bool,
           "changePasswordAtNextLogin": bool,
           "ipWhitelisted": bool,
           "emails": [
            {
             "address": string,
             "primary": bool
            }
           ],
           "nonEditableAliases": [
                string,
           ],
           "customerId": string,
           "orgUnitPath": "/",
           "isMailboxSetup": bool,
           "isEnrolledIn2Sv": bool,
           "isEnforcedIn2Sv": boool,
           "includeInGlobalAddressList": bool
        },
    ]
    """
    assert service is not None

    logger.info('Getting the first {} users in the domain'.format(max_results))
    page_token = None

    if is_admin:
        is_admin_str = 'true'
    else:
        is_admin_str = 'false'

    while True:
        # Call the Admin SDK Directory API
        results = service.users().list(
            domain=GSUITE_DOMAIN,
            maxResults=max_results,
            pageToken=page_token,
            query='isAdmin={}'.format(is_admin_str)).execute()

        yield results.get('users', [])
        page_token = results.get('nextPageToken')
        if not page_token:
            break
