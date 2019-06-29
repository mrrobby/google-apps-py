import logging
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient import errors
# pylint: disable=E1103

logger = logging.getLogger(__name__)

GOOGLE_APP_CREDS_PATH = os.environ.get('GOOGLE_APP_CREDS_PATH', None)
DEFAULT_USER_EMAIL = os.environ.get('DEFAULT_USER_EMAIL', None)
CHANNEL_ID = os.environ.get('CHANNEL_ID', None)
GCAL_HOSTNAME = os.environ.get('GCAL_HOSTNAME', None)
GCAL_API_ENDPOINT = os.environ.get('GCAL_API_ENDPOINT', None)
DEFAULT_AUTH_TOKEN = os.environ.get('GCAL_API_ENDPOINT', None)

# Good reference for message structure
# https://www.ehfeng.com/gmail-api-mime-types/

# Consider moving this into a BaseGoogleAPI class and extending
# mail and maps, then also adding calendar
# we can create factory method to build each service in here


def _auth_with_creds(credentials):
    """
    Call API build commands with Google Credentials object.
    Use this method to catch various login errors and handle
    appropriately.

    :param credentials: service_account.Credentials instance
    """
    service = build(
        'calendar',
        'v3',
        credentials=credentials,
        cache_discovery=False)

    if service:
        logger.info('GCal service active')
        return service
    else:
        logger.info('GCal service failed')
        raise Exception  # check kg error domain for appropes


def _init_gcal_service(user_id, scopes=None):
    """
    General service login for server-to-server Google API requests.
    :param scopes: list of google API scope URIs for which the server
        attempts authorization for
    """
    assert user_id is not None

    logger.info('Building GCal service')

    try:
        if not scopes:
            scopes = ['https://www.googleapis.com/auth/calendar.readonly']
        if not user_id:
            user_id = DEFAULT_USER_EMAIL

        # Change this to be google_delegated
        creds_file = GOOGLE_APP_CREDS_PATH
        creds = service_account.Credentials.from_service_account_file(
            creds_file, scopes=scopes)

        if user_id:
            creds = creds.with_subject(user_id)

        service = _auth_with_creds(credentials=creds)

        logger.info('GCal service built')
        return service
    except errors.HttpError as error:
        logger.exception('GCal http setup error %s', error)
        return None
    except Exception as error:
        logger.exception('GCal setup error: %s', error)
        return None


def push_subscribe(
        service,
        calendar_id,
        channel_id='',
        handler_url='',
        token=''):
    """
    Method subscribe a calendar_id to gcal authenticated service
    with a given topic, raises AssertionError if no service or calendar_id
    :param service: authenticated googleapiclient.discovery.build instance
    :param calendar_id: email account to be watched and synced
    :param topicName: topic string to subscribe too, as setup in the console
    :param historyId: can be used if we sync
    :return response: response dictionary from watch command containing:
        'resourceUri' --> api specific resource URI
        'kind' --> resource type "api#channel"
        'resourceId' --> important ID for reference to the subscription
        'token' --> session id for webhook
        'expiration' --> unavoidable expiration time
        'id' --> channel ID of the subscription

    """

    assert service is not None
    channelUuid = CHANNEL_ID
    logger.info('Attempting subscribe to channel: %s', channelUuid)

    if not handler_url:
        handler_url = "https://{}/{}/".format(
            GCAL_HOSTNAME, GCAL_API_ENDPOINT)

    if not token:
        token = DEFAULT_AUTH_TOKEN

    subscribe_request = {
        "id": channelUuid,
        "type": "web_hook",
        "address": handler_url,
        "token": token
    }

    # Otherwise, we'll just keep getting a bunch of illegal requests
    assert "id" in subscribe_request
    assert "token" in subscribe_request
    assert "address" in subscribe_request

    assert subscribe_request["id"] is not None
    assert subscribe_request["token"] is not None
    assert subscribe_request["address"] is not None

    response = None
    try:
        response = service.events().watch(
            calendarId=calendar_id, body=subscribe_request).execute()
    except errors.HttpError as error:
        logger.info(
            "Denied from Re-subscribing to calendar ID: %s. This is likely due to a missing a resource: %s.",
            calendar_id,
            error)
        return None
    except Exception as error:
        logger.info(
            "Exception on Re-Subscribe for calendar ID: %s. %s",
            calendar_id,
            error)
        return None

    return response


def push_unsubscribe(service, resource_id, channel_id=''):
    """
    Method to ensure no subscription exists for a given userId.
    Subsequent watch calls will result in multiple subscription
    instances and hence, multiple deliveries of the same message.
    You cannot stop for individual topics
    :param service: authenticated googleapiclient.discovery.build instance
    :param user_id: the user we wish to mock to start a service and stop
    :param resource_id: the id of the account of which to unsubscribe from
    :param channel_id: optional channel_id of the subscribtion, defaults
        to the configuration channel_id
    """
    assert service is not None

    if not channel_id:
        channel_id = CHANNEL_ID

    body = {
        'id': channel_id,
        'resourceId': resource_id
    }

    try:
        response = service.channels().stop(body=body).execute()
        logger.info('Gcal hook stopped for resource: %s', resource_id)
        return response
    except AttributeError as e:
        logger.info(
            'Gcal hook stop attempt Attribute error was thrown for resource: %s - %s',
            resource_id,
            e)
    except errors.HttpError as error:
        logger.info(
            'Gcal hook stop attempt rejected for resource: %s - This can be a result of an inactive subscription',
            resource_id)
    except Exception as e:  # I really want us to build a standard error domain
        logger.info(
            'Gcal hook stop attempt rejected for resource: %s - This can be a result of an inactive subscription',
            resource_id)


def remove_subscription_with_email(email, resource_id, channel_id=''):
    """
    Public method to unscubscribe a calendar by supplying the adaquate
    params.
    :param email: the email address that is definitely associated with the
        account
    :param resource_id: the id of the account of which to unsubscribe from
    :param channel_id: optional channel_id of the subscribtion, defaults
        to the configuration channel_id if empty
    """

    assert email
    assert resource_id

    service = _init_gcal_service(user_id=email)
    assert service

    push_unsubscribe(service, resource_id, channel_id)


def refresh_calendar_subscriptions(**kwargs):
    """
    Full cycle of stop and watch commands to google api
    for calendar subscriptions.

    Expect kwargs to contain some form of:
    {
        'calendar_id': string,
        'channel_id': UUID string,
        'resource_id': null or string,
        'next_sync_token': null or string,
        'email': required string
        'subscription_state': exists or not_exists
    }

    Consider changing subscription_state naming or
    adding a google enum to keep it consistant as
    google only here
    """
    # TODO fix kwargs documentation

    email = kwargs.get('email', None)
    if email is None:
        raise AttributeError('email is missing')

    calendar_id = kwargs.get('calendar_id', None)
    channel_id = kwargs.get('channel_id', None)
    subscription_state = kwargs.get('subscription_state', 'not_exists')
    resource_id = kwargs.get('resource_id', None)
    # May not need this yet
    next_sync_token = kwargs.get('next_sync_token', None)

    service = _init_gcal_service(user_id=email)
    # If this gets lost, we can't get it. Add in extra error
    # handling loop that is a pain

    if resource_id is not None:
        logger.info("Resource ID Supplied. Calling Unsubscribe")
        push_unsubscribe(service, resource_id, channel_id)

    logger.info("Calling Subscribe")
    subscription_info = push_subscribe(
        service=service,
        calendar_id=calendar_id,
        channel_id=channel_id
    )
    return subscription_info


# Can use syncToken, or we can just get all of them each time


def get_user_calendar_list(email, sort_list=False):
    """
    Get all calendars as full response from google or sorted calendar IDs
    :param email: user email address for which to obtain calendars
    :param sort_list: if True, it will return a sorted list of active
        and deleted calendar IDs, otherwise a full google API response
        will be returned. Default is False
    """
    try:
        service = _init_gcal_service(email)
    except google.auth.exceptions.RefreshError as e:
        logger.exception("Unauthorized Flagged: {}".format(email))
        #: ('unauthorized_client: Client is unauthorized to retrieve access tokens using this method.', u'{\n  "error" : "unauthorized_client",\n  "error_description" : "Client is unauthorized to retrieve access tokens using this method."\n}')
    except Exception as e:
        logger.error("Service auth error for: {}".format(email))
        raise
    # a max count probably won't be hit to need paging but just in case
    page_token = None
    full_list = {}
    full_list['items'] = []

    while True:

        calendar_list = service.calendarList().list(
            pageToken=page_token,
            minAccessRole='owner',
            showDeleted=True
        ).execute()

        full_list['items'].extend(calendar_list['items'])
        page_token = calendar_list.get('nextPageToken')

        if not page_token:
            break

    if sort_list:
        return get_calender_ids_from_list(email=email, calendar_list=full_list)

    return full_list


def get_event_changes(
        calendar_id,
        email='',
        service=None,
        sync_token='',
        date_updated=''):
    """
    Return a list of calendar event items that have occurred either since the last
    sync token or since the last date updated (updatedMin). This looks at a
    direct calendar Id which should be supplied with an authenticated service
    corresponding to the user account email associated with the owner of the
    calendar with calendar_id. If the sync token has expired, a 410 will be
    returned. See below. It is up to the caller then to obtain the last date and
    re-call this function.

    :param service: authenticated google service
    :param email: alternate to service email address which will be used
    in attempts to authenticate
    :param calendar_id: used as the calendarId
    :param sync_token: string associated with the last set of events. this should
    be stored with the calendar subscription along with the date last updated
    :param date_updated: RFC3339 timestamp with mandatory time zone offset supplied
    as an alternate to sync_token. This can be used if the sync_token has expired
    but cannot be used in conjunction with the sync token

    Note - If the syncToken expires, the server will respond with a 410 GONE
        response code and it's recommended the client should clear its storage
        and perform a full synchronization without any syncToken. The full sync
        is overkill. Instead we need to increment on our own with date_updated.

    """
    assert email or service

    if not service:
        service = _init_gcal_service(user_id=email)

    page_token = None
    event_changes = {}
    event_changes['items'] = []

    while True:

        if sync_token:
            events = service.events().list(
                calendarId=calendar_id,
                syncToken=sync_token,
                pageToken=page_token,
                showDeleted=True,
                singleEvents=True).execute()

        elif date_updated:
            events = service.events().list(
                calendarId=calendar_id,
                updatedMin=date_updated,
                pageToken=page_token,
                showDeleted=True,
                singleEvents=True).execute()

        else:
            events = service.events().list(
                calendarId=calendar_id,
                pageToken=page_token,
                showDeleted=True,
                singleEvents=True).execute()

        if 'error' in events.keys():
            return events.get('error')

        next_sync_token = events.get('nextSyncToken')
        event_changes['nextSyncToken'] = next_sync_token

        for event in events['items']:
            event_changes['items'].append(event)

        page_token = events.get('nextPageToken')

        if not page_token:
            return event_changes


def get_calender_ids_from_list(email, calendar_list):
    """
    Parse calendar_list and to retrieve calendar_ids, separated
    to active and deleted

    Response:
    {
      "active":["id1","id2"],
      "deleted":["id3","id4"]
    }
    """
    assert calendar_list['items']

    response = {}
    response['email'] = email
    response['active'] = []
    response['deleted'] = []

    for item in calendar_list['items']:

        if 'deleted' in item.keys():
            if item['deleted']:
                response['deleted'].append(item['id'])
            else:
                response['active'].append(item['id'])
        else:
            response['active'].append(item['id'])

    return response
