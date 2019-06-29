import logging
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient import errors
import base64
import json
import re
# pylint: disable=E1103

logger = logging.getLogger(__name__)

GOOGLE_APP_CREDS_PATH = os.environ.get('GOOGLE_APP_CREDS_PATH', None)
DEFAULT_USER_EMAIL = os.environ.get('DEFAULT_USER_EMAIL', None)
PUBSUB_TOPIC = os.environ.get('PUBSUB_TOPIC', None)

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
    service = build('gmail', 'v1', credentials=credentials)

    if service:
        logger.info('gmail service active')
        return service
    else:
        logger.info('gmail service failed')
        raise Exception  # check kg error domain for appropes


def _auth_with_api_key(key):
    service = build('gmail', 'v1', developerKey=key)

    if service:
        logger.info('gmail service active')
        return service
    else:
        logger.info('gmail service failed')
        raise Exception  # check kg

# Another BaseGoogleAPI method __init__ probably


def init_gmail_service(userId, scopes=None):
    """
    General service login for server-to-server Google API requests.
    :param scopes: list of google API scope URIs for which the server
        attempts authorization for
    """
    logger.info('building gmail service')

    try:
        if not scopes:
            scopes = ['https://www.googleapis.com/auth/gmail.readonly']
        if not userId:
            userId = DEFAULT_USER_EMAIL

        creds_file = GOOGLE_APP_CREDS_PATH
        creds = service_account.Credentials.from_service_account_file(
            creds_file, scopes=scopes)

        if userId:
            creds = creds.with_subject(userId)

        service = _auth_with_creds(credentials=creds)

        logger.info('gmail service built')
        return service
    except errors.HttpError as error:
        logger.exception('gmail http setup error %s', error)
        return None
    except Exception as error:
        logger.exception('gmail setup error: %s', error)
        return None


def push_subscribe(service, userId, topicName):
    """
    Method subscribe a userId to gmail authenticated service
    with a given topic
    :param service: authenticated googleapiclient.discovery.build instance
    :param userId: email account to be watched and synced
    :param topicName: topic string to subscribe too, as setup in the console
    :param historyId: can be used if we sync
    """

    assert service is not None
    logger.info('attempting unsubscribe to topic: %s', topicName)
    push_unsubscribe(service, userId)

    logger.info('attempting subscribe to topic: %s for %s', topicName, userId)
    subscribe_request = {
        'labelIds': ['INBOX'],
        'topicName': topicName,
        'labelFilterAction': 'include'
    }

    response = None
    response = service.users().watch(
        userId=userId, body=subscribe_request).execute()

    if 'error' in response:
        # The API executed, but the script returned an error.
        # Exception should go up the chain of domain
        error = response['error']['details'][0]
        logging.error("Script error! Message: {0}".format(
            error['errorMessage']))
        raise errors.HttpError

    return response


def push_unsubscribe(service=None, userId=''):
    """
    Method to ensure no subscription exists for a given userId.
    Subsequent watch calls will result in multiple subscription
    instances and hence, multiple deliveries of the same message.
    You cannot stop for individual topics
    :param service: authenticated googleapiclient.discovery.build instance
    :param userId: the id of the account of which to unsubscribe from
    """
    if not userId:
        userId = DEFAULT_USER_EMAIL

    if not service:
        service = init_gmail_service(
            userId=userId,
            scopes=['https://www.googleapis.com/auth/gmail.readonly']
        )
    response = service.users().stop(userId=userId).execute()
    logger.info('gmail hook stopped')
    return response

# this will move to celery tasks
# @app.task()


def sync_gmail_handler(userId=None, topicName=None):
    """
    Primary method to ensure a proper gmail handler is setup,
    synced, and watching with only one subscription. It does this
    by handling authentication, unsubscribing any existing, syncing,
    then starting beginning a new subscription to the topic specified
    for the account specified
    :param userId: email account to be watched and synced
    :param topicName: topic string to subscribe too, as setup in the console

    history should have
    {
      "historyId": unsigned long,
      "expiration": long
    }
    """
    # TODO: add Sync flow
    # Add config here
    if not userId:
        userId = DEFAULT_USER_EMAIL
    if not topicName:
        topicName = PUBSUB_TOPIC
    try:
        service = init_gmail_service(
            userId=userId,
            scopes=['https://www.googleapis.com/auth/gmail.readonly']
        )
        # it seems like service should have userId, topicName, and scopes
        # already read accessible. I'd prefer that
        push_history = push_subscribe(
            service,
            userId=userId,
            topicName=topicName
        )

        if not push_history['historyId']:
            logger.error("Gmail push historyId is missing ")
            raise ValueError
        return push_history
    except AssertionError as error:
        logger.error('AssertionError in gmail resync and watch. Retry')
    except errors.HttpError as error:
        logger.error(error)
    except Exception as error:
        logger.error('Error starting gmail service: {}'. format(error))
        raise ValueError


def decode_message_data(message):
    message_data = base64.urlsafe_b64decode(
        message.get('data').encode('UTF-8'))
    return message_data


# Just really need a schema. There's no way to name this properly haha
def get_origin_from_push_data(push_data):
    """
    Take incoming push data and return the emailAddress expression after
    deserializing
    """
    message_meta = get_event_meta_from_push_data(push_data)
    return message_meta[
        'emailAddress'] if 'emailAddress' in message_meta else None

# Just really need a schema. There's no way to name this properly haha


def get_event_meta_from_push_data(push_data):
    """
    Take incoming push data and return the data packet containing
    emailAddress and historyId
    """
    try:
        return json.loads(decode_message_data(push_data.get('message')))
    except AttributeError:
        return get_event_meta_from_message(push_data)


def get_event_meta_from_message(message):
    """
    Return message-specific meta for processing event
    """
    return {
        "historyId": "{}".format(str(get_message_history_id(message))),
        "emailAddress": "{}".format(get_message_sender_address(message))}
# Just really need a schema. There's no way to name this properly haha


def get_history_id_from_message_meta(message_meta):
    """
    Accept message meta from push notifaction and obtain the sender or
    userId as called in the protocol
    """
    return message_meta['historyId'] if 'historyId' in message_meta else None


def get_change_meta(service, userId, startHistoryId=1):
    """
    Obtain the full packet of changes by the history ID that is sent
    in notifications
    """
    # This is very much like sync and should be combined
    assert service is not None
    assert userId is not None

    try:
        history = (
            service.users().history().list(
                userId=userId,
                startHistoryId=startHistoryId).execute())
        changes = history['history'] if 'history' in history else []

        while 'nextPageToken' in history:
            page_token = history['nextPageToken']
            history = (
                service.users().history().list(
                    userId=userId,
                    startHistoryId=startHistoryId,
                    pageToken=page_token).execute())
            changes.extend(
                history['history'] if 'history' in history else [])

        return changes
    except errors.HttpError as error:
        logger.error('An error occurred: %s', error)
        # Error chaining only works in python3


def get_new_messages(service, userId, historyId=1):
    # Add changes as class property
    """
    Accept message meta and check for new messages added.
    There can also be messages deleted and other history
    changes events, so we need to check this first.
    Packet:
    change = {
        u'messages': [
            {u'id': u'string-id', u'threadId': u'string-id'}
        ],
        u'id': u'int-id',
        u'messagesAdded': [
            {
                u'message': {
                    u'labelIds': [
                        u'UNREAD', u'CATEGORY_PERSONAL', u'INBOX'
                    ],
                    u'id': u'string-id',
                    u'threadId': u'string-id'
                }
            }
        ]
    }
    """
    newMessages = []
    changes = get_change_meta(service, userId, historyId)
    if changes:
        newMessages.extend([messageAdded['message']
                            for change in changes if 'messagesAdded' in change
                            for messageAdded in change['messagesAdded']])
        return newMessages
    else:
        return None


def get_new_messages_from_history(
        service,
        userId,
        history_id,
        full_data=False):
    """
    Call Gmail to find out to get new messages based on
    push data sent from GMail
    :param service: authorized service object created with init_gmail_service
    :param push_json: json packet from sent from incoming push request
    """
    # history_id = get_history_id_from_message_meta(message_meta)
    logger.info("Processing Messages for History Id : {}".format(history_id))

    if full_data:
        messages = get_new_messages(
            service=service,
            userId=userId,
            historyId=history_id
        )
        if messages:
            return [get_message_data(
                service=service,
                userId=userId,
                messageId=message['id']) for message in messages]
        else:
            return []
    else:
        return get_new_messages(
            service=service,
            userId=userId,
            historyId=history_id
        )


def get_message_data(service, userId, messageId, is_mime=False):
    if not is_mime:
        return service.users()\
            .messages()\
            .get(userId=userId, id=messageId)\
            .execute()
    else:
        # do a bunch of mime message stuff
        return None


def get_message_subject(message):
    """
    Obtain subject from headers in message payload.
    An actual message has a payload expression:
    "payload": {
        "partId": string,
        "mimeType": string,
        "filename": string,
        "headers": [
          {
            "name": string,
            "value": string
          }
        ],
        "body": users.messages.attachments Resource,
        "parts": [
          (MessagePart)
        ]
    },
    https://developers.google.com/gmail/api/v1/reference/users/messages
    """
    return [header['value'] for header in message['payload'][
        'headers'] if header['name'].lower() == 'subject'][0]


def extract_email_from_text(text):
    """
    Gmail From comes like
    First Last <hello@mail.com>
    """
    regex = re.compile(r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b')
    return regex.findall(text)[0]


def get_message_sender_address(message):
    """
    Obtain from email address from headers in message payload.
    An actual message has a payload expression:
    "payload": {
        .
        "headers": [
          {
            "name": string,
            "value": string
          }
        ],
        .
    },
    https://developers.google.com/gmail/api/v1/reference/users/messages
    """
    return [extract_email_from_text(header['value'])
            for header in message['payload']['headers']
            if header['name'].lower() == 'from'][0]


def get_message_history_id(message):
    """
    Obtain the historyId from the full user message
    """
    return message['historyId']


def parse_message_details(full_message):
    """
    Entry method to pass in full message details and move
    through parts of its payload to assemble parts into
    wholes
    """
    text = ''
    try:
        if 'parts' in full_message['payload']:
            text_parts = get_text_message_parts(full_message)
        else:
            text_parts = [full_message['payload']]

        for part in text_parts:
            if 'data' in part['body']:
                text += decode_message_data(part['body'])

    except KeyError as error:
        logger.error('A KeyError occurred getting text: %s', error)

    return text.rstrip('\r\n')


def get_attachment_bytes(message, service, userId=''):
    """
    Obtain attachments as byte generator. Treat as multipart.
    """
    if not userId:
        userId = DEFAULT_USER_EMAIL

    try:
        attachment_parts = get_attachment_message_parts(message)
        message_id = message['id']
        file_data = {}
        for part in attachment_parts:
            if part['filename']:
                if 'data' in part['body']:
                    file_data['data'] = decode_message_data(part['body'])
                    file_data['mimeType'] = part['mimeType']
                    file_data['fileName'] = part['filename']
                else:
                    attach_id = part['body']['attachmentId']
                    attachment = service.users()\
                        .messages()\
                        .attachments()\
                        .get(userId=userId,
                             messageId=message_id,
                             id=attach_id)\
                        .execute()
                    file_data['mimeType'] = part['mimeType'].encode('utf-8')
                    file_data['fileName'] = part['filename'].encode('utf-8')
                    file_data['data'] = decode_message_data(attachment)
                yield file_data

    except KeyError as error:
        logger.error(
            'A KeyError occurred getting attachement bytes: %s',
            error)

    except errors.HttpError as error:
        logger.error('An error occurred getting bytes: %s', error)


def get_text_message_parts(message):
    """
    Filter multipart message for parts that have a mimetype
    key with non-empty value
    """
    if not 'parts' in message['payload']:
        return [message['payload']]
    return [part for part in message_payload_parts(message['payload'])
            if part['mimeType'] == 'text/plain']


def get_attachment_message_parts(message):
    """
    Filter multipart message for just parts that have a filename
    key with non-empty value
    """
    if not 'parts' in message['payload']:
        return [message['payload']]
    return [part for part in message_payload_parts(message['payload'])
            if part['filename']]


def message_has_attachment(message):
    """
    Check if full message has attachment
    """
    if not 'parts' in message['payload']:
        return False
    if get_attachment_message_parts(message):
        return True
    else:
        return False


def message_payload_parts(payload):
    """
    Recursive generator to get nested parts in a message payload.
    :param payload: equivilent of full_message['payload']
    """
    for k, v in payload.iteritems():
        if isinstance(v, dict):
            if 'mimeType' in v.keys():
                if (v == 'multipart/related' or
                        v == 'multipart/mixed'):
                    for multi_parts in message_payload_parts(v):
                        yield multi_parts

        elif isinstance(v, list):
            for d in v:
                for related_parts in message_payload_parts(d):
                    yield related_parts

        else:
            if k == 'mimeType':
                if v == 'multipart/alternative':
                    for part in payload['parts']:
                        if 'parts' in part.keys():
                            for ppart in message_payload_parts(part):
                                yield ppart
                        else:
                            yield part
                    break
                else:
                    yield payload
