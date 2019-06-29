## Google Apps Wrapper

This is unmaintained, but can be used with some adjustments as it has been tested well.

To use, you must set environment variables, as of now.


## Gmail API with Google PubSub
```
GOOGLE_APP_CREDS_PATH = os.environ.get('GOOGLE_APP_CREDS_PATH', None)
DEFAULT_USER_EMAIL = os.environ.get('DEFAULT_USER_EMAIL', None)
PUBSUB_TOPIC = os.environ.get('PUBSUB_TOPIC', None)
```

## GCal API
```
GOOGLE_APP_CREDS_PATH = os.environ.get('GOOGLE_APP_CREDS_PATH', None)
DEFAULT_USER_EMAIL = os.environ.get('DEFAULT_USER_EMAIL', None)
CHANNEL_ID = os.environ.get('CHANNEL_ID', None)
GCAL_HOSTNAME = os.environ.get('GCAL_HOSTNAME', None)
GCAL_API_ENDPOINT = os.environ.get('GCAL_API_ENDPOINT', None)
DEFAULT_AUTH_TOKEN = os.environ.get('GCAL_API_ENDPOINT', None)
```

## GSuite Admin Directory API
```
GOOGLE_APP_CREDS_PATH = os.environ.get('GOOGLE_APP_CREDS_PATH', None)
DEFAULT_USER_EMAIL = os.environ.get('DEFAULT_USER_EMAIL', None)
GSUITE_DOMAIN = os.environ.get('GSUITE_DOMAIN', None)
```

