from setuptools import setup, find_packages

# req has moved to _internal on newer vesions of pip
# this fixes local tests randomly
try:
    from pip.req import parse_requirements
except ImportError:
    from pip._internal.req import parse_requirements
import uuid

install_reqs = parse_requirements('requirements.txt', session=uuid.uuid1())
requirements = [str(ir.req) for ir in install_reqs if ir.req]

config = {
    'description': 'High-level Wrappers around Google API SDK',
    'author': 'Museality LLC',
    'url': '',
    'download_url': '',
    'author_email': '',
    'version': '0.1',
    'install_requires': requirements,
    'packages': find_packages(),
    'scripts': [],
    'name': 'google-apps-py'
}

setup(**config)
