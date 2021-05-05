# -*- coding: UTF-8 -*-
# File: dns_transip.py
"""certbot DNS plugin for Transip."""

import logging
import os
import time
from tempfile import mktemp

import transip
import zope.interface
from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

__author__ = '''Wim Fournier <wim@fournier.nl>'''
__docformat__ = 'plaintext'
__date__ = '''14-07-2017'''

LOGGER = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):

    """
    DNS Authenticator for Transip.

    This Authenticator uses the Transip API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using Transip for DNS).'

    def __init__(self, *args, **kwargs):
        """Setup object."""
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None
        self.logger = LOGGER.getChild(self.__class__.__name__)
        self.temp_file = None
        self.clients = {}

    @classmethod
    def add_parser_arguments(cls, add, **_):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=240)
        add('credentials', help='Transip credentials INI file.')

    # pylint: disable=no-self-use
    def more_info(self):
        """Returns info about this plugin."""
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Transip API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Transip credentials INI file',
            {
                'key_file': 'RSA key file'
                            '(convert with openssl rsa -in transip.key -out decrypted_key)',
                'username': 'Transip username',
            }
        )

    def perform(self, achalls): # pylint: disable=missing-function-docstring
        self._setup_credentials()

        self._attempt_cleanup = True

        responses = []
        performs = []
        self.logger.info("Using overridden perform from dns_transip for %s",
            ", ".join(a.domain for a in achalls)
        )
        for achall in achalls:
            domain = achall.domain
            validation_domain_name = achall.validation_domain_name(domain)
            validation = achall.validation(achall.account_key)

            self._perform(domain, validation_domain_name, validation)
            # performs.append(domain, validation_domain_name, validation)
            responses.append(achall.response(achall.account_key))

        # DNS updates take time to propagate and checking to see if the update has occurred is not
        # reliable (the machine this code is running on might be able to see an update before
        # the ACME server). So: we sleep for a short amount of time we believe to be long enough.
        self.logger.info("Waiting %d seconds for DNS changes to propagate",
                    self.conf('propagation-seconds'))
        time.sleep(self.conf('propagation-seconds'))

        return responses

    def _perform(self, domain, validation_name, validation):
        self.logger.debug('_perform: running adding txt record %s.%s', domain, validation_name)
        self._get_transip_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self.logger.debug('_cleanup: removing adding txt record %s.%s', domain, validation_name)
        try:
            self._get_transip_client().del_txt_record(domain, validation_name, validation)
        except Exception:
            if self.temp_file:
                os.unlink(self.temp_file)
            raise

    def _get_transip_client(self):
        username = self.credentials.conf('username')
        if username in self.clients:
            return self.clients[username]

        if not self.credentials.conf('key_file'):
            if self.credentials.conf('rsa_key'):
                key_file = mktemp()
                os.chmod(key_file, 600)
                with key_file as key:
                    key.write(self.credentials.conf('rsa_key'))
            else:
                raise ValueError('Please specify either an RSA key, or an RSA key file')
        else:
            key_file = self.credentials.conf('key_file')
        self.logger.debug('Creating Transip API client for user %s', username)
        self.clients[username] = _TransipClient(username=username, key_file=key_file)
        return self.clients[username]


class _TransipClient():
    """Encapsulates all communication with the Transip API."""

    def __init__(self, username, key_file, sleep_time=.5):
        self.sleep_time = sleep_time
        self.logger = LOGGER.getChild(self.__class__.__name__)
        self.logger.debug('Creating Transip API client for user %s with sleep %s', username, sleep_time)
        self.client = transip.TransIP(login=username, private_key_file=key_file)

    def add_txt_record(self, domain_name, record_name, record_content):
        """
        Add a TXT record using the supplied information.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Transip
                                            API
        """
        try:
            domain = self._find_domain(domain_name)
        except Exception as error:
            self.logger.error('Error finding domain using the Transip API: %s', error)
            raise errors.PluginError('Error finding domain using the Transip API: {0}'
                                     .format(error))

        # Retrieve the DNS records of a single domain.
        transip_domain_service = self.client.domains.get(domain)

        # records = transip_domain_service.dns.list()

        # Dictionary containing the information for a single DNS record.
        dns_entry_data = {
            "name": self._compute_record_name(domain, record_name),
            "expire": 1,
            "type": "TXT",
            "content": record_content
        }
        # Add the DNS record to the domain.
        try:
            self.logger.info('Attempt adding TXT record: %s ', record_name)
            transip_domain_service.dns.create(dns_entry_data)
            self.logger.info('Successfully added TXT record: %s', record_name)
            time.sleep(self.sleep_time)
            self.logger.info('Sleeping for %s seconds', self.sleep_time)
        except Exception as error:
            self.logger.error('Error adding TXT record using the Transip API: %s', error)
            raise errors.PluginError('Error adding TXT record using the Transip API: {0}'
                                     .format(error))

    def del_txt_record(self, domain_name, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """
        try:
            domain = self._find_domain(domain_name)
        except Exception as error:
            self.logger.error('Error finding domain using the Transip API: %s', error)
            raise errors.PluginError('Error finding domain using the Transip API: {0}'
                                     .format(error))

        # Retrieve the DNS records of a single domain.
        transip_domain_service = self.client.domains.get(domain)

        # Dictionary containing the information for a single DNS record.
        dns_entry_data = {
            "name": self._compute_record_name(domain, record_name),
            "expire": 1,
            "type": "TXT",
            "content": record_content
        }

        # Retrieve the DNS records of a single domain.
        records = transip_domain_service.dns.list()
        for record in records:
            # Update the A-record for localhost
            if (
                record.name == dns_entry_data["name"] and
                record.type == dns_entry_data["type"] and
                record.content == dns_entry_data["content"]
            ):
                try:
                    self.logger.info('Removing TXT record with name: %s', record.name)
                    transip_domain_service.dns.delete(dns_entry_data)
                    time.sleep(self.sleep_time)
                    self.logger.info('Sleeping for %s seconds', self.sleep_time)
                except Exception as error:
                    self.logger.error('Error while storing DNS records: %s', error)

    def _fetch_domains(self, refresh=False):
        if hasattr(self, "_c_fetched_domains") and not refresh:
            return getattr(self, "_c_fetched_domains", [])

        domains = [d.name for d in self.client.domains.list()]
        setattr(self, "_c_fetched_domains", domains)
        return domains

    def _find_domain(self, domain_name):
        """
        Find the domain object for a given domain name.

        :param str domain_name: The domain name for which to find the corresponding Domain.
        :returns: The Domain, if found.
        :rtype: `str`
        :raises certbot.errors.PluginError: if no matching Domain is found.
        """
        domain_name_guesses = dns_common.base_domain_name_guesses(domain_name)

        domains = self._fetch_domains()

        for guess in domain_name_guesses:
            if guess in domains:
                self.logger.debug('Found base domain for %s using name %s', domain_name, guess)
                return guess

        raise errors.PluginError('Unable to determine base domain for {0} using names: {1} and domains: {2}.'
                                 .format(domain_name, domain_name_guesses, domains))

    @staticmethod
    def _compute_record_name(domain, full_record_name):
        # The domain, from Transip's point of view, is automatically appended.
        return full_record_name.rpartition("." + domain)[0]
