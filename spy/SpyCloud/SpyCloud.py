import demistomock as demisto
from math import floor, ceil
from CommonServerPython import *
from typing import Dict, List, Optional, Any, Tuple
from dateparser import parse
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

INTEGRATION_CONTEXT_NAME = 'SpyCloud'
INVALID_CREDENTIALS_ERROR_MSG = 'Authorization Error: The provided API Key ' \
                                'for SpyCloud is invalid. Please provide a ' \
                                'valid API Key.'
DEFAULT_PAGE_SIZE = 50
MAX_RETRIES = 5
BACK_OFF_TIME = 0.1
DEFAULT_OFFSET = 0
PAGE_NUMBER_ERROR_MSG = "Invalid Input Error: page number should be greater " \
                        "than zero."
PAGE_SIZE_ERROR_MSG = "Invalid Input Error: page size should be greater than " \
                      "zero."
LIMIT_EXCEED = 'LimitExceededException'
TOO_MANY_REQUESTS = 'TooManyRequestsException'
INVALID_IP = 'Invalid IP'
INVALID_API_KEY = 'Invalid API key'
X_AMAZON_ERROR_TYPE = 'x-amzn-ErrorType'
SPYCLOUD_ERROR = 'SpyCloud-Error'
INVALID_IP_MSG = 'Kindly contact SpyCloud support to whitelist your IP Address.'
MONTHLY_QUOTA_EXCEED_MSG = 'You have exceeded your monthly quota. Kindly ' \
                           'contact SpyCloud support.'


class Client(BaseClient):
    """
    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this implementation, no special attributes defined
    """

    def __init__(self, base_url: str, apikey: str,
                 verify=None,
                 proxy=None):
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers={
                'Content-type': 'application/json',
                'X-API-Key': apikey
            }
        )
        self.apikey = apikey

    def query_spy_cloud_api(self, end_point: str, params: Dict[Any, Any] = None,
                            is_retry: bool = False) -> Dict:

        """
        Args:
            end_point (str): SpyCloud endpoint.
            params (dict): Params.
            is_retry (bool): Boolean Variable to check weather retry required.
        Returns:
            Return the raw api response from Cisco Umbrella Reporting API.
        """
        response: Dict = {}
        if params is None:
            params = {}
        if not is_retry:
            url_path = f'{self._base_url}{end_point}'
            response = self._http_request(
                method='GET',
                full_url=url_path,
                params=params,
                headers=self._headers,
                error_handler=self.spy_cloud_error_handler
            )
        else:
            response = self._http_request(
                method='GET',
                full_url=end_point,
                headers=self._headers,
                retries=MAX_RETRIES,
                status_list_to_retry={429},
                backoff_factor=BACK_OFF_TIME,
                error_handler=self.spy_cloud_error_handler
            )
        return response

    def spy_cloud_error_handler(self, response: requests.Response):
        """
        Error Handler for SpyCloud
        Args:
            response (response): SpyCloud response
        Raise:
             DemistoException
        """
        response_headers = response.headers
        err_msg = response.json().get('message') or response.json().get(
            'errorMessage')
        if response.status_code == 429:
            if TOO_MANY_REQUESTS in response_headers.get(X_AMAZON_ERROR_TYPE,
                                                         ''):
                self.query_spy_cloud_api(response.url, is_retry=True)
            elif LIMIT_EXCEED in response_headers.get(X_AMAZON_ERROR_TYPE, ''):
                raise DemistoException(MONTHLY_QUOTA_EXCEED_MSG)
        elif response.status_code == 403:
            if INVALID_IP in response_headers.get(SPYCLOUD_ERROR, ''):
                raise DemistoException(
                    f'{response_headers.get(SPYCLOUD_ERROR, "")}. '
                    f'{INVALID_IP_MSG}')
            elif INVALID_API_KEY in response_headers.get(SPYCLOUD_ERROR, ''):
                raise DemistoException(INVALID_CREDENTIALS_ERROR_MSG)
        else:
            raise DemistoException(err_msg)

    ''' HELPER FUNCTIONS '''


def pagination(page: Optional[int], page_size: Optional[int],
               limit: Optional[int]):
    """
    Define pagination.
    Args:
        limit: Records per page.
        page: The page number.
        page_size: The number of requested results per page.
    Returns:
        limit (int): Records per page.
        offset (int): The number of records to be skipped.
    """
    if page and page <= 0:
        raise DemistoException(PAGE_NUMBER_ERROR_MSG)
    if page_size and page_size <= 0:
        raise DemistoException(PAGE_SIZE_ERROR_MSG)

    if page_size and limit:
        limit = page_size
    page = page - 1 if page else DEFAULT_OFFSET
    page_size = page_size or DEFAULT_PAGE_SIZE

    limit = limit or page_size or DEFAULT_PAGE_SIZE
    offset = page * page_size

    return limit, offset


def get_paginated_results(results: List, offset: int, limit: int) -> List:
    return results[offset:offset + limit]


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like
    it is supposed to and connection to the service is successful.
    Args:
        client(Client): Client class object
    Returns:
        Connection ok
    """
    client.query_spy_cloud_api("breach/data/domains/loginsoft.com", {})

    return "ok"


def create_spycloud_args(args: Dict) -> Dict:
    """
    This function creates a dictionary of the arguments sent to the SpyCloud
    API based on the demisto.args().
    Args:
        args: demisto.args()
    Returns:
        Return arguments dict.
    """

    spycloud_args: Dict = {}
    since: Any = parse(args.get('since', ''), settings={"TIMEZONE": "UTC"})
    until: Any = parse(args.get('until', ''), settings={"TIMEZONE": "UTC"})
    if until:
        until = until.strftime('%Y-%m-%d')
    if since:
        since = since.strftime('%Y-%m-%d')
    spycloud_args['since'] = since
    spycloud_args['until'] = until
    spycloud_args['type'] = args.get('type', '')
    spycloud_args['severity'] = args.get('severity', '')
    spycloud_args['source_id'] = args.get('source_id', '')
    spycloud_args['query'] = args.get('query', '')
    spycloud_args['type'] = args.get('type', '')
    spycloud_args['watchlist_type'] = args.get('watchlist_type', '')
    return spycloud_args


def breaches_lookup_to_markdown(response: List[Dict], title: str):
    """
    Parsing the SpyCloud data
    Args:
        response (list): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    record_list = []
    for data in response:
        new = {
            'Title': data.get('title'),
            'SpyCloud Publish Date': data.get('spycloud_publish_date'),
            'Description': data.get('description'),
            'Confidence': data.get('confidence'),
            'ID': data.get('id'),
            'Acquisition Date': data.get('acquisition_date'),
            'UUID': data.get('uuid'),
            'Type': data.get('type')
        }
        record_list.append(new)
    headers = record_list[0] if record_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, record_list, headers=headers,
                               removeNull=True)
    return markdown


def lookup_to_markdown_table(response: List[Dict], title: str):
    """
    Parsing the SpyCloud data
    Args:
        response (list): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    record_list = []
    for data in response:
        new = {
            'Source ID': data.get('source_id'),
            'Email': data.get('email'),
            'Full Name': data.get('full_name'),
            'User Name': data.get('username'),
            'Email Domain': data.get('email_domain'),
            'Email Username': data.get('email_username'),
            'Target Domain': data.get('target_domain'),
            'Target Subdomain': data.get('target_subdomain'),
            'Password': data.get('password'),
            'Password Plaintext': data.get('password_plaintext'),
            'Password Type': data.get('password_type'),
            'Target URL': data.get('target_url'),
            'User Browser': data.get('user_browser'),
            'IP Addresses': data.get('ip_addresses'),
            'Infected Machine ID': data.get('infected_machine_id'),
            'Infected Path': data.get('infected_path'),
            'Infected Time': data.get('infected_time'),
            'User System Domain': data.get('user_sys_domain'),
            'User Hostname': data.get('user_hostname'),
            'User OS': data.get('user_os'),
            'User SYS Registered Owner': data.get('user_sys_registered_owner'),
            'SpyCloud Publish Date': data.get('spycloud_publish_date'),
            'Confidence': data.get('confidence'),
            'ID': data.get('id'),
            'Domain': data.get('domain'),
            'Document ID': data.get('document_id'),
            'UUID': data.get('uuid'),
            'Severity': data.get('severity'),
            'Sighting': data.get('sighting')
        }
        record_list.append(new)
    headers = record_list[0] if record_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, record_list, headers=headers,
                               removeNull=True)
    return markdown


def command_helper_function(client: Client, endpoint: str, args: Dict[str, Any],
                            title_string: str) -> Tuple[list, str]:
    """
    A helper function that aids in pagination for querying an API.

    Args:
        client: SpyCloud client to use.
        endpoint: The endpoint to query.
        args: demisto.args().
        title_string: Command title string.

    Returns:
        Paginated response, title.

    Raises:
        DemistoException: If there is no data available for the requested page.
    """
    results = []
    spycloud_args = create_spycloud_args(args)

    page = arg_to_number(args.get("page"), arg_name="page")
    page_size = arg_to_number(args.get("page_size"), arg_name="page_size")
    limit = arg_to_number(args.get('limit', DEFAULT_PAGE_SIZE),
                          arg_name='limit')
    all_results = argToBoolean(args.get('all_results', False))

    response = client.query_spy_cloud_api(endpoint, spycloud_args)
    total_records = response.get('hits', 0)

    title = get_command_title_string(title_string, page, page_size,
                                     total_records)

    if total_records > 0:
        results += response.get('results', [])
        cursor = response.get('cursor', '')

        if all_results:
            while cursor:
                res = client.query_spy_cloud_api(endpoint, {'cursor': cursor})
                cursor = res.get('cursor')
                results += res.get('results', [])
        else:
            updated_limit, offset = pagination(page, page_size, limit)
            required_page = floor(offset / 1000)
            if total_records > offset:
                for i in range(required_page):
                    res = client.query_spy_cloud_api(endpoint,
                                                     {'cursor': cursor})
                    cursor = res.get('cursor')
                    results += res.get('results', [])
            else:
                raise DemistoException(
                    f'No data available for page {page}. Tota'
                    f'l pages available are {ceil(total_records / page_size)}')

            results = get_paginated_results(results, offset, updated_limit)

    return results, title


def get_command_title_string(sub_context: str, page: Optional[int],
                             page_size: Optional[int], hits: Optional[int]) -> \
        str:
    """
    Define command title
    Args:
        sub_context: Commands sub_context
        page: page_number
        page_size: page_size
        hits: total number of page
    Returns:
        Returns the title for the readable output
    """
    if page and page_size and (page > 0 and page_size > 0):
        total_page = ceil(hits / page_size) if hits and hits > 0 else 1
        return f'{sub_context} \nCurrent page size: {page_size}\n' \
               f'Showing page {page} out of {total_page}'

    return f"{sub_context}"


def get_breaches_list_command(client: Client, args: Dict[str, Any]):
    """
    List of breach data.
    Args:
        client: SpyCloud client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that contains an updated
            result.
    """
    endpoint = 'breach/catalog'
    title_string = 'Breach List'
    paginated_results, title = command_helper_function(client, endpoint,
                                                       args, title_string)
    readable_output = breaches_lookup_to_markdown(paginated_results, title)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.BreachList',
        outputs_key_field='uuid',
        outputs=paginated_results
    )


def get_breache_data_by_id_command(client: Client, args: Dict[str, Any]):
    """
    Breach data by id.
    Args:
        client: SpyCloud client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that contains an updated
            result.
    """
    spycloud_args = create_spycloud_args(args)
    endpoint = f'breach/catalog/{args.get("id")}'
    title = f'Breach data for id {args.get("id")}'
    response = client.query_spy_cloud_api(endpoint, spycloud_args).get(
        'results', [])
    readable_output = breaches_lookup_to_markdown(response, title)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.BreachDataByID',
        outputs_key_field='id',
        outputs=response
    )


def get_breach_data_by_domain_command(client: Client, args: Dict[str, Any]):
    """
    Breach data by domain.
    Args:
        client: SpyCloud client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that contains an updated
            result.
    """
    domain = args.get('domain')
    endpoint = f'breach/data/domains/{domain}'
    title_string = f'Breach List for domain {domain}'
    paginated_results, title = command_helper_function(client, endpoint,
                                                       args, title_string)
    readable_output = lookup_to_markdown_table(paginated_results, title)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.DomainBreachData',
        outputs_key_field='document_id',
        outputs=paginated_results
    )


def get_breach_data_by_username_command(client: Client, args: Dict[str, Any]):
    """
    Breach data by username.
    Args:
        client: SpyCloud client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that contains an updated
            result.
    """
    username = args.get('username')
    endpoint = f'breach/data/usernames/{username}'
    title_string = f'Breach List for username {username}'
    paginated_results, title = command_helper_function(client, endpoint, args,
                                                       title_string)
    readable_output = lookup_to_markdown_table(paginated_results, title)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.UsernameBreachData',
        outputs_key_field='document_id',
        outputs=paginated_results
    )


def get_breach_data_by_ip_address_command(client: Client, args: Dict[str, Any]):
    """
    Breach data by ip address.
    Args:
        client: SpyCloud client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that contains an updated
            result.
    """
    ip = args.get('ip')
    endpoint = f'breach/data/ips/{ip}'
    title_string = f'Breach List for IP address {ip}'
    paginated_results, title = command_helper_function(client, endpoint, args,
                                                       title_string)
    readable_output = lookup_to_markdown_table(paginated_results, title)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.IPAddressBreachData',
        outputs_key_field='document_id',
        outputs=paginated_results
    )


def get_breach_data_by_email_address_command(client: Client,
                                             args: Dict[str, Any]):
    """
    Breach data by email address.
    Args:
        client: SpyCloud client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that contains an updated
            result.
    """
    email = args.get('email')
    endpoint = f'breach/data/emails/{email}'
    title_string = f'Breach List for Email address {email}'
    paginated_results, title = command_helper_function(client, endpoint,
                                                       args, title_string)
    readable_output = lookup_to_markdown_table(paginated_results, title)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.EmailAddressBreachData',
        outputs_key_field='document_id',
        outputs=paginated_results
    )


def get_breach_data_by_passwords_command(client: Client, args: Dict[str, Any]):
    """
    Breach data by password.
    Args:
        client: SpyCloud client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that contains an updated
            result.
    """
    passwords = args.get('password')
    title_string = f'breach/data/passwords/{passwords}'
    endpoint = f'breach/data/passwords/{passwords}'
    paginated_results, title = command_helper_function(client, endpoint, args,
                                                       title_string)
    readable_output = lookup_to_markdown_table(paginated_results, title)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.PasswordBreachData',
        outputs_key_field='document_id',
        outputs=paginated_results
    )


def get_watchlist_data_command(client: Client, args: Dict[str, Any]):
    """
    Watchlist data.
    Args:
        client: SpyCloud client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that contains an updated
            result.
    """
    endpoint = 'breach/data/watchlist'
    title_string = 'Watchlist Data'
    paginated_results, title = command_helper_function(client, endpoint, args,
                                                       title_string)
    readable_output = lookup_to_markdown_table(paginated_results, title)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.WatchlistData',
        outputs_key_field='document_id',
        outputs=paginated_results
    )


def get_compass_device_data_command(client: Client, args: Dict[str, Any]):
    """
    Compass Devices - Data by infected_machine_id.
    Args:
        client: SpyCloud client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that contains an updated
            result.
    """
    infected_machine_id = args.get('infected_machine_id')
    endpoint = f'compass/data/devices/{infected_machine_id}'
    title_string = 'Compass Devices - Data'
    paginated_results, title = command_helper_function(client, endpoint,
                                                       args, title_string)
    readable_output = lookup_to_markdown_table(paginated_results, title)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.CompassDeviceData',
        outputs_key_field='document_id',
        outputs=paginated_results
    )


def compass_data_list_command(client: Client, args: Dict[str, Any]):
    """
    Compass Data list command.
    Args:
        client: SpyCloud client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that contains an updated
            result.
    """
    endpoint = 'compass/data'
    title_string = 'Compass Data List'
    paginated_results, title = command_helper_function(client, endpoint,
                                                       args, title_string)
    readable_output = lookup_to_markdown_table(paginated_results, title)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.CompassDataList',
        outputs_key_field='document_id',
        outputs=paginated_results
    )


def compass_device_list_command(client: Client, args: Dict[str, Any]):
    """
    Compass Device list command.
    Args:
        client: SpyCloud client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that contains an updated
            result.
    """
    endpoint = 'compass/devices'
    title_string = 'Compass Device List'
    spycloud_args = create_spycloud_args(args)
    page = arg_to_number(args.get("page"), arg_name="page")
    page_size = arg_to_number(args.get("page_size"), arg_name="page_size")
    limit = arg_to_number(args.get('limit', DEFAULT_PAGE_SIZE),
                          arg_name='limit')
    response = client.query_spy_cloud_api(endpoint, spycloud_args)
    results = response.get('results', [])
    total_record = response.get('hits', 0)
    title = get_command_title_string(title_string, page, page_size, total_record)
    updated_limit, offset = pagination(page, page_size, limit)
    paginated_results = get_paginated_results(results, offset, updated_limit)
    readable_output = lookup_to_markdown_table(paginated_results, title)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.CompassDeviceList',
        outputs_key_field='document_id',
        outputs=paginated_results
    )


def get_compass_application_data_command(client: Client, args: Dict[str, Any]):
    """
    Compass Application Data command.
    Args:
        client: SpyCloud client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that contains an updated
            result.
    """
    target_application = args.get('target_application')
    endpoint = f'compass/data/applications/{target_application}'
    spycloud_args = create_spycloud_args(args)
    page = arg_to_number(args.get("page"), arg_name="page")
    page_size = arg_to_number(args.get("page_size"), arg_name="page_size")
    limit = arg_to_number(args.get('limit', DEFAULT_PAGE_SIZE),
                          arg_name='limit')
    response = client.query_spy_cloud_api(endpoint, spycloud_args)
    results = response.get('results', [])
    total_record = response.get('hits', 0)
    title = get_command_title_string('Compass Applications - Data', page, page_size, total_record)
    updated_limit, offset = pagination(page, page_size, limit)
    paginated_results = get_paginated_results(results, offset, updated_limit)
    readable_output = lookup_to_markdown_table(paginated_results, title)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.CompassApplicationData',
        outputs_key_field='document_id',
        outputs=paginated_results
    )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    apikey = params.get('apikey')
    args = demisto.args()
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    try:
        base_url = params.get('url')
        client = Client(
            base_url,
            apikey,
            verify=verify_certificate,
            proxy=proxy)
        LOG(f'Command being called is {command}')
        commands = {
            'spycloud-breach-list':
                get_breaches_list_command,
            'spycloud-breach-data-by-id': get_breache_data_by_id_command,
            'spycloud-breach-data-by-domain': get_breach_data_by_domain_command,
            'spycloud-breach-data-by-username':
                get_breach_data_by_username_command,
            'spycloud-breach-data-by-ip-address':
                get_breach_data_by_ip_address_command,
            'spycloud-breach-data-by-email-address':
                get_breach_data_by_email_address_command,
            'spycloud-breach-data-by-password':
                get_breach_data_by_passwords_command,
            'spycloud-watchlist-data': get_watchlist_data_command,
            'spycloud-compass-device-data': get_compass_device_data_command,
            'spycloud-compass-data-list': compass_data_list_command,
            'spycloud-compass-device-list': compass_device_list_command,
            'spycloud-compass-application-data': get_compass_application_data_command
        }
        if command == "test-module":
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError
    except Exception as e:
        return_error(
            f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
