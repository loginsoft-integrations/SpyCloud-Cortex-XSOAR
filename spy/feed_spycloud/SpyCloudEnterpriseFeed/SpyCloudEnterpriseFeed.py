import json
import demistomock as demisto
import time
from CommonServerPython import *
from typing import Dict, List, Any, Tuple
from dateparser import parse
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

INTEGRATION_CONTEXT_NAME = "SpyCloud"
INVALID_CREDENTIALS_ERROR_MSG = (
    "Authorization Error: The provided API Key "
    "for SpyCloud is invalid. Please provide a "
    "valid API Key."
)
MAX_RETRIES = 5
BACK_OFF_TIME = 0.1
DEFAULT_OFFSET = 0
PAGE_NUMBER_ERROR_MSG = (
    "Invalid Input Error: page number should be greater " "than zero."
)
PAGE_SIZE_ERROR_MSG = "Invalid Input Error: page size should be greater than " "zero."
LIMIT_EXCEED = "LimitExceededException"
TOO_MANY_REQUESTS = "TooManyRequestsException"
INVALID_IP = "Invalid IP"
INVALID_API_KEY = "Invalid API key"
X_AMAZON_ERROR_TYPE = "x-amzn-ErrorType"
SPYCLOUD_ERROR = "SpyCloud-Error"
INVALID_IP_MSG = "Kindly contact SpyCloud support to whitelist your IP Address."
MONTHLY_QUOTA_EXCEED_MSG = (
    "You have exceeded your monthly quota. Kindly " "contact SpyCloud support."
)
IDENTIFIER_ENDPOINT = "watchlist/identifiers"
WATCHLIST_ENDPOINT = "breach/data/watchlist"
DATE_TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


class Client(BaseClient):
    """
    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this implementation, no special attributes defined
    """

    def __init__(self, base_url: str, apikey: str, verify=None, proxy=None):
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers={"Content-type": "application/json", "X-API-Key": apikey},
        )
        self.apikey = apikey

    def query_spy_cloud_api(
        self, end_point: str, params: Dict[Any, Any] = None, is_retry: bool = False
    ) -> Dict:
        """
        Args:
         end_point (str): SpyCloud endpoint.
         params (dict): Params.
         is_retry (bool): Boolean Variable to check whether retry required.
        Returns:
         Return the raw API response from SpyCloud API.
        """
        if params is None:
            params = {}
        url_path = f"{self._base_url}{end_point}" if not is_retry else end_point
        if not is_retry:
            retries = None
            status_list_to_retry = None
            backoff_factor =  None
        else:
            retries = MAX_RETRIES
            status_list_to_retry = {429}
            backoff_factor = BACK_OFF_TIME

        response = self._http_request(
            method="GET",
            full_url=url_path,
            params=params,
            headers=self._headers,
            retries=retries,
            status_list_to_retry=status_list_to_retry,
            backoff_factor=backoff_factor,
            error_handler=self.spy_cloud_error_handler,
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
            if TOO_MANY_REQUESTS in response_headers.get(X_AMAZON_ERROR_TYPE, ''):
                self.query_spy_cloud_api(response.url, is_retry=True)
            elif LIMIT_EXCEED in response_headers.get(X_AMAZON_ERROR_TYPE, ''):
                raise DemistoException(MONTHLY_QUOTA_EXCEED_MSG, res=response)
        elif response.status_code == 403:
            if INVALID_IP in response_headers.get(SPYCLOUD_ERROR, ''):
                raise DemistoException(
                    f'{response_headers.get(SPYCLOUD_ERROR, "")}. '
                    f'{INVALID_IP_MSG}', res=response)
            elif INVALID_API_KEY in response_headers.get(SPYCLOUD_ERROR, ''):
                raise DemistoException(INVALID_CREDENTIALS_ERROR_MSG, res=response)
        else:
            raise DemistoException(err_msg)


    @staticmethod
    def set_last_run():
        """
        sets the last run
        """
        current_date = datetime.now()
        demisto.setIntegrationContext({"last_modified_time": current_date.strftime("%Y-%m-%d")})
        demisto.setLastRun({"last_run": current_date.strftime(DATE_TIME_FORMAT)})
        demisto.info(f"set last_run: {current_date}")

    @staticmethod
    def get_last_run() -> str:
        """Gets last run time in timestamp
        Returns:
            last run in timestamp, or '' if no last run
        """
        return demisto.getIntegrationContext().get("last_modified_time")

""" HELPER FUNCTIONS """


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
    client.query_spy_cloud_api("breach/data/watchlist", {})

    return "ok"

def build_iterators(results: List) -> List:
    """
        Function to parse data and create relationship.
        Args:
            results: API response.
        Returns:
            Incident list
    """
    incident_record = []
    for item in results:
        if item.get('severity') == 25:
            incident = {
                "type": f"SpyCloud Malware Data",
                "name": f"SpyCloud Malware Alert on {item['email']}"
                if item.get('email')
                else f"SpyCloud Malware Alert on {item['ip_addresses'][0]}",
                "rawJSON": json.dumps(item),
                "severity": 4,
            }
            incident_record.append(incident)
        if item.get('severity') == 20:
            incident = {
                "type": "SpyCloud Breach Data",
                "name": f"SpyCloud Breach Alert on {item['email']}"
                if item.get('email')
                else f"SpyCloud Malware Alert on {item['ip_addresses'][0]}",
                "rawJSON": json.dumps(item),
                "severity": 3,
            }
            incident_record.append(incident)
    return incident_record


def create_spycloud_args(client: Client, args: Dict) -> Dict:
    """
    This function creates a dictionary of the arguments sent to the SpyCloud
    API based on the demisto.args().
    Args:
        client(Client): Client class object
        args: demisto.args()
    Returns:
        Return arguments dict.
    """

    spycloud_args: Dict = {}
    last_run = client.get_last_run()
    since: Any
    until: Any = ""
    since_modification_date: Any = ""
    until_modification_date: Any = ""
    if last_run:
        since = last_run
    else:
        since = parse(args.get("since", ""), settings={"TIMEZONE": "UTC"})
        until = parse(args.get("until", ""), settings={"TIMEZONE": "UTC"})
        since_modification_date = parse(
            args.get("since_modification_date", ""), settings={"TIMEZONE": "UTC"}
        )
        until_modification_date = parse(
            args.get("until_modification_date", ""), settings={"TIMEZONE": "UTC"}
        )
        if until:
            until = until.strftime("%Y-%m-%d")
        if since:
            since = since.strftime("%Y-%m-%d")
        if since_modification_date:
            since_modification_date = since_modification_date.strftime(
                "%Y-%m-%d")
        if until_modification_date:
            until_modification_date = until_modification_date.strftime(
                "%Y-%m-%d")
    severity_list = argToList(args.get("severity", []))
    for severity in severity_list:
        if severity not in ["2", "5", "25", "20"]:
            raise DemistoException(
                "Invalid input Error: supported values for "
                "severity are: 2, 5, 20, 25"
            )
    spycloud_args["since"] = since
    spycloud_args["until"] = until
    spycloud_args["type"] = args.get("type", "")
    spycloud_args["severity"] = args.get("severity")
    spycloud_args["source_id"] = args.get("source_id", "")
    spycloud_args["query"] = args.get("query", "")
    spycloud_args["type"] = args.get("type", "")
    spycloud_args["watchlist_type"] = args.get("watchlist_type", "")
    spycloud_args["since_modification_date"] = since_modification_date
    spycloud_args["until_modification_date"] = until_modification_date
    spycloud_args['salt'] = args.get('salt')
    return spycloud_args


def fetch_incident_command(client: Client, args: Dict):
    """
    Function to create Incident and Indicator to XSOAR platform.
    Args:
        client(Client): Client class object
        args: demisto.args()
    """
    cursor = ""
    wait_duration = 1.1
    param = create_spycloud_args(client, args)
    while True:
        response = client.query_spy_cloud_api(
            WATCHLIST_ENDPOINT, {"cursor": cursor, **param}
        )
        results = response.get("results", [])
        incident_record = build_iterators(results)
        demisto.incidents(incident_record)
        cursor = response.get("cursor", "")
        if not cursor or cursor == "":
            client.set_last_run()
            break
        time.sleep(wait_duration)


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    apikey = params.get("apikey")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    handle_proxy()
    command = demisto.command()
    try:
        base_url = params.get("url")
        client = Client(base_url, apikey, verify=verify_certificate, proxy=proxy)
        demisto.info(f"Command being called is {command}")
        if command == "test-module":
            return_results(test_module(client))
        elif command == "fetch-incidents":
            fetch_incident_command(client, params)
        else:
            raise NotImplementedError(f"command {command} is not supported")
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
