from elasticsearch import Elasticsearch, ConnectionError
from elasticsearch_dsl import Search, Q
import datetime
import configargparse
import ipaddress
import requests


def parse_args():
    parser = configargparse.ArgParser(add_help=False, description='This script will fetch data from ElasticSearch '
                                                                  'and BAN IP addresses in hbl API.')
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')
    '''Suppressing default help'''
    optional.add_argument('-h', '--help', action='help', default=configargparse.SUPPRESS,
                          help='show this help message and exit')
    required.add_argument('--es_user', help='Elastic http auth username', required=True, env_var='ES_USER')
    required.add_argument("--es_pass", help='Elastic http auth password', required=True, env_var='ES_PASS')
    required.add_argument("--es_url", help='ElasticSearch url', env_var='ES_URL', required=True)
    required.add_argument("--es_index", help='Index name, default: openresty-*', env_var='ES_INDEX', required=True)
    optional.add_argument("--es_scheme", default='https', help='Transport, default: https',
                          choices=('https', 'http'), env_var='ES_SCHEME')
    optional.add_argument("--es_timeout", default=15, help='ES read timeout, default: 15', type=int, env_var='ES_SCHEME')
    optional.add_argument("--es_port", default=443, help='80 or 443, default: 443', type=int, env_var='ES_PORT')
    optional.add_argument("--ban_threshold", default=1000,
                          help='Count to get banned, integer, default: 1000', type=int, env_var='BAN_THRESHOLD')
    optional.add_argument("--ban_uniq_webs", default=5,
                          help='Unique webs to get banned, integer, default: 5', type=int, env_var='BAN_UNIQ_WEBS')
    required.add_argument("--hbl_url", help='HBL API base url', type=str, env_var='HBL_URL')
    required.add_argument("--hbl_key", help='HBL API key for auth', env_var='HBL_KEY')

    optional.add_argument("--time_window", default=10, help="Time window, in minutes",
                          choices=(10, 15, 30, 60), type=int, env_var='TIME_WINDOW')
    optional.add_argument("--dry_run", default=False, action='store_true', help='Just print, do not change',
                          env_var='DRY_RUN')
    return parser.parse_args()


class Es:
    def __init__(self, args):
        self.hosts = args.es_url
        self.http_auth = (args.es_user, args.es_pass)
        self.port = args.es_port
        self.scheme = args.es_scheme
        self.rq_timeout = args.es_timeout
        self.index = args.es_index
        self.time_window = args.time_window
        self.__es_client = self.__get_client()

    def __get_client(self):
        es = None
        try:
            es = Elasticsearch(hosts=self.hosts,
                               http_auth=self.http_auth,
                               port=self.port,
                               scheme=self.scheme)
        except ConnectionError:
            print("Error getting abusers from elastic: {}".format(ConnectionError.info))
        return es

    def __get_timestamps(self):
        dt_now_mills = round(datetime.datetime.now().timestamp() * 1000)
        dt_minus = datetime.datetime.now() - datetime.timedelta(minutes=self.time_window)
        past_mills = round(dt_minus.timestamp() * 1000)
        return dt_now_mills, past_mills

    def construct_query(self, lookup="POST /xmlrpc.php.*"):
        now, before = self.__get_timestamps()
        search_obj = Search(index=self.index)

        query = Q('bool', must=[Q('query_string', query='request:\"{}\"'.format(lookup),
                                  analyze_wildcard=True,
                                  default_field="*")])
        search_obj.aggs.bucket('ips', 'terms', field='remote_addr.keyword', size=500, order={'_count': 'desc'}) \
            .bucket('hosts', 'cardinality', field='host.keyword')
        search_obj = search_obj.query('range', **{'@timestamp': {"gte": before, "lte": now}})
        search_obj = search_obj.query(query)

        return search_obj

    def execute_search(self, search_object):
        ex = search_object.using(self.__es_client)
        return ex.execute()

    @staticmethod
    def reverse(ip):
        if len(ip) <= 1:
            return ip
        return '.'.join(ip.split('.')[::-1])


class HttpCall:
    def __init__(self, base_url, **kwargs):
        self.base_url = base_url
        self.session = requests.Session()
        for arg in kwargs:
            if isinstance(kwargs[arg], dict):
                kwargs[arg] = self.__deep_merge(getattr(self.session, arg), kwargs[arg])
            setattr(self.session, arg, kwargs[arg])

    def request(self, method, url, **kwargs):
        return self.session.request(method, self.base_url+url, **kwargs)

    def get(self, url, **kwargs):
        return self.session.get(self.base_url+url, **kwargs)

    def post(self, url, **kwargs):
        return self.session.post(self.base_url+url, **kwargs)

    def put(self, url, **kwargs):
        return self.session.put(self.base_url+url, **kwargs)

    def patch(self, url, **kwargs):
        return self.session.patch(self.base_url+url, **kwargs)

    def delete(self, url, **kwargs):
        return self.session.delete(self.base_url+url, **kwargs)

    @staticmethod
    def __deep_merge(source, destination):
        for key, value in source.items():
            if isinstance(value, dict):
                node = destination.setdefault(key, {})
                HttpCall.__deep_merge(value, node)
            else:
                destination[key] = value
        return destination


def main():
    args = parse_args()
    hrbl = HttpCall(args.hbl_url,
                    headers={
                        "X-API-Key": args.hbl_key})

    elastic = Es(args)
    '''
    Separated query object for future, to be able to generate different objects,
    if same structure is needed, it should be fine using same object just passing different "lookup=" variable.
    '''
    query_obj = elastic.construct_query(lookup='POST /xmlrpc.php.*')
    response = elastic.execute_search(query_obj)
    badlist = []
    for bucket in response.aggregations.ips.buckets:
        # Discard ipv6
        try:
            ipaddress.IPv4Address(bucket['key'])
        except ValueError:
            continue
        # Check if IP is above threshold, > 10 unique webs and is valid ipv4
        if (bucket['doc_count'] > args.ban_threshold
                and ipaddress.IPv4Address(bucket['key']).is_global
                and bucket.hosts['value'] > args.ban_uniq_webs):
            # Append to list of tuples
            badlist.append({'ipaddress': bucket['key'],
                            'xml_hits': bucket['doc_count'],
                            'uniq_hosts': bucket.hosts['value'],
                            'time_window': args.time_window})
    if args.dry_run:
        for item in badlist:
            print('would get banned: ',
                  item.get('ipaddress'),
                  item.get('xml_hits'),
                  item.get('uniq_hosts'),
                  item.get('time_window'))
    else:
        # Do bans
        for item in badlist:
            r = hrbl.post("/addresses", headers={"Accept": "application/json"},
                          json={"IP": item.get('ipaddress'),
                                "Action": 'Block',
                                "Author": "WH ES importer",
                                "comment": "xmlrpc bruteforce unique webs: {} count: {}".format(item.get('uniq_hosts'),
                                                                                                item.get('xml_hits'))})
            if r.status_code != 200:
                print('Ban failed for ip {0}. '
                      'Reason from API: {1}'.format(item.get('ipaddress'), r.json()))


if __name__ == "__main__":
    main()
