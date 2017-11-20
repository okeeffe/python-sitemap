import config
import logging
from urllib.parse import urljoin, urlunparse

import re
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from urllib.robotparser import RobotFileParser
from datetime import datetime

import mimetypes
import os

class Crawler():

	# Variables
	parserobots = False
	output 	= None
	report 	= False
	forcehttps = False

	config 	= None
	domain	= ""

	ignore = []
	skipext = []
	drop    = []

	debug	= False

	tocrawl = set([])
	crawled = set([])
	ignored = set([])
	excluded = set([])

	marked = {}

	not_parseable_resources = (".epub", ".mobi", ".docx", ".doc", ".opf", ".7z", ".ibooks", ".cbr", ".avi", ".mkv", ".mp4", ".jpg", ".jpeg", ".png", ".gif" ,".pdf", ".iso", ".rar", ".tar", ".tgz", ".zip", ".dmg", ".exe")

	# TODO also search for window.location={.*?}
	linkregex = re.compile(b'<a [^>]*href=[\'|"](.*?)[\'"][^>]*?>')
	imageregex = re.compile (b'<img [^>]*src=[\'|"](.*?)[\'"].*?>')

	rp = None
	response_code={}
	nb_url=1 # Number of url.
	nb_rp=0 # Number of url blocked by the robots.txt
	nb_ignore=0 # Number of url ignored by extension or word
	nb_exclude=0 # Number of url excluded by extension or word

	output_file = None

	target_domain = ""
	scheme		  = ""

	def __init__(self, parserobots=False, output=None, report=False, domain="", exclude=[],
				 ignore=[], skipext=[], drop=[], debug=False, verbose=False, images=False, forcehttps=False):
		self.parserobots = parserobots
		self.output 	= output
		self.report 	= report
		self.domain 	= domain
		self.ignore 	= ignore
		self.exclude 	= exclude
		self.skipext 	= skipext
		self.drop		= drop
		self.debug		= debug
		self.verbose    = verbose
		self.images     = images
		self.forcehttps = forcehttps

		if self.verbose:
			log_level = logging.DEBUG
		elif self.debug:
			log_level = logging.INFO
		else:
			log_level = logging.ERROR

		logging.basicConfig(level=log_level)

		domain = self.clean_link(domain)
		logging.debug("Root domain is: {}".format(domain))
		logging.debug("Force HTTPS is {}".format(self.forcehttps))
		self.tocrawl = set([domain])

		try:
			url_parsed = urlparse(domain)
			self.target_domain = url_parsed.netloc
			self.scheme = url_parsed.scheme
		except:
			logging.error("Invalid domain")
			raise ("Invalid domain")

		if self.output:
			try:
				self.output_file = open(self.output, 'w')
			except:
				logging.error ("Output file not available.")
				exit(255)

	def run(self):
		print(config.xml_header, file=self.output_file)

		if self.parserobots:
			self.check_robots()

		logging.info("Start the crawling process")

		while len(self.tocrawl) != 0:
			self.__crawling()

		logging.info("Crawling has reached end of all found links")

		print (config.xml_footer, file=self.output_file)


	def __crawling(self):
		crawling = self.tocrawl.pop()

		url = urlparse(crawling)
		self.crawled.add(crawling)
		logging.info("Crawling #{}: {}".format(len(self.crawled), url.geturl()))
		request = Request(crawling, headers={"User-Agent":config.crawler_user_agent})

		# Ignore resources listed in the not_parseable_resources
		# Don't download files like pdf… etc
		if not url.path.endswith(self.not_parseable_resources):
			try:
				response = urlopen(request)
			except Exception as e:
				if hasattr(e,'code'):
					if e.code in self.response_code:
						self.response_code[e.code]+=1
					else:
						self.response_code[e.code]=1

					# Gestion des urls marked pour le reporting
					if self.report:
						if e.code in self.marked:
							self.marked[e.code].append(crawling)
						else:
							self.marked[e.code] = [crawling]

				logging.debug ("{1} ==> {0}".format(e, crawling))
				return self.__continue_crawling()
		else:
			logging.debug("Ignore {0} content might be not parseable.".format(crawling))
			response = None

		# Read the response
		if response is not None:
			try:
				msg = response.read()
				if response.getcode() in self.response_code:
					self.response_code[response.getcode()]+=1
				else:
					self.response_code[response.getcode()]=1

				response.close()

				# Get the last modify date
				if 'last-modified' in response.headers:
					date = response.headers['Last-Modified']
				else:
					date = response.headers['Date']

				date = datetime.strptime(date, '%a, %d %b %Y %H:%M:%S %Z')
			except IOError as e:
				# URLOpen error, probably our fault (momentary network outage). Trust URL.
			    if hasattr(e, 'reason'):
			        logging.debug ("{1} ===> {0}, adding url anyway.".format(e, crawling))
		        # HTTPError, probably their fault so we will throw away this url.
			    elif hasattr(e, 'code'):
			        logging.debug ("{1} ===> {0}".format(e, crawling))
			        return None
			except Exception as e:
				logging.debug ("{1} ===> {0}".format(e, crawling))
				return None
		else:
			# Response is None, content not downloaded, just continue and add
			# the link to the sitemap
			msg = "".encode( )
			date = None

		# Image sitemap enabled ?
		image_list = "";
		if self.images:
			# Search for images in the current page.
			images = self.imageregex.findall(msg)
			for image_link in list(set(images)):
				image_link = image_link.decode("utf-8", errors="ignore")

				# Ignore link starting with data:
				if image_link.startswith("data:"):
					continue

				# If path start with // get the current url scheme
				if image_link.startswith("//"):
					image_link = url.scheme + ":" + image_link
				# Append domain if not present
				elif not image_link.startswith(("http", "https")):
					if not image_link.startswith("/"):
						image_link = "/{0}".format(image_link)
					image_link = "{0}{1}".format(self.domain.strip("/"), image_link.replace("./", "/"))

				# Ignore image if path is in the ignore_url list
				if not self.ignore_url(image_link):
					continue

				# Ignore other domain images
				image_link_parsed = urlparse(image_link)
				if image_link_parsed.netloc != self.target_domain:
					continue


				# Test if images as been already seen and not present in the
				# robot file
				if self.can_fetch(image_link):
					logging.debug("Found image : {0}".format(image_link))
					image_list = "{0}<image:image><image:loc>{1}</image:loc></image:image>".format(image_list, self.htmlspecialchars(image_link))

		# Check if the current url contains an excluded word
		full_url = url.geturl()
		if self.exclude_url(full_url):
			self.exclude_link(full_url)
			self.nb_exclude+=1
		else:
			# If it doesn't, we add it to the sitemap
			# Location
			loc = '<loc>{}</loc>'.format(self.htmlspecialchars(full_url))

			# Last mod
			date = date if date else datetime.now()
			lastmod = '<lastmod>{}</lastmod>'.format(date.strftime('%Y-%m-%dT%H:%M:%S+00:00'))

			# Priority
			priority = 0.5
			if url.path == '':
				priority = 1.0
			# TODO: Horrible hack for specific use-case out of laziness.
			elif 'aspx' in url.path:
				priority = 0.9
			priority = '<priority>{}</priority>'.format(priority)

			# Change frequency
			changefreq = '<changefreq>monthly</changefreq>'

			# Full entry
			sitemap_entry = '<url>{}{}{}{}{}</url>'.format(loc,
														   lastmod,
														   image_list,
														   changefreq,
														   priority)

			print (sitemap_entry, file=self.output_file)
			if self.output_file:
				self.output_file.flush()


		# Either way, we deal with the found links
		links = self.linkregex.findall(msg)
		for link in links:
			link = link.decode("utf-8", errors="ignore")
			link = self.clean_link(link)
			logging.debug("Found : {0}".format(link))

			if link.startswith('/'):
				link = url.scheme + '://' + url[1] + link
			elif link.startswith('#'):
				link = url.scheme + '://' + url[1] + url[2] + link
			elif link.startswith(("mailto", "tel")):
				continue
			elif not link.startswith(('http', "https")):
				link = url.scheme + '://' + url[1] + '/' + link

			# Remove the anchor part if needed
			if "#" in link:
				link = link[:link.index('#')]

			# Drop attributes if needed
			for toDrop in self.drop:
				link=re.sub(toDrop,'',link)

			# Parse the url to get domain and file extension
			parsed_link = urlparse(link)
			domain_link = parsed_link.netloc
			target_extension = os.path.splitext(parsed_link.path)[1][1:]

			if link.strip() == '':
				continue
			if link in self.crawled:
				continue
			if link in self.tocrawl:
				continue
			if link in self.ignored:
				continue
			if domain_link != self.target_domain:
				continue
			if parsed_link.path in ["", "/"]:
				continue
			if "javascript" in link:
				continue
			if self.is_image(parsed_link.path):
				continue
			if parsed_link.path.startswith("data:"):
				continue

			# Count one more URL
			self.nb_url+=1

			# Check if the navigation is allowed by the robots.txt
			if not self.can_fetch(link):
				self.ignore_link(link)
				self.nb_rp+=1
				continue

			# Check if the current file extension is allowed or not.
			if (target_extension in self.skipext):
				self.ignore_link(link)
				self.nb_ignore+=1
				continue

			# Check if the current url contains an ignored word
			if self.ignore_url(link):
				self.ignore_link(link)
				self.nb_ignore+=1
				continue

			self.tocrawl.add(link)

		return None

	def clean_link(self, link):
		# Ensure urls are HTTPS when we want them to be.
		if self.forcehttps:
			link = link.replace('http:', 'https:')

		l = urlparse(link)
		l_res = list(l)
		l_res[2] = l_res[2].replace("./", "/")
		l_res[2] = l_res[2].replace("//", "/")
		return urlunparse(l_res)

	def is_image(self, path):
		 mt,me = mimetypes.guess_type(path)
		 return mt is not None and mt.startswith("image/")

	def __continue_crawling(self):
		if self.tocrawl:
			self.__crawling()

	def ignore_link(self,link):
		if link not in self.ignored:
			self.ignored.add(link)

	def exclude_link(self,link):
		if link not in self.excluded:
			self.excluded.add(link)

	def check_robots(self):
		robots_url = urljoin(self.domain, "robots.txt")
		try:
			self.rp = RobotFileParser()
			self.rp.set_url(robots_url)
			self.rp.read()
		except Exception as e:
			logging.error("Could not read robots.txt so ignoring. Error: {}".format(e))
			self.parserobots = False

	def can_fetch(self, link):
		try:
			if self.parserobots:
				if self.rp.can_fetch("*", link):
					return True
				else:
					logging.debug("Crawling of {0} disabled by robots.txt".format(link))
					return False

			if not self.parserobots:
				return True

			return True
		except:
			# On error continue!
			logging.debug("Error during parsing robots.txt")
			return True

	def ignore_url(self, link):
		for ex in self.ignore:
			if ex in link:
				return True
		return False

	def exclude_url(self, link):
		for ex in self.exclude:
			if ex in link:
				return True
		return False

	def htmlspecialchars(self, text):
		return text.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")

	def make_report(self):
		print ("Number of found URL : {0}".format(self.nb_url))
		print ("Number of link crawled : {0}".format(len(self.crawled)))
		if self.parserobots:
			print ("Number of link block by robots.txt : {0}".format(self.nb_rp))
		if self.skipext or self.ignore:
			print ("Number of link ignore : {0}".format(self.nb_ignore))

		for code in self.response_code:
			print ("Nb Code HTTP {0} : {1}".format(code, self.response_code[code]))

		for code in self.marked:
			print ("Link with status {0}:".format(code))
			for uri in self.marked[code]:
				print ("\t- {0}".format(uri))
