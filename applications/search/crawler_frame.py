import logging
from datamodel.search.datamodel import ProducedLink, OneUnProcessedGroup, robot_manager, Link
from spacetime.client.IApplication import IApplication
from spacetime.client.declarations import Producer, GetterSetter, Getter
from lxml import html,etree
import re, os
from time import time

# Global Variables for Analytical Statistic:
maximumLink = ""
maximumNumber = 0
totalNumberOfInvalidLinks = 0
dictOfSubdomains = dict()

# Keys to Global Dict
DL_COUNT = 'dl_count'
MAX_LINK = 'max_link'
MAX_COUNT = 'max_count'
INVALID_COUNT = 'invalid_count'
SUB_DOMAINS = 'sub_domains'


Analytics = {
    DL_COUNT: 0,
    MAX_LINK: "",
    MAX_COUNT: 0,
    INVALID_COUNT: 0,
    SUB_DOMAINS: dict()
}


try:
    # For python 2
    from urlparse import urlparse, parse_qs, urljoin
except ImportError:
    # For python 3
    from urllib.parse import urlparse, parse_qs


logger = logging.getLogger(__name__)
LOG_HEADER = "[CRAWLER]"
url_count = (set() 
    if not os.path.exists("successful_urls.txt") else 
    set([line.strip() for line in open("successful_urls.txt").readlines() if line.strip() != ""]))
MAX_LINKS_TO_DOWNLOAD = 3000

@Producer(ProducedLink, Link)
@GetterSetter(OneUnProcessedGroup)
class CrawlerFrame(IApplication):

    def __init__(self, frame):
        self.starttime = time()
        # Set app_id <student_id1>_<student_id2>...
        self.app_id = "28474741_32431627_24136956"
        # Set user agent string to IR W17 UnderGrad <student_id1>, <student_id2> ...
        # If Graduate studetn, change the UnderGrad part to Grad.
        self.UserAgentString = "IR S17 UnderGrad 28474741, 32431627, 24136956"
		
        self.frame = frame
        assert(self.UserAgentString != None)
        assert(self.app_id != "")
        if len(url_count) >= MAX_LINKS_TO_DOWNLOAD:
            self.done = True

    def initialize(self):
        self.count = 0
        l = ProducedLink("http://www.ics.uci.edu", self.UserAgentString)
        print l.full_url
        self.frame.add(l)

    def update(self):
        for g in self.frame.get_new(OneUnProcessedGroup):
            print "Got a Group"
            outputLinks, urlResps = process_url_group(g, self.UserAgentString)
            for urlResp in urlResps:
                if urlResp.bad_url and self.UserAgentString not in set(urlResp.dataframe_obj.bad_url):
                    urlResp.dataframe_obj.bad_url += [self.UserAgentString]
            for l in outputLinks:
                if is_valid(l) and robot_manager.Allowed(l, self.UserAgentString):
                    lObj = ProducedLink(l, self.UserAgentString)
                    self.frame.add(lObj)
        if len(url_count) >= MAX_LINKS_TO_DOWNLOAD:
            self.done = True

    def shutdown(self):
        print "downloaded ", len(url_count), " in ", time() - self.starttime, " seconds."
        to_file()
        pass

def save_count(urls):
    global url_count
    urls = set(urls).difference(url_count)
    url_count.update(urls)
    if len(urls):
        with open("successful_urls.txt", "a") as surls:
            surls.write(("\n".join(urls) + "\n").encode("utf-8"))

def process_url_group(group, useragentstr):
    rawDatas, successfull_urls = group.download(useragentstr, is_valid)
    save_count(successfull_urls)
    return extract_next_links(rawDatas), rawDatas
    
#######################################################################################
'''
STUB FUNCTIONS TO BE FILLED OUT BY THE STUDENT.
'''
def extract_next_links(rawDatas):
    outputLinks = list()
    '''
    rawDatas is a list of objs -> [raw_content_obj1, raw_content_obj2, ....]
    Each obj is of type UrlResponse  declared at L28-42 datamodel/search/datamodel.py
    the return of this function should be a list of urls in their absolute form
    Validation of link via is_valid function is done later (see line 42).
    It is not required to remove duplicates that have already been downloaded. 
    The frontier takes care of that.

    Suggested library: lxml
    '''

    # print "##### EXTRACTING NEXT LINKS #####"
    # print "##### Raw Data Info #####"
    # print "Raw Data Length: ", len(rawDatas)

    for data in rawDatas:
        global Analytics
        # print "##### Data Info #####"
        print "URL: ", data.url.encode('utf-8')
        print "Is Redirected?: ", data.is_redirected
        print "Final URL: ", data.final_url.encode('utf-8') if data.is_redirected else "None"
        print "Error: ", data.error_message
        print "HTTP Code: |", data.http_code, "|"

        # Parse the url
        # print "##### Parsing URL #####"
        url = data.final_url if data.is_redirected else data.url
        parsed_url = urlparse(url)
        print "Parsed URL: ", parsed_url
        # Parse the data

        if parsed_url.hostname in Analytics[SUB_DOMAINS]:
            Analytics[SUB_DOMAINS][parsed_url.hostname] += 1
        else:
            Analytics[SUB_DOMAINS][parsed_url.hostname] = 0
        Analytic[DL_COUNT] += 1


        # Check if there is an error
        # print "##### Checking for error message #####"
        if data.error_message:
            print "Setting Bad URL to True"
            # There is an error.
            # Set bad url, and not do anything
            data.bad_url = True
        elif int(data.http_code) == 200:
            # print "##### Parsing Data #####"
            # There is no error, and everything is OK
            # Try to parse the data
            try:
                parsed_data = html.document_fromstring(data.content)
                # print "Parsed Data: ", parsed_data
            except etree.ParserError:
                print "Parser Error"
                continue # Formerly return
            except etree.XMLSyntaxError:
                print "XML Syntax Error"
                continue # Formerly return

            # print "##### Searching data #####"
            # Go through every link in the data
            for _, _, link, _ in parsed_data.iterlinks():
                print "Link: ", link
                # Make link absolute
                # print "##### Making url absolute #####"
                base_url = parsed_url.scheme + "://" + parsed_url.netloc
                # print "Base URL: ", base_url
                abs_url = urljoin(base_url, link)
                print "Absolute URL: ", abs_url


                outputLinks.append(abs_url)
        else:
            data.bad_url = True

    if len(outputLinks) > Analytics[MAX_COUNT]:
        Analytics[MAX_COUNT] = len(outputLinks)
        Analytics[MAX_LINK] = url
    # print "##### OUTPUT LINKS #####"
    print outputLinks
    # raw_input()
    return outputLinks

def is_valid(url):
    '''
    Function returns True or False based on whether the url has to be downloaded or not.
    Robot rules and duplication rules are checked separately.

    This is a great place to filter out crawler traps.
    '''

    print 'url', url
    global Analytic

    try:
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"]:
            Analytics[INVALID_COUNT] += 1
            return False
        if is_bad_url(url):
            Analytics[INVALID_COUNT] += 1
            return False
        isValid = re.search("\.ics\.uci\.edu\.?$", parsed.hostname) \
                  and not re.match(".*\.(css|js|bmp|gif|jpe?g|ico" + "|png|tiff?|mid|mp2|mp3|mp4" \
                                   + "|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|h5" \
                                   + "|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1" \
                                   + "|thmx|mso|arff|rtf|jar|csv" \
                                   + "|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

        if not isValid:
            Analytics[INVALID_COUNT] += 1
        else:
            print 'IS VALID YAY'
        return isValid

    except TypeError:
        print ("TypeError for ", parsed)


def is_bad_url(url):
    if url.startswith("#"):
        return True
    if url.startswith("javascript"):
        return True
    if url.startswith("mailto:"):
        return True
    if url.find('doku.php') != -1:
        return True
    if url.find('?') != -1:
        return True
    if url.count('.php') > 1:
        return True
    if url.find('.phphttp') != -1:
        return True
    # TRAP LINKS

    if url.startswith("http://calendar.ics.uci.edu"):
        return True

def to_file():
    print "Analytics to File"
    global Analytics
    import datetime
    with open('analytics.txt', 'a') as out:
        date = datetime.datetime.fromtimestamp(time()).strftime('%m-%d-%Y %H:%M:%S')
        out.writelines(date + '\n')
        out.writelines("# Successful Downloads: " + str(Analytics[DL_COUNT]) + '\n')
        out.writelines('# Invalid: ' + str(Analytics[INVALID_COUNT]) + '\n')
        out.writelines('Most Outgoing Link: ' + Analytics[MAX_LINK] + '\n')
        out.writelines('# Outgoing Links: ' + str(Analytics[MAX_COUNT]) + '\n')

        out.writelines('\n')
        out.writelines('Subdomains \n')
        for sub, links in Analytics[SUB_DOMAINS].iteritems():
            out.writelines(str(sub) + ": " + str(links) + '\n')

        out.writelines('\n\n')