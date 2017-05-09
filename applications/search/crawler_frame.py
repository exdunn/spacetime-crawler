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
IMAGE_COUNT = 'image_count'
VIDEO_COUNT = 'video_count'
AUDIO_COUNT = 'audio_count'
DOC_COUNT = 'document_count'
MISC_COUNT = 'misc_count'
JS_COUNT = 'js_count'
CSS_COUNT = 'css_count'
MIN_LINK = 'min_link'
MIN_COUNT = 'min_count'
CODE_COUNT = 'code_count'

Analytics = {
    DL_COUNT: 0,
    MAX_LINK: "",
    MAX_COUNT: 0,
    INVALID_COUNT: 0,
    SUB_DOMAINS: dict(),
    IMAGE_COUNT: 0,
    VIDEO_COUNT: 0,
    AUDIO_COUNT: 0,
    DOC_COUNT: 0,
    MISC_COUNT: 0,
    JS_COUNT: 0,
    CSS_COUNT: 0,
    MIN_LINK: "",
    MIN_COUNT: -1,
    CODE_COUNT: 0
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
    global Analytics  # For Analytics
    # Go through each raw data object
    for data in rawDatas:
        print "Is Redirected?: ", data.is_redirected
        print "Error: ", data.error_message
        print "HTTP Code: ", data.http_code

        # Check if the final url is OK (URL should be OK if in this method)
        data_good = not data.is_redirected or not data.final_url > 0 or is_valid_no_analytics(data.final_url)
        if not data_good:
            continue

        # Empty dict and list
        link_map = dict()
        link_links = list()

        # Parse the url
        url = data.final_url if data.is_redirected and data.final_url > 0 else data.url
        parsed_url = urlparse(url)

        # Add to subdomains count for Analytics
        if parsed_url.hostname in Analytics[SUB_DOMAINS]:
            Analytics[SUB_DOMAINS][parsed_url.hostname] += 1
        else:
            Analytics[SUB_DOMAINS][parsed_url.hostname] = 1
        Analytics[DL_COUNT] += 1

        # Check for error from frontier
        if data.error_message:
            # There is an error.
            # Set bad url, and not do anything
            data.bad_url = True
        # Check for HTTP error (Sometimes the code is a dict, Ignore those)
        elif type(data.http_code) is not dict and int(data.http_code) < 400:
            # Try to parse the html
            try:
                parsed_data = html.document_fromstring(data.content)
            except etree.ParserError:
                print "Parser Error"
                continue
            except etree.XMLSyntaxError:
                print "XML Syntax Error"
                continue

            # Go through every link in the data
            for _, _, link, _ in parsed_data.iterlinks():
                # Encode to utf-8
                link = link.encode('utf-8')
                print "Link: ", link
                # Remove queries and anchors
                anchor_mark = link.find('#')
                if anchor_mark != -1:
                    link = link[:anchor_mark]
                query_mark = link.find('?')
                if query_mark != -1:
                    link = link[:query_mark]
                # Base URL and Get Absolute URL from Relative
                base_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
                abs_url = urljoin(base_url, link)

                # Add to Link Dict for Analysis
                link_map[abs_url] = False

                # Check if the outgoing link is valid (without analytics)
                if is_valid_no_analytics(abs_url):
                    link_map[abs_url] = True
                    link_links.append(abs_url)

            # Write the outgoing links for this url to file
            with open('links.txt', 'a') as out:
                out.writelines('#  ' + str(url) + '\n')
                for l, g in link_map.iteritems():
                    out.writelines(str(l) + ' : ' + str(g) + '\n')
                out.writelines('\n')
        else:
            data.bad_url = True

        # If the url was good, then check for max outgoing and min outgoing
        if data_good:
            if len(link_links) > Analytics[MAX_COUNT]:
                Analytics[MAX_COUNT] = len(link_links)
                Analytics[MAX_LINK] = url
            elif len(link_links) < Analytics[MIN_COUNT] or Analytics[MIN_COUNT] == -1:
                Analytics[MIN_COUNT] = len(link_links)
                Analytics[MIN_LINK] = url
        # Add to output links
        outputLinks.extend(link_links)

    # Print all outgoing links
    for i, l in enumerate(outputLinks):
        print i, ": ", l

    print '\n'
    # Return outgoing links
    return list()


def is_valid(url):
    '''
    Function returns True or False based on whether the url has to be downloaded or not.
    Robot rules and duplication rules are checked separately.

    This is a great place to filter out crawler traps.
    '''

    print 'url: ', url
    global Analytics
    url_check = True
    try:
        # Parse the URL
        parsed = urlparse(url)
        # Check the scheme
        if parsed.scheme not in ["http", "https"]:
            Analytics[INVALID_COUNT] += 1
            url_check = False
        # Check the URL for invalidity(?)
        if is_bad_url(url):
            Analytics[INVALID_COUNT] += 1
            url_check = False
        # Check the URL's extension (if any)
        if analytics_url(url, True):
            Analytics[INVALID_COUNT] += 1
            url_check = False
        # Check the URL for domain, and extension
        isValid = re.search("\.ics\.uci\.edu\.?$", parsed.hostname) \
                  and not re.match(".*\.(css|js|bmp|gif|jpe?g|ico" + "|png|tiff?|mid|mp2|mp3|mp4" \
                                   + "|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|h5" \
                                   + "|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1" \
                                   + "|thmx|mso|arff|rtf|jar|csv" \
                                   + "|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

        if not isValid:
            Analytics[INVALID_COUNT] += 1
        if not isValid or not url_check:
            # Write the invalid URL
            with open('invalids.txt', 'a') as out:
                out.writelines('#' + str(url) + '\n')
                out.writelines('\n')
        print '\n'
        return isValid and url_check
    except TypeError:
        print ("TypeError for ", parsed)


def is_valid_no_analytics(url):
    # Non Analytics version of is valid
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"]:
            return False
        if is_bad_url(url):
            return False
        if analytics_url(url, False):
            return False
        isValid = re.search("\.ics\.uci\.edu\.?$", parsed.hostname) \
                  and not re.match(".*\.(css|js|bmp|gif|jpe?g|ico" + "|png|tiff?|mid|mp2|mp3|mp4" \
                                   + "|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|h5" \
                                   + "|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1" \
                                   + "|thmx|mso|arff|rtf|jar|csv" \
                                   + "|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())
        return isValid
    except TypeError:
        print ("TypeError for ", parsed)


def is_bad_url(url):
    # No scheme version of the URL
    no_scheme_url = url[8:] if url[:8] == 'https://' else url[7:]

    if url.find('?') != -1 and url.find('doku.php') != -1:
        print 'INVALID: doku and query'
        return True

    # Check the beginning of the link for funny stuff
    if not url[:5].startswith('http'):
        print "INVALID: Does not begin with http"
        return True

    # .php Stuff
    if url.count('.php') > 1:
        print "INVALID: More than one .php"
        return True
    if url.count('.php') == 1:
        if url.find('doku') == -1 and url[:-4].find('.php') != -1:
            print 'INVALID: Not doku and .php is not at the end'
            return True
        if url.find('doku') == -1 and re.search('\.php.', url):
            print 'INVALID: .php is followed by a character'
            return True

    # .html Stuff
    if url.count('.html') > 1:
        print 'INVALID: More than one .html'
        return True
    if url[:-5].find('.html') != -1:
        print 'INVALID: .html found not at the end'

    # Doku Stuff
    if url.find('doku.php') != -1:
        php_index = url.find('.php')
        if php_index + 4 < len(url) and (url[php_index + 4] != '?' and url[php_index + 4] != '/'):
            print 'INVALID: A character that is not ? nor nothing follows .php'
            return True

    # Misc. Stuff
    if url.find('..') != -1:
        print 'INVALID: .. is found'
        return True
    if re.search('/{2,}', no_scheme_url):
        print 'INVALID: Consecutive /\'s are found outside of scheme'
        return True
    if no_scheme_url.count('/') >= 10:
        print 'INVALID: Path depth is greater than 10'
        return True

    # Trap subdomains
    if url.startswith("http://calendar.ics.uci.edu"):
        print 'INVALID: Is the trap calendar'
        return True

    if url.startswith("https://ganglia.ics.uci.edu"):
        print 'INVALID: Is the trap ganglia'
        return True

    # if url.startswith("https://duttgroup.ics.uci.edu"):
    #     print 'INVALID: Is the trap duttgroup'
    #     return True

    if url.startswith("http://vcp.ics.uci.edu"):
        print 'INVALID: Is the trap vcp'
        return True

    return False


def analytics_url(url, set):
    global Analytics
    # Analytics stuff
    last_dot = url[-6:].rfind('.')
    if last_dot == -1:
        return False
    ext_url = url[-6:][last_dot:].lower()
    print 'Extension: ', ext_url
    pic_formats = '(ani|bmp|cal|fax|gif|img|jbg|jpe|jpeg|jpg|mac|pbm|pcd|pcx|pct|pgm|png|ppm|psd|ras|tga|tiff|wmf|ico|ps|eps)'
    if re.match('.' + pic_formats, ext_url):
        print 'PICTURE EXTENSION FOUND'
        if set: Analytics[IMAGE_COUNT] += 1
        return True
    vid_formats = '(avi|asf|mov|qt|avchd|flv|swf|mpg|mpeg|mp4|wmv|divx|fla|rm|m4v|mkv|ogv)'
    if re.match('.' + vid_formats, ext_url):
        print 'VIDEO EXTENSION FOUND'
        if set: Analytics[VIDEO_COUNT] += 1
        return True
    aud_formats = '(wav|aiff|mp3|mpa|m4a|wma|wma9|ogg|flac|mp2|mp4|aifc|mwf|ram|mid)'
    if re.match('.' + aud_formats, ext_url):
        print 'AUDIO EXTENSION FOUND'
        if set: Analytics[AUDIO_COUNT] += 1
        return True
    doc_formats = '(pdf|doc|docx|xls|xlsx|ppt|pptx|tex|smil|csv|rtf|arff|mso|thmx|epub|txt)'
    if re.match('.' + doc_formats, ext_url):
        print 'DOC EXTENSION FOUND'
        if set: Analytics[DOC_COUNT] += 1
        return True
    misc_formats = '(dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|dll|cnf|tgz|sha1|jar|zip|rar|gz|data|names|h5|lif|war)'
    if re.match('.' + misc_formats, ext_url):
        print 'MISC EXTENSION FOUND'
        if set: Analytics[MISC_COUNT] += 1
        return True
    if re.match('.' + 'js', ext_url):
        print 'JS EXTENSION FOUND'
        if set: Analytics[JS_COUNT] += 1
        return True
    if re.match('.' + 'css', ext_url):
        print 'CSS EXTENSION FOUND'
        if set: Analytics[CSS_COUNT] += 1
        return True
    code_formats = '(java|cs|py|xml)'
    if re.match('.' + code_formats, ext_url):
        print 'CODE EXTENSION FOUND'
        if set: Analytics[CODE_COUNT] += 1
        return True
    return False


def to_file():
    print "Analytics to File"
    global Analytics
    import datetime
    with open('analytics.txt', 'a') as out:
        date = datetime.datetime.fromtimestamp(time()).strftime('%m-%d-%Y %H:%M:%S')
        out.writelines(date + '\n')
        out.writelines("# Successful Downloads: " + str(Analytics[DL_COUNT]) + '\n')
        out.writelines('# Invalid Links: ' + str(Analytics[INVALID_COUNT]) + '\n')
        out.writelines('# Most Outgoing Link: ' + Analytics[MAX_LINK] + '\n')
        out.writelines('# Outgoing Links: ' + str(Analytics[MAX_COUNT]) + '\n')
        out.writelines('# Least Outgoing Link: ' + Analytics[MIN_LINK] + '\n')
        out.writelines('# Outgoing Links: ' + str(Analytics[MIN_COUNT]) + '\n')

        out.writelines('\n')
        out.writelines('Subdomains \n')
        for sub, links in Analytics[SUB_DOMAINS].iteritems():
            out.writelines(str(sub) + " : " + str(links) + '\n')
        out.writelines('\n')

        out.writelines('Other Stats \n')
        out.writelines('# Number of Image Files: ' + str(Analytics[IMAGE_COUNT]) + '\n')
        out.writelines('# Number of Video Files: ' + str(Analytics[VIDEO_COUNT]) + '\n')
        out.writelines('# Number of Audio Files: ' + str(Analytics[AUDIO_COUNT]) + '\n')
        out.writelines('# Number of Document Files: ' + str(Analytics[DOC_COUNT]) + '\n')
        out.writelines('# Number of Misc. Files: ' + str(Analytics[MISC_COUNT]) + '\n')
        out.writelines('# Number of JS Files: ' + str(Analytics[JS_COUNT]) + '\n')
        out.writelines('# Number of CSS Files: ' + str(Analytics[CSS_COUNT]) + '\n')
        out.writelines('# Number of Code Files: ' + str(Analytics[CODE_COUNT]) + '\n')
        out.writelines('\n')

        out.writelines('\n')