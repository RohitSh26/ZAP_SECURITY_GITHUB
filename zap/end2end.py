import os, sys, time, urllib, re, traceback, string, logging, requests

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import Select
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.proxy import Proxy, ProxyType

from zapv2 import ZAPv2
from zap_common import *

target = 'https://zapsecurity.azurewebsites.net'
zap_ip = '0.0.0.0'
port = 8080

http_proxy = 'http://'+zap_ip+':'+str(port)
https_proxy = 'https://'+zap_ip+':'+str(port)

report_dir = './out/'

def main():
    print('start webdriver...')

    profile = webdriver.FirefoxProfile()
    profile.set_preference('newtwork.proxy.type', 5)
    profile.set_preference('network.proxy.http', '0.0.0.0')
    profile.set_preference('network.proxy.http_port', 8080)
    profile.accept_untrusted_certs = True
    profile.update_preferences()

    proxy = '0.0.0.0:8080'

    options = Options()
    options.headless = True

    firefox_capabilities = webdriver.DesiredCapabilities.FIREFOX
    firefox_capabilities['marionette'] = True
    
    firefox_capabilities['proxy'] = {
        'proxyType': 'MANUAL',
        'httpProxy': proxy,
        'ftpProxy': proxy,
        'sslProxy': proxy,
    }

    driver = webdriver.Firefox(firefox_profile=profile, 
                                executable_path='/usr/bin/geckodriver', 
                                capabilities=firefox_capabilities, 
                                options=options)

    # driver = webdriver.Firefox(
    #                             # firefox_profile=profile, 
    #                             # executable_path='/usr/bin/geckodriver', 
    #                             # capabilities=firefox_capabilities, 
    #                             options=options)

    driver.get(target)

    print('navigated..')

    driver.close()

    print('done')

def run_active_scan_generate_reports(zap):
    print('start active scan')
    scan_policy = 'Default Policy'
    zap_active_scan(zap, target, scan_policy)

    print('active scan completed')
    urls = zap.core.urls()
    saperator = '\n'
    url_report=saperator.join(urls)
    url_report += '\n' + 'Total of ' + str(len(urls)) + ' URLs'

    print('generate reports')

    generate_html_report(zap)

    generate_URLs_report(url_report)

    print('report generation complete')

    print('shutdown zap')

def generate_html_report(zap):
    reports = zap.core.htmlreport()
    with open(report_dir + 'zap_scan_report.html', mode='wb') as f:
        if not isinstance(reports, binary_type):
            report = reports.encode('utf-8')
    
        f.write(report)

def generate_URLs_report(url_report):
    with open(report_dir + 'zap_scan_URL_report.json', mode='wb') as f:
        if not isinstance(url_report, binary_type):
            report = url_report.encode('utf-8')
    
        f.write(report)

if __name__ == "__main__":
    zap = ZAPv2(proxies={'http': http_proxy, 'https': https_proxy})
    main()
    run_active_scan_generate_reports(zap)



# zap.sh -deamon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.disablekey=true
# docker run --detach --name zap -u zap -v "$(pwd)/reports":/zap/reports/:rw -i zapsecurity zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.disablekey=true