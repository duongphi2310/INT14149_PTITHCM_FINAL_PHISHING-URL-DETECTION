import pandas as pd
import numpy as np
import sys
import re
from urllib.parse import urlparse,urlencode
from bs4 import BeautifulSoup
from datetime import datetime
import ipaddress
import whois
import urllib
import urllib.request
import tldextract
import pickle

class FeatureExtract:

    def __init__(self):
        pass  

    def isIP(self,url):
        try:
            ipaddress.ip_address(url)
            ip = 1
        except:
            ip = 0
        return ip  

    def isValid(self,domain_name):
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
            try:
                creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
            except:
                  return 1
        if ((expiration_date is None) or (creation_date is None)):
            return 1
        elif ((type(expiration_date) is list) or (type(creation_date) is list)):
            return 1
        else:
            ageofdomain = abs((expiration_date - creation_date).days)
            if ((ageofdomain/30) < 6):
                age = 1
            else:
                age = 0
        return age

    def domain_reg_len(self,domain_name):
        print('hello')
        expiration_date = domain_name.expiration_date
        if isinstance(expiration_date,str):
            try:
                expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
            except:
                return 1
        if (expiration_date is None):
            return 1
        elif (type(expiration_date) is list):
            return 1
        else:
            today = datetime.now()
            end = abs((expiration_date - today).days)
            if ((end/30) < 6):
                end = 0
            else:
                end = 1
        return end

    def isat(self,url):
        if "@" in url:
            return 1    
        else:
            return 0    

    def isRedirect(self,url):
        pos = url.rfind('//')
        if pos > 6:
            if pos > 7:
                return 1
            else:
                return 0
        else:
            return 0

    def haveDash(self,url):
        if '-' in urlparse(url).netloc:
            return 1            
        else:
            return 0   
    
    def no_sub_domain(self,url):
        url = str(url)
        url = url.replace("www.","")
        url = url.replace("."+tldextract.extract(url).suffix,"")
        count = url.count(".")
        if count==1:
            return 0
        else:
            return 1


    def httpDomain(self,url):
        domain = urlparse(url).netloc
        if 'http' in domain:
            return 1
        else:
            return 0

    def LongURL(self,url):
        if len(url) < 54:
            return 0           
        else:
            return 1            

    def tinyURL(self,url):
        shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"
        match=re.search(shortening_services,url)
        if match:
            return 1
        else:
            return 0

class PredictURL(FeatureExtract):
    def __init__(self):
        pass  
    
    def predict(self,url):
        print("hi")

        feature = []
        dns = 0

        feature.append(self.isIP(url))
        feature.append(self.isat(url))
        feature.append(self.isRedirect(url))
        feature.append(self.haveDash(url))
        feature.append(self.no_sub_domain(url))
        feature.append(self.LongURL(url))
        feature.append(self.tinyURL(url))
        
        return self.classify(np.array(feature).reshape((1,-1))) 
    
    def __getstate__(self):
        state = self.__dict__.copy() 
        return state
    
    def __setstate__(self, state):
        self.__dict__.update(state)
        
    def classify(self,features):
        pick_file = open('PHISHING_CLASSIFIER.pkl', 'rb') 
        Pickled_sample_Model = pickle.load(pick_file)
        pick_file.close()

        result = Pickled_sample_Model.predict(features)
        if result == 0:
            return "ĐÂY CÓ THỂ LÀ TRANG WEB HỢP PHÁP (LEGITIMATE)."
        else:
            return "ĐÂY CÓ THỂ LÀ TRANG WEB ĐÁNG NGỜ (PHISHING)."

def main():
    pass

if __name__ == "__main__":
    main()