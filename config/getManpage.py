from bs4 import BeautifulSoup
import bs4
import requests
import json

import re

opensslmanpage = "https://www.openssl.org/docs/man3.0/man3/"

def filterByKeyword(key:str,word:str):
    """解析openssl文档，过滤相关标签

    Args:
        key (str): 用正则过滤关键词
    """
    
    html = requests.get(opensslmanpage).content.decode('utf-8')
    soup = BeautifulSoup(html,"lxml")
    table = soup.table
    funNameList = []
    funNameList = json.load(open("fun.json","r"))
    count = 0
    for td in table.children:
        if type(td)== bs4.element.Tag:
            if td.a == None:
                continue
            else:
                funName = td.a.string
                result = re.match(key,funName)
                if result != None:
                    count+=1
                    funNameList.append(funName)
    print(word+" count : ",count)
    json.dump(funNameList,open("fun.json","w"),indent=1)
keyword = ["md5|MD5","des|DES","aes|AES","RSA|rsa","EC|ec","sha1|SHA1","RC4|rc4","SSL","TLS","md4|MD4","RC2|rc2","BF","DSA","EVP_Encrypt","EVP_Digest","EVP_PKEY"]
if __name__ == "__main__":
    for key in keyword:
        filterByKeyword(".*({}).*".format(key),key)
    # 构造表达式，查找DES 或des 并且前后并不包含字母