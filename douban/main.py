from pprint import pprint

import requests
import re

from utils import encrypt, parse


def search(search_text):
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Pragma": "no-cache",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "sec-ch-ua": "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\""
    }
    url = "https://search.douban.com/movie/subject_search"
    params = {
        "search_text": search_text,
        "cat": "1002"
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code != 200:
        raise Exception("请求失败")
    # 正则匹配获取window.__DATA__的值
    pattern = re.compile(r'window.__DATA__ = "(.+?)"', re.S)
    result = pattern.search(response.text)
    if not result:
        raise Exception("获取Data失败")
    # 获取匹配结果
    __DATA__ = result.group(1)
    # 解密
    return encrypt(__DATA__)


if __name__ == '__main__':
    search_data = search("蜘蛛侠")
    data = parse(search_data)
    pprint(data)



