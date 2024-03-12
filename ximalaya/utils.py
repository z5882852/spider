import base64
import hashlib
import os
import random
import string
import sys
import time
import cv2
import numpy as np
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
from loguru import logger


CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))


# =======日志相关配置=======
SHOW_LOG = True
SAVE_LOG = False
DEBUG = True

logger.remove(0)
level = "DEBUG" if DEBUG else "INFO"
if SHOW_LOG:
    console_log_handler = logger.add(sys.stderr, level=level, enqueue=True)
if SAVE_LOG:
    LOG_DIR = os.path.join(CURRENT_PATH, "logs")
    if not os.path.exists(LOG_DIR):
        os.mkdir(LOG_DIR)
    LOG_PATH = os.path.join(LOG_DIR, "log_{time}.log")
    file_log_handler = logger.add(LOG_PATH, level=level, encoding="utf-8", enqueue=True)
logger.debug("日志初始化成功!")


class CaptchaException(Exception):
    def __init__(self, msg):
        self.msg = msg
        logger.error(msg)

    def __str__(self):
        return self.msg


class XiMaLaYaException(Exception):
    def __init__(self, msg):
        self.msg = msg
        logger.error(msg)

    def __str__(self):
        return self.msg


def urldownload(url):
    """
    下载文件到指定目录
    :param url: 文件下载的url
    :return:
    """
    down_res = requests.get(url)
    if down_res.status_code != 200:
        raise CaptchaException(f"下载数据失败! url:{url}")
    return down_res.content


def urlencode(data: dict):
    text = []
    for k, v in data.items():
        text.append(f"{k}={v}")
    return "&".join(text)


def decimal_to_base36(decimal_num):
    if not isinstance(decimal_num, int):
        raise ValueError("Input must be an integer")
    if decimal_num < 0:
        raise ValueError("Input must be a non-negative integer")

    alphabet = '0123456789abcdefghijklmnopqrstuvwxyz'
    base36_string = ''

    while decimal_num > 0:
        remainder = decimal_num % 36
        base36_string = alphabet[remainder] + base36_string
        decimal_num //= 36

    return base36_string or '0'


def generate_random_string(length):
    characters = string.digits + string.ascii_lowercase
    return ''.join(random.choice(characters) for _ in range(length))


def get_session_id():
    t = int(time.time() * 1000)
    r = "xm_"
    r += decimal_to_base36(t)
    r += generate_random_string(6)
    return r


def sign(data):
    text = urlencode(data)
    text += "&WEB-V1-PRODUCT-E7768904917C4154A925FBE1A3848BC3E84E2C7770744E56AFBC9600C267891F"
    return sha1(text.upper())


def md5(text: str):
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def sha1(text: str):
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def rsa_encrypt(text):
    key = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCVhaR3Or7suUlwHUl2Ly36uVmboZ3+HhovogDjLgRE9CbaUokS2eqGaVFfbxAUxFThNDuXq/fBD+SdUgppmcZrIw4HMMP4AtE2qJJQH/KxPWmbXH7Lv+9CisNtPYOlvWJ/GHRqf9x3TBKjjeJ2CjuVxlPBDX63+Ecil2JR9klVawIDAQAB\n-----END PUBLIC KEY-----"
    pub_key = RSA.importKey(str(key))
    cipher = PKCS1_cipher.new(pub_key)
    rsa_text = base64.b64encode(cipher.encrypt(bytes(text.encode("utf8"))))
    return rsa_text.decode('utf-8')



class SlideCrack(object):
    def __init__(self):
        pass

    def bytes_to_cv2(self, img):
        """
        二进制图片转cv2
        :param img: 二进制图片数据, <type 'bytes'>
        :return: cv2图像, <type 'numpy.ndarray'>
        """
        # 将图片字节码bytes, 转换成一维的numpy数组到缓存中
        img_buffer_np = np.frombuffer(img, dtype=np.uint8)
        # 从指定的内存缓存中读取一维numpy数据, 并把数据转换(解码)成图像矩阵格式
        img_np = cv2.imdecode(img_buffer_np, 1)
        return img_np

    def cv2_open(self, img, flag=None):
        if isinstance(img, bytes):
            img = self.bytes_to_cv2(img)
        elif isinstance(img, str):
            img = cv2.imread(str(img))
        elif isinstance(img, np.ndarray):
            img = img
        else:
            raise ValueError(f'输入的图片类型无法解析: {type(img)}')
        if flag is not None:
            img = cv2.cvtColor(img, flag)
        return img

    def get_distance(self, bg, tp):
        """
        :param bg: 背景图路径
        :param tp: 缺口图路径
        :param save_path: 保存路径
        :return: 缺口位置
        """
        # 读取图片
        bg_img = self.cv2_open(bg)
        tp_gray = self.cv2_open(tp, flag=cv2.COLOR_BGR2GRAY)

        # 金字塔均值漂移
        bg_shift = cv2.pyrMeanShiftFiltering(bg_img, 5, 50)

        # 边缘检测
        tp_gray = cv2.Canny(tp_gray, 255, 255)
        bg_gray = cv2.Canny(bg_shift, 255, 255)

        # 目标匹配
        result = cv2.matchTemplate(bg_gray, tp_gray, cv2.TM_CCOEFF_NORMED)
        # 解析匹配结果
        min_val, max_val, min_loc, max_loc = cv2.minMaxLoc(result)

        distance = max_loc[0]
        return distance


