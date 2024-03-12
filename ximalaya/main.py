import json
from utils import *



class XiMaLaYaAuth(object):
    def __init__(self, session=requests.session()):
        self.nonce = None
        self.session = session
        self.session_id = None
        self.session.headers = {
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            "Origin": "https://www.ximalaya.com",
            "Referer": "https://www.ximalaya.com/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
            "sec-ch-ua": "\"Chromium\";v=\"122\", \"Not(A:Brand\";v=\"24\", \"Microsoft Edge\";v=\"122\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\""
        }

    def get_token(self):
        """获取密码登录的token"""
        self.session_id = get_session_id()
        logger.debug("生成验证sessionId: {}", self.session_id)
        xmlyc = XiMaLaYaCaptcha("139", self.session_id, self.session)
        xmlyc.run()
        token = xmlyc.token
        xmlyc.session.close()
        logger.debug("验证码token: {}", token)
        self.session.cookies.set("fds_otp", token)
    
    def get_token_2(self):
        """当登录返回20005时，获取发送验证码的token"""
        xmlyc = XiMaLaYaCaptcha("152", self.session_id, self.session)
        xmlyc.run()
        token = xmlyc.token
        xmlyc.session.close()
        logger.debug("验证码token: {}", token)
        self.session.cookies.set("fds_otp", token)

    def login(self, phone, password):
        """账号密码登录"""
        self.get_token()
        password = rsa_encrypt(password)
        logger.debug("rsa加密后的password: {}", password)
        self.get_nonce()
        sign_data = {
            "account": phone,
            "nonce": self.nonce,
            "password": password
        }
        signature = sign(sign_data)
        logger.debug("计算签名, signature: {}", signature)
        return self.pwd_login(phone, password, signature)
    
    def login_2(self, phone, bizKey=None):
        """短信验证码登录"""
        self.get_token_2()
        self.get_nonce()
        self.send_sms(phone)
        time.sleep(0.5)
        sms = input("请输入收到的短信验证码: ")
        self.get_nonce()
        verify_data = self.verify_sms(phone, sms)
        self.get_nonce()
        return self.sms_login(smsKey=verify_data.get("bizKey"), bizKey=bizKey)

    def get_nonce(self):
        url = f"https://passport.ximalaya.com/web/nonce/{int(time.time() * 1000)}"
        response = self.session.get(url)
        if response.status_code != 200:
            raise XiMaLaYaException(f"nonce get fail! status_code: {response.status_code}, result: {response.text}")
        data = response.json()
        logger.debug("nonce get: {}", data)
        if data.get("ret", -1) != 0:
            raise XiMaLaYaException(f"nonce get fail! result: {data}")
        self.nonce = data.get("nonce")
        logger.debug("nonce: {}", self.nonce)

    def pwd_login(self, account, password, signature):
        url = "https://passport.ximalaya.com/web/login/pwd/v1"
        data = {
            "account": account,
            "password": password,
            "nonce": self.nonce,
            "signature": signature,
            "rememberMe": True
        }
        data = json.dumps(data, separators=(',', ':'))
        response = self.session.post(url, data=data)
        if response.status_code != 200:
            raise XiMaLaYaException(f"login fail! status_code: {response.status_code}, result: {response.text}")
        data = response.json()
        logger.debug("login: {}", data)
        if data.get("ret", -1) == 0:
            logger.success("登录成功! uid: {}", data.get("uid"))
            return data
        elif data.get("ret", -1) == 20005:
            logger.warning("需要手机短信验证码!")
            time.sleep(0.5)
            i = input("是否确认发送手机短信验证码[yes/no]: ")
            if i.upper() in ["Y", "YES"]:
                return self.login_2(data.get("mobileCipher"), data.get("bizKey"))
            raise XiMaLaYaException(f"login fail! result: {data}")
        else:
            raise XiMaLaYaException(f"login fail! result: {data}")

    def sms_login(self, smsKey, bizKey):
        url = "https://passport.ximalaya.com/web/login/mobile/validate/v1"
        data = {
            "bizKey": bizKey,
            "nonce": self.nonce,
            "smsKey": smsKey,
        }
        data.update({"signature": sign(data.copy())})
        data = json.dumps(data, separators=(',', ':'))
        response = self.session.post(url, data=data)
        if response.status_code != 200:
            raise XiMaLaYaException(f"sms login fail! status_code: {response.status_code}, result: {response.text}")
        data = response.json()
        logger.debug("sms login: {}", data)
        if data.get("ret", -1) == 0:
            logger.success("登录成功! uid: {}", data.get("uid"))
            return data
        else:
            raise XiMaLaYaException(f"sms login fail! result: {data}")


    def send_sms(self, mobile):
        url = "https://passport.ximalaya.com/web/sms/send"
        data = {
            "mobile": mobile,
            "nonce": self.nonce,
            "sendType": 1
        }
        data.update({"signature": sign(data.copy())})
        data = json.dumps(data, separators=(',', ':'))
        response = self.session.post(url, data=data)
        if response.status_code != 200:
            raise XiMaLaYaException(f"send sms fail! status_code: {response.status_code}, result: {response.text}")
        data = response.json()
        logger.debug("send sms: {}", data)
        if data.get("ret", -1) != 0:
            raise XiMaLaYaException(f"send sms fail! result: {data}")
        logger.success("发送短信验证码成功!")

    def verify_sms(self, mobile, sms):
        url = "https://passport.ximalaya.com/web/sms/verify"
        data = {
            "code": sms,
            "mobile": mobile,
            "nonce": self.nonce,
        }
        data.update({"signature": sign(data.copy())})
        data = json.dumps(data, separators=(',', ':'))
        response = self.session.post(url, data=data)
        if response.status_code != 200:
            raise XiMaLaYaException(f"verify sms fail! status_code: {response.status_code}, result: {response.text}")
        data = response.json()
        logger.debug("send sms: {}", data)
        if data.get("ret", -1) != 0:
            raise XiMaLaYaException(f"verify sms fail! result: {data}")
        logger.success("短信验证码验证成功!")
        return data


class XiMaLaYaCaptcha(object):
    def __init__(self, bp_id, session_id, session=requests.session()):
        self.token = None
        self.captcha_data = None
        self.bp_id = bp_id
        self.session_id = session_id
        self.session = session
        self.session.headers = {
            "authority": "mobile.ximalaya.com",
            "accept": "*/*",
            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "cache-control": "no-cache",
            "content-type": "application/json",
            "origin": "https://www.ximalaya.com",
            "pragma": "no-cache",
            "referer": "https://www.ximalaya.com/",
            "sec-ch-ua": "\"Chromium\";v=\"122\", \"Not(A:Brand\";v=\"24\", \"Microsoft Edge\";v=\"122\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"
        }

    def run(self):
        self.get_captcha()
        if self.captcha_data.get("type") == "slider":
            logger.debug("本次验证类型为无感验证!")
            self.slide()
        elif self.captcha_data.get("type") == "pass":
            logger.debug("本次验证类型为无感验证!")
            if "token" not in self.captcha_data:
                raise CaptchaException(f"未知错误! 返回内容未包含token! Error: {self.captcha_data}")
            logger.debug("验证成功!")
            self.token = self.captcha_data.get("token")
        else:
            raise CaptchaException(f"不支持的验证类型! {self.captcha_data.get('type')}")

    def slide(self):
        bg_url = self.captcha_data.get("data").get("bgUrl")
        slide_url = self.captcha_data.get("data").get("fgUrl")

        bg_data = urldownload(bg_url)
        logger.debug("背景图片下载成功!")
        slide_data = urldownload(slide_url)
        logger.debug("滑块图片下载成功!")

        distance = SlideCrack().get_distance(bg_data, slide_data)
        logger.debug("滑块缺口位置偏移: {}", distance)

        self.verify(distance)

    def get_captcha(self):
        url = "https://mobile.ximalaya.com/captcha-web/check/slide/get"
        params = {
            "bpId": str(self.bp_id),
            "sessionId": self.session_id
        }
        response = self.session.get(url, params=params)
        if response.status_code != 200:
            raise CaptchaException(f"加载验证数据失败！status_code: {response.status_code}, result: {response.text}")
        data = response.json()
        logger.debug("slide get: {}", data)
        if (data.get("result", "false") != "true" or "data" not in data) and data.get("type") != "pass":
            raise CaptchaException(f"加载验证数据失败！result: {data}")
        logger.debug("加载验证数据成功!")
        self.captcha_data = data

    def verify(self, distance):
        url = "https://mobile.ximalaya.com/captcha-web/valid/slider"
        captcha = [str(distance + 44), str(random.randint(1, 4))]
        data = {
            "bpId": int(self.bp_id),
            "sessionId": self.session_id,
            "type": self.captcha_data.get("type"),
            "captchaText": ",".join(captcha),
            "startX": 850,
            "startY": 501,
            "startTime": int(time.time() * 1000)
        }
        time.sleep(1)
        data = json.dumps(data, separators=(',', ':'))
        response = self.session.post(url, data=data)
        if response.status_code != 200:
            raise CaptchaException(f"验证失败，！status_code: {response.status_code}, result: {response.text}")
        data = response.json()
        logger.debug("valid slider: {}", data)
        if data.get("result", "false") != "true":
            raise CaptchaException(f"验证失败！result: {data}")
        logger.debug("验证成功!")
        self.token = data.get("token")


class XiMaLaYaAPI(object):
    def __init__(self, session=requests.session()):
        self.session = session
        self.session.headers = {
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            # "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "Pragma": "no-cache",
            "Referer": "https://www.ximalaya.com/login.html",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
            "sec-ch-ua": "\"Chromium\";v=\"122\", \"Not(A:Brand\";v=\"24\", \"Microsoft Edge\";v=\"122\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "xm-sign": ""
        }
        self.server_time = None
        self.time()
        self.xm_sign = f"{md5(f'himalaya-{self.server_time}')}(random_1){self.server_time}(random_2)now_time"

    def sign(self):
        xm_sign = self.xm_sign
        xm_sign = xm_sign.replace("random_1", str(random.randint(1, 99)))
        xm_sign = xm_sign.replace("random_2", str(random.randint(1, 99)))
        xm_sign = xm_sign.replace("now_time", str(int(time.time() * 1000)))
        self.session.headers.update({"xm-sign": xm_sign})
        logger.debug("设置xm-sign: {}", xm_sign)

    def time(self):
        headers = self.session.headers
        headers.update({"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"})
        url = "https://www.ximalaya.com/revision/time"
        response = self.session.get(url, headers=headers)
        if response.status_code != 200:
            raise XiMaLaYaException("获取服务器时间戳失败!")
        self.server_time = int(response.text)
        logger.debug("获取服务器时间戳成功! server_time: {}", self.server_time)

    def albums(self):
        url = "https://www.ximalaya.com/revision/metadata/v2/channel/albums"
        params = {
            "groupId": "14",
            "pageNum": "1",
            "pageSize": "30",
            "sort": "2"
        }
        self.sign()
        response = self.session.get(url, params=params)
        if response.status_code != 200:
            raise XiMaLaYaException(f"获取频道内容失败! status_code: {response.status_code}, result: {response.text}")
        data = response.json()
        logger.debug("channel.albums: {}", data)
        return data


if __name__ == '__main__':
    account = "19176044723"  # 账号
    password = "Phy20031031yyyyy"  # 密码

    xmlya = XiMaLaYaAuth()
    result = xmlya.login(account, password)  # 账号密码登录
    # result = xmlya.sms_login(account)  # 短信验证码登录
    logger.info(result)
    logger.info(xmlya.session.cookies.get_dict())

    # xmly_api = XiMaLaYaAPI(xmlya.session)
    # xmly_api.albums()


