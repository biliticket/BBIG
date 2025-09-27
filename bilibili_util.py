import hmac
import time
import uuid
import httpx
import random
import qrcode
import hashlib
import warnings

from functools import reduce
from urllib.parse import quote, urlencode
from typing import Optional, Tuple
from loguru import logger

class BilibiliClient:

    def __init__(self):
        self.uid = 0
        # ONLY FOR OS VER
        model_list = {
            "OnePlus": ["PJX110"]
        }
        self.brand = random.choice(list(model_list.keys()))
        self.model = random.choice(model_list[self.brand])
        self.show_init = False
        self.wbi = False
        self.app_sign = False
        self._get_newest_version()
        self.ua = self._gen_ua()
        self.headers = {
            'User-Agent': self.ua,
        }
        self.screen_info = "382*795*24"
        self.canvasFp = "".join([str(random.choice("0123456789abcdef")) for _ in range(32)])
        self.webglFp = "".join([str(random.choice("0123456789abcdef")) for _ in range(32)])
        self.feSign = "".join([str(random.choice("0123456789abcdef")) for _ in range(32)])
        self.session = httpx.Client(
            headers=self.headers,
            timeout=10,
            http2=True,
            event_hooks={
                "request": [self._on_request],
                "response": [self._on_response]
            },
            verify=False
        )
        self._init_buvid()
        self._getKeys()
        self.risk_header = self._gen_risk_header()

    def _get_newest_version(self):
        # resp = self.get("https://app.bilibili.com/x/v2/version?mobi_app=android")
        # use origin httpx
        tmp_headers = {
            'User-Agent': "Mozilla/5.0",
        }
        try:
            resp = httpx.get("https://app.bilibili.com/x/v2/version?mobi_app=android", headers=tmp_headers).json()
        except Exception as e:
            logger.error(f"获取最新版本失败: {e} Fallback to 8.35.0")
            self.biliAppVersion = "8350200"
            self.biliAppVersionName = "8.35.0"
            return
        self.biliAppVersion = resp['data'][0]['build']
        self.biliAppVersionName = resp['data'][0]['version']

    def _gen_ua(self):
        _dist = [
            f"Mozilla/5.0 (Linux; Android 15; {self.model} Build/{self._gen_build_id()}; wv)",
            f"AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0",
            f"Chrome/135.0.7049.{random.randint(1,150)} Mobile Safari/537.36",
            f"BiliApp/{self.biliAppVersion}",
            f"mobi_app/android",
            f"isNotchWindow/1",
            f"NotchHeight={random.randint(20, 40)}",
            f"mallVersion/{self.biliAppVersion}",
            f"mVersion/296",
            f"disable_rcmd/0",
            f"magent/BILI_H5_ANDROID_15_{self.biliAppVersionName}_{self.biliAppVersion}",
        ]
        return " ".join(_dist)

    def _gen_build_id(self):
        # NOT AVAILABLE YET
        return f"AP1A.240101.011"


    def _hmac_sha256(self, key, message):
        return hmac.new(key.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).digest().hex()

    def _getKeys(self):
        ts = int(time.time())
        o = self._hmac_sha256("XgwSnGZ1p",f"ts{ts}")
        csrf = self.session.cookies.get("bili_jct")
        if csrf is None:
            csrf = ""
        params = {
            "key_id":"ec02",
            "hexsign":o,
            "context[ts]":ts,
            "csrf": csrf,
        }
        resp = self.post("https://api.bilibili.com/bapis/bilibili.api.ticket.v1.Ticket/GenWebTicket", params=params)
        if resp['code'] != 0:
            img_key = ""
            sub_key = ""
            bili_ticket = ""
            bili_ticket_expires = 0
            logger.warning(f"获取ticket失败，无法访问Wbi接口: {resp}")
        else:
            img_url: str = resp['data']['nav']['img']
            sub_url: str = resp['data']['nav']['sub']
            bili_ticket: str = resp['data']['ticket']
            bili_ticket_expires: int = resp['data']['created_at'] + resp['data']['ttl']
            img_key = img_url.rsplit('/', 1)[1].split('.')[0]
            sub_key = sub_url.rsplit('/', 1)[1].split('.')[0]
        self.img_key = img_key
        self.sub_key = sub_key
        self.bili_ticket = bili_ticket
        self.session.cookies.update({
            "bili_ticket": bili_ticket,
            "bili_ticket_expires": str(bili_ticket_expires),
        })

    def get_csrf(self):
        csrf = None
        csrf = self.session.cookies.get("bili_jct", domain=".bilibili.com")
        if csrf is not None:
            return csrf
        csrf = self.session.cookies.get("bili_jct", domain="")
        if csrf is not None:
            return csrf
        return ""

    def _wbi_sign(self, params: dict) -> dict:
        mixinKeyEncTab = [
            46, 47, 18, 2, 53, 8, 23, 32, 15, 50, 10, 31, 58, 3, 45, 35, 27, 43, 5, 49,
            33, 9, 42, 19, 29, 28, 14, 39, 12, 38, 41, 13, 37, 48, 7, 16, 24, 55, 40,
            61, 26, 17, 0, 1, 60, 51, 30, 4, 22, 25, 54, 21, 56, 59, 6, 63, 57, 62, 11,
            36, 20, 34, 44, 52
        ]
        def getMixinKey(orig: str):
            '对 imgKey 和 subKey 进行字符顺序打乱编码'
            return reduce(lambda s, i: s + orig[i], mixinKeyEncTab, '')[:32]
        mixin_key = getMixinKey(self.img_key + self.sub_key)
        curr_time = round(time.time())
        params['wts'] = curr_time                                   # 添加 wts 字段
        params = dict(sorted(params.items()))                       # 按照 key 重排参数
        params = {
            k : ''.join(filter(lambda chr: chr not in "!'()*", str(v)))
            for k, v 
            in params.items()
        }
        query = urlencode(params)                      # 序列化参数
        wbi_sign = hashlib.md5((query + mixin_key).encode()).hexdigest()    # 计算 w_rid
        params['w_rid'] = wbi_sign
        return params

    def _init_buvid(self):
        # self.get("https://www.bilibili.com")
        random_md5_1 = hashlib.md5(str(random.random()).encode()).hexdigest()
        random_md5_2 = hashlib.md5(str(random.random()).encode()).hexdigest()
        buvid = f"XU{random_md5_1[2]}{random_md5_1[12]}{random_md5_1[22]}{random_md5_1}"
        buvid = buvid.upper()
        self.buvid = buvid
        fp_raw = random_md5_2 + time.strftime("%Y%m%d%H%M%S", time.localtime()) + "".join([str(random.choice("0123456789abcdef")) for _ in range(16)])
        fp_raw_sub_str = [fp_raw[i:i+2] for i in range(0, len(fp_raw), 2)]
        veri_code = 0
        for i in range(0, len(fp_raw_sub_str), 2):
            veri_code += int(fp_raw_sub_str[i], 16)
        veri_code = hex(veri_code%256)[2:]
        self.fp = f"{fp_raw}{veri_code}"
        resp = self.get("https://api.bilibili.com/x/frontend/finger/spi")
        if resp["code"] != 0:
            self.session.cookies.update({
                "buvid3": "",
                "buvid4": "",
                "buvid_fp": self.fp,
                "_uuid": self.gen_uuid_infoc(),
            })
            return
        self.session.cookies.update({
            "buvid3": resp["data"]["b_3"],
            "buvid4": resp["data"]["b_4"],
            "buvid_fp": self.fp,
            "_uuid": self.gen_uuid_infoc(),
        })


    def gen_uuid_infoc(self) -> str:
        t = int(time.time() * 1000) % 100000
        return str(uuid.uuid4()) + str(t).ljust(5, "0") + "infoc"

    def init_show_cookies(self):
        self.devicefp = uuid.uuid4().hex
        self.session.cookies.update({
            "msource": "bilibiliapp",
            "kfcSource": "bilibiliapp",
            "deviceFingerprint": self.devicefp,
        })
        self.show_init = True

    def _on_request(self, request: httpx.Request):
        if self.wbi:
            request.params = self._wbi_sign(request.params)
        if self.app_sign:
            # TODO: 实现app_sign
            pass
        self.session.cookies.update({
            "identify": quote(urlencode(self._app_sign({"ts": int(time.time() * 1000)}))),
            "screenInfo": self.screen_info,
            "canvasFp": self.canvasFp,
            "webglFp": self.webglFp,
            "feSign": self.feSign,
        })
        if not self.show_init and request.url.host == "show.bilibili.com":
            logger.warning("show ck not init")
        pass

    def _on_response(self, response: httpx.Response):
        pass

    def _gen_risk_header(self):
        uid = self.uid
        buvid = self.buvid
        identify = urlencode(self._app_sign({"ts": int(time.time() * 1000)}))
        identify = quote(identify)
        _dist = [
            f"appkey/1d8b6e7d45233436",
            f"brand/{self.brand}",
            f"localBuvid/{buvid}",
            f"mVersion/296",
            f"mallVersion/{self.biliAppVersion}",
            f"model/{self.model}",
            f"osver/15",
            f"platform/h5",
            f"uid/{uid}",
            f"channel/1",
            f"deviceId/{buvid}",
            f"sLocale/zh_CN",
            f"cLocale/zh_CN",
            f"identify/{identify}" 
        ]
        return " ".join(_dist)

    # NOT AVAILABLE YET
    def _app_sign(self,params: dict) -> dict:
        raise Exception("Not Available in Open Source Version")

    def gen_qr_url(self) -> Tuple[Optional[str], Optional[str]]:
        generate = self.get(
            "https://passport.bilibili.com/x/passport-login/web/qrcode/generate"
        )
        if generate["code"] == 0:
            url = generate["data"]["url"]
            key = generate["data"]["qrcode_key"]
        else:
            logger.error(generate)
            return None, None
        return url, key

    def check_qr_status(self, key) -> tuple[bool, bool]:
        '''
        return: (is_login, RETRY)
        '''
        url = (
                "https://passport.bilibili.com/x/passport-login/web/qrcode/poll?source=main-fe-header&qrcode_key="
                + key
            )
        check = self.get(url)
        if check["code"] != 0:
            logger.debug(check)
            logger.error(check["message"])
            return False, True
        if check["data"]["code"] == 0:
            self.check_login()
            return True, False
        elif check["data"]["code"] in [86101, 86090]:
            return False, True
        else:
            return False, False

    def check_login(self) -> Tuple[bool, Optional[dict]]:
        resp = self.get("https://api.bilibili.com/x/web-interface/nav")
        if resp["code"] == 0:
            self.uid = resp["data"]["mid"]
            self.username = resp["data"]["uname"]
            return True, resp["data"]
        else:
            return False, None


    def qrLogin(self): 
        warnings.warn(
            "This method is deprecated", DeprecationWarning
        )
        url, key = self.gen_qr_url()
        qr = qrcode.QRCode()
        qr.add_data(url)
        qr.print_ascii(invert=True)
        img = qr.make_image()
        img.show()
        while True:
            time.sleep(1)
            url = (
                "https://passport.bilibili.com/x/passport-login/web/qrcode/poll?source=main-fe-header&qrcode_key="
                + key
            )
            req = self.get(url)
            check = req["data"]
            if check["code"] == 0:
                break
            elif check["code"] == 86101:
                pass
            elif check["code"] == 86090:
                logger.info(check["message"])
            elif check["code"] == 86083:
                logger.error(check["message"])
                return False
            elif check["code"] == 86038:
                logger.error(check["message"])
                return False
            else:
                logger.error(check)
                return False
        self.uid = self.session.cookies.get("DedeUserID")
        return True

    def _print_session_header(self):
        cookies = self.session.cookies
        sessdata = cookies.get("SESSDATA")
        # rm sessdata
        cookies.pop("SESSDATA")
        cookies.update(
            {
                "SESSDATA": sessdata[:8]+"*"*16+ sessdata[-8:],
            }
        )
        logger.info(f"cookies: {cookies}")

        return self.session.headers, self.session.cookies

    # NOT AVAILABLE YET
    def generate_token(self, projectId: int, screenId: int, skuId: int, count: int, orderType: int, ts=None) -> str:
        raise Exception("Not Available in Open Source Version")

    # NOT AVAILABLE YET
    def generate_ctoken(
        self,
        touchend=-1,
        visibilitychange=-1,
        openWindow=-1,
        timer=-1,
        ticket_collection_t=0,
        scrollX=0,
        scrollY=0,
        innerWidth=255,
        innerHeight=255, 
        outerWidth=255,
        outerHeight=255,
        screenX=0,
        screenY=0,
        screenWidth=255,
        screenHeight=255,
        screenAvailWidth=255
    ):
        raise Exception("Not Available in Open Source Version")
      
    # NOT AVAILABLE YET
    def decode_ctoken(self, ctoken):
        raise Exception("Not Available in Open Source Version")

    # NOT AVAILABLE YET
    def generate_ptoken(self,ctoken, uid, timestamp):
        raise Exception("Not Available in Open Source Version")

    def get(self, url: str, **kwargs) -> httpx.Response:
        try:
            resp = self.session.get(url, **kwargs)
        except Exception as e:
            return {"code": -114514,"message": f"请求失败：{e}","data": None}
        if resp.status_code == 200:
            resp = resp.json()
            resp_content = {
                "code": resp["code"] if "code" in resp else resp["errno"] if "errno" in resp else None,
                "message": resp["message"] if "message" in resp else resp["msg"] if "msg" in resp else None,
                "data": resp["data"] if "data" in resp else None
            }
            return resp_content
        else:
            resp.read()
            resp_summary = resp.text if len(resp.text) < 30 else resp.text[:30] + "..."
            logger.error(f"非标状态码返回：[{resp.status_code}] {resp_summary}")
            content_type = resp.headers.get("Content-Type")
            if content_type and "application/json" in content_type:
                resp = resp.json()
                resp_content = {
                    "code": resp["code"] if "code" in resp else resp["errno"] if "errno" in resp else None,
                    "message": resp["message"] if "message" in resp else resp["msg"] if "msg" in resp else None,
                    "data": resp["data"] if "data" in resp else None
                }
            else:
                resp_content = {
                    "code": -resp.status_code,
                    "message": f"非标状态码返回：[{resp.status_code}] {resp_summary}",
                    "data": resp.text
                }
            return resp_content

            

    def post(self, url: str, **kwargs) -> httpx.Response:
        try:
            resp = self.session.post(url, **kwargs)
        except Exception as e:
            return {"code": -114514,"message": f"请求失败：{e}","data": None}
        if "raw" in locals():
            return resp
        if resp.status_code == 200:
            try:
                # logger.debug(f"Request headers: {resp.request.headers}")
                # logger.debug(f"Request body: {resp.request.content}")
                # logger.debug(f"Response headers: {resp.headers}")
                # logger.debug(f"Response content: {resp.text}")
                resp = resp.json()
                resp_content = {
                    "code": resp["code"] if "code" in resp else resp["errno"] if "errno" in resp else None,
                    "message": resp["message"] if "message" in resp else resp["msg"] if "msg" in resp else None,
                    "data": resp["data"] if "data" in resp else None
                }
                return resp_content
            except Exception as e:
                return {"code": -114514,"message": f"响应解析失败：{e}","data": None}
        elif resp.status_code == 429:
            resp.read()
            return {"code": 429,"message": f"请求被限流：[{resp.status_code}]","data": None}
        elif resp.status_code == 412:
            resp.read()
            return {"code": 412,"message": f"请求被风控：[{resp.status_code}]","data": None}
        else:
            resp.read()
            resp_summary = resp.text if len(resp.text) < 30 else resp.text[:30] + "..."
            logger.error(f"非标状态码返回：[{resp.status_code}] {resp_summary}")
            logger.debug(f"Response headers: {resp.headers}")  # 打印响应头
            logger.debug(f"Response content: {resp.text}")  # 打印响应内容
            content_type = resp.headers.get("Content-Type")
            if content_type and "application/json" in content_type:
                resp = resp.json()
                resp_content = {
                    "code": resp["code"] if "code" in resp else resp["errno"] if "errno" in resp else None,
                    "message": resp["message"] if "message" in resp else resp["msg"] if "msg" in resp else None,
                    "data": resp["data"] if "data" in resp else None
                }
            else:
                resp_content = {
                    "code": resp.status_code,
                    "message": None,
                    "data": resp.text
                }
            return resp_content

    # NOT AVAILABLE YET
    def save(self):
        raise Exception("Not Available in Open Source Version")

    # NOT AVAILABLE YET
    def load(self, data):
        raise Exception("Not Available in Open Source Version")
