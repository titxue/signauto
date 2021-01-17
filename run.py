import requests
import json
import io
import random
import time
import re
import pyDes
import base64
import uuid
import sys
import os
import hashlib
import csv
from Crypto.Cipher import AES
from apscheduler.schedulers.blocking import BlockingScheduler


class DailyCP:
    def __init__(self, schoolName="学校名称"):
        self.key = "b3L26XNL"  # dynamic when app update
        self.session = requests.session()
        self.host = "hnchxy.campusphere.net"
        self.loginUrl = "学校登录地址url"
        self.isIAPLogin = True
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36 Edg/83.0.478.37",
            # "X-Requested-With": "XMLHttpRequest",
            "Pragma": "no-cache",
            "Accept": "application/json, text/plain, */*",
            # "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            # "User-Agent": "okhttp/3.12.4"
        })
        extension = {"deviceId": str(uuid.uuid4()), "systemName": "白洞操作系统", "userId": "5201314",
                     "appVersion": "8.1.13", "model": "黑洞量子计算机", "lon": 0.0, "systemVersion": "第一代", "lat": 0.0}
        self.session.headers.update(
            {"Cpdaily-Extension": self.encrypt(json.dumps(extension))})
        self.setHostBySchoolName(schoolName)

    def setHostBySchoolName(self, schoolName):
        ret = self.request(
            "https://static.campushoy.com/apicache/tenantListSort")
        school = [j for i in ret["data"]
                  for j in i["datas"] if j["name"] == schoolName]
        if len(school) == 0:
            print("不支持的学校或者学校名称错误,以下是支持的学校列表")
            print(ret)
            exit()
        ret = self.request(
            "https://mobile.campushoy.com/v6/config/guest/tenant/info?ids={ids}".format(ids=school[0]["id"]))
        self.loginUrl = ret["data"][0]["ampUrl"]
        if ret == "":
            print("学校并没有申请入驻今日校园平台")
            exit()
        # print("{name}的登录地址{url}".format(name=schoolName, url=self.loginUrl))
        self.host = re.findall(r"//(.*?)/", self.loginUrl)[0]

    def encrypt(self, text):
        k = pyDes.des(self.key, pyDes.CBC, b"\x01\x02\x03\x04\x05\x06\x07\x08",
                      pad=None, padmode=pyDes.PAD_PKCS5)
        ret = k.encrypt(text)
        return base64.b64encode(ret).decode()

    def passwordEncrypt(self, text: str, key: str):
        def pad(s): return s + (len(key) - len(s) %
                                len(key)) * chr(len(key) - len(s) % len(key))

        def _(s): return s[:-ord(s[len(s) - 1:])]
        text = pad(
            "TdEEGazAXQMBzEAisrYaxRRax5kmnMJnpbKxcE6jxQfWRwP2J78adKYm8WzSkfXJ"+text).encode("utf-8")
        aes = AES.new(str.encode(key), AES.MODE_CBC,
                      str.encode("ya8C45aRrBEn8sZH"))
        return base64.b64encode(aes.encrypt(text))

    def request(self, url: str, body=None, parseJson=True, JsonBody=True, Referer=None):
        url = url.format(host=self.host)
        if Referer != None:
            self.session.headers.update({"Referer": Referer})
        if body == None:
            ret = self.session.get(url)
        else:
            self.session.headers.update(
                {"Content-Type": ("application/json" if JsonBody else "application/x-www-form-urlencoded")})
            ret = self.session.post(url, data=(
                json.dumps(body) if JsonBody else body))
        if parseJson:
            return json.loads(ret.text)
        else:
            return ret

    def decrypt(self, text):
        k = pyDes.des(self.key, pyDes.CBC, b"\x01\x02\x03\x04\x05\x06\x07\x08",
                      pad=None, padmode=pyDes.PAD_PKCS5)
        ret = k.decrypt(base64.b64decode(text))
        return ret.decode()

    def checkNeedCaptcha(self, username):
        url = "https://{host}/iap/checkNeedCaptcha?username={username}".format(
            host=self.host, username=username)
        ret = self.session.get(url)
        ret = json.loads(ret.text)
        return ret["needCaptcha"]

    def getBasicInfo(self):
        return self.request("https://{host}/iap/tenant/basicInfo", "{}")

    def login(self, username, password, captcha=""):
        if "campusphere" in self.loginUrl:
            return self.loginIAP(username, password, captcha)
        else:
            return self.loginAuthserver(username, password, captcha)

    def loginIAP(self, username, password, captcha=""):
        self.session.headers.update({"X-Requested-With": "XMLHttpRequest"})
        ret = self.session.get(
            "https://{host}/iap/login?service=https://{host}/portal/login".format(host=self.host)).url
        client = ret[ret.find("=")+1:]
        ret = self.request("https://{host}/iap/security/lt",
                           "lt={client}".format(client=client), True, False)
        client = ret["result"]["_lt"]
        # self.encryptSalt = ret["result"]["_encryptSalt"]

        body = {
            "username": username,
            "password": password,
            "lt": client,
            "captcha": captcha,
            "rememberMe": "true",
            "dllt": "",
            "mobile": ""
        }
        ret = self.request("https://{host}/iap/doLogin", body, True, False)
        if ret["resultCode"] == "REDIRECT":
            self.session.get(ret["url"])
            # print(ret["url"])
            return True
        else:
            return False

    def checkNeedCaptchaAuthServer(self, username):
        ret = self.request("http://{host}/authserver/needCaptcha.html?username={username}&pwdEncrypt2=pwdEncryptSalt".format(
            username=username), parseJson=False).text
        # print(ret)
        return ret == "true"

    def loginAuthserver(self, username, password, captcha=""):
        ret = self.request(self.loginUrl, parseJson=False)
        body = dict(re.findall(
            r'''<input type="hidden" name="(.*?)" value="(.*?)"''', ret.text))
        salt = dict(re.findall(
            r'''<input type="hidden" id="(.*?)" value="(.*?)"''', ret.text))
        body["username"] = username
        body["dllt"] = "userNamePasswordLogin"
        if "pwdDefaultEncryptSalt" in salt.keys():
            body["password"] = self.passwordEncrypt(
                password, salt["pwdDefaultEncryptSalt"])
        else:
            body["password"] = password
        ret = self.request(ret.url, body, False, False,
                           Referer=self.loginUrl).url
        print(self.session.cookies)
        print("本函数不一定能用。")
        return True

    def getStuSignIn(self):
        body = {
            # "pageSize": 10,
            # "pageNumber": 1
        }
        ret = self.request(
            "https://{host}/wec-counselor-sign-apps/stu/sign/getStuSignInfosInOneDay", body)
        # print(ret["datas"])
        return ret["datas"]

    def SigninForm(self, wid, signInstanceWid):
        body = {
            "signWid": wid,
            "signInstanceWid": signInstanceWid
        }
        ret = self.request(
            "https://{host}/wec-counselor-sign-apps/stu/sign/detailSignInstance", body)
        return ret

    def autoComplete(self):
        collectList = self.getStuSignIn()
        # print(collectList)
        if collectList["unSignedTasks"]:
            item = collectList["unSignedTasks"][0]
        else:
            item = collectList["signedTasks"][0]

        form = self.SigninForm(item["signWid"], item["signInstanceWid"])
        # username =
        extraFieldItems = form['datas']["extraField"]
        extraFieldItemWids = []
        for extraFieldItem in extraFieldItems:
            # print(extraFieldItem["extraFieldItems"])
            for item in extraFieldItem["extraFieldItems"]:
                if item["content"] == "否" or item["content"] == "其它":
                    extraFieldItemWids.append(item["wid"])



        
        

        self.signed(form["datas"]["signInstanceWid"], extraFieldItemWids,form['datas']['signedStuInfo']['userName'])

    def signed(self, signInstanceWid, extraFieldItemWids,user):
        # 113.863019,34.793585
        data = {
            #定位地址经纬度
            "longitude":111 ,
            "latitude": 11 ,
            
            "isMalposition": 1,
            "abnormalReason": "",
            "signPhotoUrl": "",
            "isNeedExtra": 1,
            "position": "签到地点",
            "uaIsCpadaily": True,
            "signInstanceWid": str(signInstanceWid),
            "extraFieldItems": [
                {
                    "extraFieldItemValue": "否",
                    "extraFieldItemWid": str(extraFieldItemWids[0])
                },
                {
                    "extraFieldItemValue": "36.5",
                    "extraFieldItemWid": str(extraFieldItemWids[1])
                },
                {
                    "extraFieldItemValue": "否",
                    "extraFieldItemWid": str(extraFieldItemWids[2])
                },
                {
                    "extraFieldItemValue": "否",
                    "extraFieldItemWid": str(extraFieldItemWids[3])
                }
            ]
        }

        signurl = "https://{学校地址}/wec-counselor-sign-apps/stu/sign/submitSign"
        res = self.request(url=signurl, body=data)
        print("谁在签到：" + user )    
        
        if res["message"] == "SUCCESS":
            print("签到成功")
        else:
            print(res["message"])
            self.request(url = "server酱key ?text=【用户：{}】签到失败&desp={}".format(user,res["message"]))
            return 
        
            # print(res["datas"]) #返回数据
        if "SUCCESS" in res:
            print("[+] " + str([signInstanceWid, extraFieldItemWids]))
            self.request(url = "server酱key ?text=【用户：{}】签到成功&desp={}".format(user,res["message"]))
        else:
            print(str([signInstanceWid, extraFieldItemWids]))
            

def readUser():
    # 读取配置文件
    username = []
    with open("config.csv")as f:
        f_csv = csv.reader(f)
        next(f_csv)
        for row in f_csv:
            username.append(row)
    return username

def run():
    users = readUser()
    apps = []
    for _ in range(len(users)):
        apps.append(DailyCP())
    
    for (app,user) in zip(apps,users):
        app.login(user[0],user[1])
        app.autoComplete()

def runTime(hour=0, minute=10):
        # 定时运行
        print("您开启了每日{}时{}分的定时器。".format(hour,minute))
        scheduler = BlockingScheduler()
        scheduler.add_job(run, 'cron', hour=hour,minute=minute)
        try:
            scheduler.start()
        except (KeyboardInterrupt,SystemExit):
            pass




if __name__ == "__main__":
    run()
    # runTime(0,6)




# 更新日志
# 2021/1/17 优化提提示内容，添加server酱微信通知，修复签到失败bug
# 2021/1/16 增加批量登录，增加定时器。
# 2021/1/15 浪费别人的时间是一种可耻的行为。
