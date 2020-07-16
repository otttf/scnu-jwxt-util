import bs4
import base64
import pandas
import re
import requests
import rsa
import time


def timestamp():
    return int(time.time() * 1000)


class ScnuJwxtLoginForm:
    class InvalidAccountOrPasswordError(Exception):
        pass

    def __init__(self):
        self.username = ""
        self.password = ""
        self.time = timestamp()
        self.session = requests.session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/84.0.4147.89 Safari/537.36 '
        })

    @staticmethod
    def hextob64(s):
        return str(base64.b64encode(s), 'utf-8')

    @staticmethod
    def b64tohex(s):
        return base64.b64decode(s).hex()

    # 用户登录
    def login(self):
        # 1、访问页面，获取csrftoken
        resp = self.session.get('https://jwxt.scnu.edu.cn/xtgl/login_slogin.html')
        soup = bs4.BeautifulSoup(resp.text, "lxml")
        csrftoken = soup.find('input', id='csrftoken')['value']
        # 2、获取密钥信息
        rsa_key_info = self.session.get(
            f'https://jwxt.scnu.edu.cn/xtgl/login_getPublicKey.html?time={self.time}').json()
        modulus = int(ScnuJwxtLoginForm.b64tohex(rsa_key_info['modulus']), 16)
        exponent = int(ScnuJwxtLoginForm.b64tohex(rsa_key_info['exponent']), 16)
        pub_key = rsa.PublicKey(modulus, exponent)
        # 3、公钥加密密码
        enpsw = ScnuJwxtLoginForm.hextob64(rsa.encrypt(self.password.encode('utf-8'), pub_key))
        # 4、登录
        resp = self.session.post(f'https://jwxt.scnu.edu.cn/xtgl/login_slogin.html?time={self.time}', headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        }, data=[('csrftoken', csrftoken), ('yhm', self.username), ('mm', enpsw), ('mm', enpsw)])
        if re.match('用户名或密码不正确', resp.text):
            raise ScnuJwxtLoginForm.InvalidAccountOrPasswordError


class ScnuJwxt:
    def __init__(self, sjlf: ScnuJwxtLoginForm):
        self.username = sjlf.username
        self.session = sjlf.session

    def query_all_score(self):
        fi = {'xnmmc': ['学年', str], 'xqmmc': ['学期', int], 'cj': ['成绩', int], 'xf': ['学分', float], 'jd': ['绩点', float],
              'kcmc': ['课程名称', str], 'jsxm': ['教师姓名', str]}
        a = zip(*fi.values())
        resp = self.session.post('https://jwxt.scnu.edu.cn/cjcx/cjcx_cxDgXscj.html?doType=query&gnmkdm=N305005', data={
            'xnm': '',
            'xqm': '',
            '_search': False,
            'nd': int(time.time() * 1000),
            'queryModel.showCount': 5000,
            'queryModel.currentPage': 1,
            'queryModel.sortName': '',
            'queryModel.sortOrder': 'asc',
            'time': 1
        }).json()
        li = [list(list(zip(*fi.values()))[0])]
        li.extend([[v[1](it[k]) for k, v in fi.items() if it.get(k) is not None] for it in resp['items']])
        return pandas.DataFrame(li)


def run():
    import sys
    sjlf = ScnuJwxtLoginForm()
    sjlf.username = input('用户名：')
    sjlf.password = input('密码：')
    print('2')
    sjlf.login()
    sj = ScnuJwxt(sjlf)
    df = sj.query_all_score()
    print(df)


if __name__ == '__main__':
    run()
