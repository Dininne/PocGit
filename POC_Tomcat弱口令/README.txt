## ✨使用指南

* ** 运行环境 **
本工具基于[Python 3.x]开发和测试，运行环境需要高于Python 3.x版本才能运行。

安装Python环境可以参考[Python 3 安装指南](https://pythonguidecn.readthedocs.io/zh/latest/starting/installation.html#python-3)。

运行以下命令检查Python和pip3版本：
python -v


* ** 安装依赖 **
pip install -r requirements.txt


* ** FoFa语句 **
title="Apache Tomcat"


* ** 推荐语句 **
*
* URL批量检测并保存：
python POC_Tomcat弱口令.py -f url.txt -u user.txt -p pass.txt -o result.txt 

* 单个URL检测：
python POC_Tomcat弱口令.py -t url -u user.txt -p pass.txt


* ** 支持参数 **
  -t, --target      指定目标URL
  -f, --file        指定批量URL文件路径
  -o, --output      指定保存 存在漏洞URL的txt文件
  -u, --userfile    指定 用户名文件路径
  -p, --passfile    指定 密码文件路径
  -h, --help        列出帮助信息


## 👍功能特性
* **支持  单域名  验证**,通过 -t 参数 单域名验证
* **支持 批量域名 验证**,通过 -f 参数 批量域名验证
* **支持 结果导出 **，通过 -o 参数 支持导出 txt文件
* **速度极快**
* **体验良好**


## 👏用到框架
* [argparse, sys, json, re, os ,base64 ] - 系统自带，无需动手
* [requests](https://github.com/psf/requests) - Requests 唯一的一个非转基因的 Python HTTP 库，人类可以安全享用。


## 📜免责声明
本工具仅能在取得足够合法授权的企业安全建设中使用，在使用本工具过程中，您应确保自己所有行为符合当地的法律法规。 
如您在使用本工具的过程中存在任何非法行为，您将自行承担所有后果，本工具所有开发者和所有贡献者不承担任何法律及连带责任。
除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。
您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。