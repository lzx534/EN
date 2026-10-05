# ==========================================================
# 📦 utils.py -----这里是本殿下的工具箱
#  使用说明，工具箱里面暂时有五个工具，分别是：基础日志，重试请求，最佳描述，cvss评分，统一储存（未完待续）
# ==========================================================

import requests
import pandas as pd
import time
import datetime
import logging
import sqlite3
import logging

# 🛠️ 工具一 ：基础日志
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,#将日志存储加了个级别限制
        format="%(asctime)s-%(levelname)s-%(message)s",#日志包含的具体消息
        handlers=[
        logging.FileHandler('spider_run_log',encoding='utf-8', mode="a"),#文件名字是spider_run_log，utf-8代表删除最后结果的逗号，a是让下一个数据直接加到后面，不用覆盖
        logging.StreamHandler() #文件夹和控制台都要显示
        ])
logging.getLogger("requests").setLevel(logging.WARNING)

# 🛠️ 工具二 ：重试请求
def fetch_with_retry(url,params,headers,max_retries=3,timeout=50,):
    for attempt in range(max_retries):
        try:
            response = requests.get(
                url,
                params = params,
                headers = headers,
                timeout = timeout
            )

            #检查服务器返回时的HTTP的状态的状态码，将返还数据都编成Json的格式，方便读取
            response.raise_for_status()
            return response

        #如果返回失败，检查具体原因
        except requests.exceptions.Timeout:
            logging.error(f"请求超时，第{attempt + 1}次重试")
        except requests.exceptions.ConnectionError as error:
            logging.error(f"连接错误:{error},第{attempt + 1}次重试")
        except requests.exceptions.RequestException as error:
            logging.error(f"请求失败：{error},第{attempt + 1}次重试")
        if attempt < max_retries - 1:
            time.sleep(2)


    logging.error("重试还是失败")
    return None

# 🛠️ 工具三 ：最佳描述
def get_best_descriptions(descriptions,target_lang="en"):

    #如果没有描述，直接返回空列表
    if not descriptions:
       return ""

    #假设最开始的目标描述不存在
    target_desc = None

    #建立一个for 循环，当满足有中文叙述的条件，停止
    for goal in descriptions:
        if goal.get("lang") != target_lang:
           continue
        if not goal.get("value"):#这里的意思是我们得到描述goal存在内容的意思
           continue
        target_desc = goal.get("value")
        break

    #当没有没有目标描述的时候，取第一条描述就行了
    if not target_desc:
        target_desc = descriptions[0].get("value")

    #最后返还结果
    return target_desc or ""

# 🛠️ 工具四 ：cvss评分（nvd专属版）
def parse_nvd_cvss(metrics):
    if not metrics:
     return None,None

    cvss_types = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]
    #用以上的评分系统进行抓取信息，将评分系统在漏洞信息列表得出的所需数据做成一个新的列表
    for cvss_true_type in cvss_types:
        metrics_list = metrics.get(cvss_true_type,[])

        #取评分系统的第一版所需数据
        if metrics_list:
            metrics_data = metrics_list[0].get("cvssData",{})
            cvss_score = metrics_data.get("baseScore")
            cvss_version = metrics_data.get("version")
            return cvss_score,cvss_version

    return None,None

# 🛠️ 工具五：格式化时间
def format_date(raw_date):#raw_date是定义的原始数据，就是那个不太好看的日期
    if not raw_date:
        return "未知"
    if "T" in raw_date:
        return raw_date.split("T")[0]
    return str(raw_date)[:10]

# 🛠️ 工具六：储蓄卡
def save_data(all_results,csv_name="My_date.csv",db_name="My_date.db",table_name="vulnerabilities"):
    if not all_results:
        logging.info("没有数据需要保存")
        return None

    #把所有结果都做成列表，df是数据表格缩写
    df = pd.DataFrame(all_results)
    logging.info("数据已经保存为表格")

    if "cve_id" in df.columns:
        df.drop_duplicates(subset="cve_id",inplace=True)
    elif "url" in df.columns:
        df.drop_duplicates(subset="url",inplace=True)
    else:
        df.drop_duplicates(inplace=True)

    #给人看的表格
    df.to_csv(
    csv_name,
    index=False,
    encoding="utf-8-sig")#确保excel可以顺利打开,这是给人看的
    logging.info("csv文件已保存")

    #建立一个用sqlite表示的表格，给程序的看的,为了方便我理解，这里给名字设置成vulnerabilities
    conn = sqlite3.connect(db_name)
    df.to_sql(table_name,conn,if_exists="replace",index=False)
    conn.close()

    return df

#nvd_spider.py
import logging
import time
import datetime
from utils import fetch_with_retry,get_best_descriptions,parse_nvd_cvss,format_date
def fetch_nvd(_name_=None, days = 30,max_page = 4,result_per_page = 50):


    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"User-Agent":"nvd-cve-collector/1.0",
               "apikey":""}

    all_result = []
    start_index = 0
    page = 0

    #确定结束开始的时间，在datetime的箱子里找到datetime这个工具
    today = datetime.date.today()
    #利用timedelta指定一段时间
    some_days_ago = today - datetime.timedelta(days = days)
    #将初始和结束的时间确定下来,strftime目的是为了格式化爬取的时间
    pub_start_date = some_days_ago.strftime("%Y-%m-%dT00:00:00.000")
    pub_end_date = today.strftime("%Y-%m-%dT23:59:59.999")

    while True:
        logging.info(f"正在抓取{start_index//result_per_page  + 1 }页|抓取了{start_index}条bugs|截至时间为{pub_end_date}")
        params ={
                 "startIndex":start_index,
                 "resultsPerPage":result_per_page,
                 "pubStartDate":pub_start_date,
                 "pubEndDate":pub_end_date
        }
        response = fetch_with_retry(url,params=params,headers=headers,timeout=50,max_retries=3)
        if  response is None:
            logging.error(f"服务器被拒绝访问或者服务器错误，状态码：{response.status_code}")

        if response.status_code == 200:#这表示服务器访问顺利
            try:
                data = response.json()
                #将返回的数据里的所有漏洞放进bugs这个列表
                bugs = data.get("vulnerabilities",[])

                if not bugs:
                  break

                #将所有漏洞都循环一遍
                for bug in bugs:
                    bug_datas = bug.get("cve",{})#如果存在漏洞，取出第一个漏洞，并且命名为bug_bags
                    bug_name = bug_datas.get("id","")

                    #提出描述
                    descriptions = bug_datas.get("descriptions",[])
                    target_desc = get_best_descriptions(descriptions,target_lang="en")

                    metrics = bug_datas.get("metrics",[])
                    cvss_score,cvss_version = parse_nvd_cvss(metrics)

                    #调用工具箱语言格式进行调整
                    raw_date = bug_datas.get("published","")
                    complete_date = format_date(raw_date)


                    all_result.append({
                        "cve_id":bug_datas.get("id",bug_name),
                        "source":"NVD",
                        "title":"",
                        "descriptions":target_desc or "",
                        "cvss_score":cvss_score,
                        "cvss_version":cvss_version or "",
                        "pubStartDate":pub_start_date,
                        "pubEndDate":pub_end_date,
                        "publish_date":complete_date
                    })
                if len(bugs) < result_per_page or page >= max_page:
                    break
                start_index += result_per_page
                page += 1
                time.sleep(2)
                return all_result

            except ValueError as error:
                logging.error(f"无法将数据统计为Json格式:{error}")
                break

        logging.info(f"抓取完毕，一共获得{start_index}条bugs")

    if _name_ == "_main_":
      setup_logging()

      all_results = fetch_nvd (days=7,result_per_page = 50,max_page=4)

      save_data(
            all_results,
            csv_name="My_date.csv",
            db_name="My_date.db",
            table_name="vulnerabilities",
        )

















# ============================================================
# 这里是connector.py的总控中心（请不要影响其他小虫休息，他们工作很累了）
# ============================================================

#这里引进logging一下，方便我说废话
import logging
#各种程序工具应有尽有，包您满意
from utils import setup_logging,save_data

#这下是该选一些螺丝出来了.
import fetch_nvd

def run_connector():
    logging.info("程序启动，启动，启动，启动，还有这个……")
    #写日记了，怎么连程序也逃不过写工作记录啊，做个人吧！
    setup_logging()
    logging.info("开启进行基础日志的编写")

    all_data = []

    try:
        logging.info("爬虫大军全军出击")
        nvd_data = ()
        all_data = fetch_nvd(nvd_data)
        logging.info("干得不错，数据收集成功")

    except Exception as e:
        logging.error(f"爬取失败，换一家吧")