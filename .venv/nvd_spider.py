
import pandas as pd
import sqlite3



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
from utils import setup_logging,fetch_with_retry,get_best_descriptions,parse_nvd_cvss,format_date,save_data
def fetch_nvd(_name_, days:int = 30,max_page:int = 4,result_per_page:int = 50):

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

      all_results = fetch_nvd(
        days=7,
        result_per_page=50,
        max_page=4,
    )

      save_data(
            all_results,
            csv_name="My_date.csv",
            db_name="My_date.db",
            table_name="vulnerabilities",
      )
