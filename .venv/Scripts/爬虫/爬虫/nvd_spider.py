import datetime
import logging
import time

from utils import (
    fetch_with_retry,
    format_date,
    get_best_descriptions,
    parse_nvd_cvss,
)


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_nvd(days=30, max_page=4, result_per_page=50):
    headers = {
        "User-Agent": "nvd-cve-collector/1.0",
    }

    all_results = []
    start_index = 0
    page = 1

    today = datetime.date.today()
    start_day = today - datetime.timedelta(days=days)

    pub_start_date = start_day.strftime("%Y-%m-%dT00:00:00.000")
    pub_end_date = today.strftime("%Y-%m-%dT23:59:59.999")

    while page <= max_page:
        logging.info(
            "正在抓取第%s页，当前偏移量为%s",
            page,
            start_index,
        )

        params = {
            "startIndex": start_index,
            "resultsPerPage": result_per_page,
            "pubStartDate": pub_start_date,
            "pubEndDate": pub_end_date,
        }

        response = fetch_with_retry(
            url=NVD_URL,
            params=params,
            headers=headers,
            max_retries=3,
            timeout=50,
        )

        if response is None:
            logging.error("没有获得 NVD 响应，停止抓取")
            break

        try:
            data = response.json()
        except ValueError as error:
            logging.error("NVD 返回内容不是合法 JSON：%s", error)
            break

        vulnerabilities = data.get("vulnerabilities") or []

        if not vulnerabilities:
            logging.info("没有更多漏洞数据，停止抓取")
            break

        for item in vulnerabilities:
            cve_data = item.get("cve") or {}
            cve_id = cve_data.get("id", "")

            description = get_best_descriptions(
                cve_data.get("descriptions") or [],
                target_lang="en",
            )

            cvss_score, cvss_version = parse_nvd_cvss(
                cve_data.get("metrics") or {}
            )

            all_results.append(
                {
                    "cve_id": cve_id,
                    "source": "NVD",
                    "title": "",
                    "description": description,
                    "cvss_score": cvss_score,
                    "cvss_version": cvss_version or "",
                    "published_at": format_date(
                        cve_data.get("published")
                    ),
                    "last_modified_at": format_date(
                        cve_data.get("lastModified")
                    ),
                    "source_url": (
                        f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                        if cve_id
                        else ""
                    ),
                }
            )

        if len(vulnerabilities) < result_per_page:
            logging.info("当前页数量不足，已到最后一页")
            break

        start_index += result_per_page
        page += 1
        time.sleep(2)

    logging.info("NVD 抓取完成，共获得%s条数据", len(all_results))
    return all_results
