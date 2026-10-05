import logging
import sqlite3
import time

import pandas as pd
import requests


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(
                "spider_run_log.log",
                encoding="utf-8",
                mode="a",
            ),
            logging.StreamHandler(),
        ],
    )


def fetch_with_retry(
    url,
    params=None,
    headers=None,
    max_retries=3,
    timeout=50,
):
    for attempt in range(max_retries):
        try:
            response = requests.get(
                url,
                params=params,
                headers=headers,
                timeout=timeout,
            )
            response.raise_for_status()
            return response
        except requests.exceptions.Timeout:
            logging.error("请求超时，第%s次尝试", attempt + 1)
        except requests.exceptions.ConnectionError as error:
            logging.error("连接错误：%s，第%s次尝试", error, attempt + 1)
        except requests.exceptions.RequestException as error:
            logging.error("请求失败：%s，第%s次尝试", error, attempt + 1)

        if attempt < max_retries - 1:
            time.sleep(2)

    logging.error("重试后仍然请求失败")
    return None


def get_best_descriptions(descriptions, target_lang="en"):
    if not descriptions:
        return ""

    for item in descriptions:
        if item.get("lang") == target_lang and item.get("value"):
            return item["value"]

    for item in descriptions:
        if item.get("value"):
            return item["value"]

    return ""


def parse_nvd_cvss(metrics):
    if not metrics:
        return None, None

    cvss_types = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]

    for cvss_type in cvss_types:
        metric_list = metrics.get(cvss_type, [])
        if not metric_list:
            continue

        cvss_data = metric_list[0].get("cvssData") or {}
        return (
            cvss_data.get("baseScore"),
            cvss_data.get("version"),
        )

    return None, None


def format_date(raw_date):
    if not raw_date:
        return ""

    return str(raw_date).split("T", 1)[0]


def save_data(
    all_results,
    csv_name="nvd_result.csv",
    db_name="nvd_result.db",
    table_name="vulnerabilities",
):
    if not all_results:
        logging.info("没有数据需要保存")
        return None

    df = pd.DataFrame(all_results)

    if "cve_id" in df.columns and "source" in df.columns:
        df.drop_duplicates(
            subset=["cve_id", "source"],
            keep="first",
            inplace=True,
        )
    elif "cve_id" in df.columns:
        df.drop_duplicates(
            subset=["cve_id"],
            keep="first",
            inplace=True,
        )
    elif "url" in df.columns:
        df.drop_duplicates(
            subset=["url"],
            keep="first",
            inplace=True,
        )
    else:
        df.drop_duplicates(keep="first", inplace=True)

    df.to_csv(
        csv_name,
        index=False,
        encoding="utf-8-sig",
    )

    conn = sqlite3.connect(db_name)
    try:
        df.to_sql(
            table_name,
            conn,
            if_exists="replace",
            index=False,
        )
    finally:
        conn.close()

    logging.info("CSV 已保存：%s", csv_name)
    logging.info("SQLite 已保存：%s，数据表：%s", db_name, table_name)
    return df
