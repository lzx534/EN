import logging

from nvd_spider import fetch_nvd
from utils import save_data, setup_logging


def run_connector():
    setup_logging()
    logging.info("程序启动")

    try:
        all_data = fetch_nvd(
            days=7,
            max_page=4,
            result_per_page=50,
        )

        if not all_data:
            logging.info("本次没有抓取到数据")
            return

        save_data(
            all_results=all_data,
            csv_name="nvd_result.csv",
            db_name="nvd_result.db",
            table_name="vulnerabilities",
        )

        logging.info("数据保存成功，共%s条", len(all_data))
    except Exception:
        logging.exception("爬取或保存失败")


if __name__ == "__main__":
    run_connector()
