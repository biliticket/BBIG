import os
from bilibili_util import BilibiliClient

from loguru import logger

client = BilibiliClient()

client.session.cookies.set("SESSDATA", os.environ.get("SESSDATA",""))

if not client.session.cookies.get("SESSDATA"):
    logger.error("请设置SESSDATA环境变量")
    exit(1)

isLogin, data = client.check_login()

if isLogin:
    logger.info(f"登录成功，欢迎：{data['uname']}")
else:
    logger.error("登录失败")

resp = client.get("https://api.bilibili.com/x/vip/vip_center/sign_in/three_days_sign")
signed = resp["data"]["three_day_sign"]["signed"]
if signed:
    logger.info("已经签到过了")
else:
    logger.info("开始签到")
    resp = client.post("https://api.bilibili.com/pgc/activity/score/task/sign2", json={}, headers={"Referer": "https://big.bilibili.com/mobile/bigPoint/task"})
    if resp.get("code") == 0:
        logger.info("签到成功")
    else:
        logger.error(f"签到失败: {resp}")

resp = client.get("https://api.biliapi.com/x/vip_point/task/combine")
common = {}
try:
    for item in resp["data"]["task_info"]["modules"]:
        if item["module_title"] == "日常任务":
            common = item["common_task_item"]
            break
except Exception as e:
    logger.error(f"获取任务失败: {e}")
    exit(1)
if not common:
    logger.error("没有找到日常任务")
    exit(1)
for task in common:
    # 0 领取
    # 1 进行中
    # 3 已完成
    # 99 补领
    if task["state"] == 3:
        logger.info(f"任务 {task['title']} 已完成")
        continue
    else:
        logger.info(f"任务 {task['title']} 未完成")
    task_code = task["task_code"]
    # logger.info(f"TaskCode: {task_code} {task["title"]}")
    if task_code == "ogvwatch":
        logger.info(f"观看视频任务(旧版)，暂不支持")
    elif task_code == "ogvwatchnew":
        logger.info(f"观看视频任务暂不支持，请自行前往APP完成")
    elif task_code == "filmtab":
        logger.info(f"开始提交任务")
        resp = client.post("https://api.bilibili.com/pgc/activity/deliver/task/complete", data={"win_id": "bigscore-filmtab","position":"tv_channel"}, headers={"Referer": "https://big.bilibili.com/mobile/bigPoint/task"})
        logger.info(f"提交结果: {resp}")
    elif task_code == "filmtab":
        logger.info(f"开始提交任务")
        resp = client.post("https://api.bilibili.com/pgc/activity/deliver/task/complete", data={"win_id": "bigscore-animatetab","position":"jp_channel"}, headers={"Referer": "https://big.bilibili.com/mobile/bigPoint/task"})
        logger.info(f"提交结果: {resp}")
    elif task_code == "tvodbuy":
        if task["state"] == 1:
            logger.info(f"已完成领取，跳过该任务")
            continue
        logger.info(f"购买视频，将领取任务")
        resp = client.post("https://api.bilibili.com/pgc/activity/score/task/receive/v2", data={"taskCode":"tvodbuy"}, headers={"Referer": "https://big.bilibili.com/mobile/bigPoint/task"})
        logger.info(f"提交结果: {resp}")
    elif task_code == "offlinetask":
        logger.info(f"线下任务，将跳过该任务")
    elif task_code == "vipmallbuy":
        if task["state"] == 1:
            logger.info(f"已完成领取，跳过该任务")
            continue
        logger.info(f"会员购购买，将领取任务")
        resp = client.post("https://api.bilibili.com/pgc/activity/score/task/receive/v2", data={"taskCode":"vipmallbuy"}, headers={"Referer": "https://big.bilibili.com/mobile/bigPoint/task"})
        logger.info(f"提交结果: {resp}")
    elif task_code == "dressbuyamount":
        if task["state"] == 1:
            logger.info(f"已完成领取，跳过该任务")
            continue
        logger.info(f"购买装扮，将领取任务")
        resp = client.post("https://api.bilibili.com/pgc/activity/score/task/receive/v2", data={"taskCode":"dressbuyamount"}, headers={"Referer": "https://big.bilibili.com/mobile/bigPoint/task"})
        logger.info(f"提交结果: {resp}")
    elif task_code == "vipmallview":
        logger.info(f"开始提交任务")
        eventId = task["link"].split("eventId=")[-1].split("&")[0]
        logger.info(f"EventId: {eventId}")
        resp = client.post("https://show.bilibili.com/api/activity/fire/common/event/dispatch", json={"eventId":eventId})
        logger.info(f"提交结果: {resp}")
    elif task_code == "dress-view":
        logger.info(f"开始提交任务")
        resp = client.post("https://api.bilibili.com/pgc/activity/score/task/complete/v2", data={"taskCode":"dress-view"}, headers={"Referer": "https://big.bilibili.com/mobile/bigPoint/task"})
        logger.info(f"提交结果: {resp}")
    elif task_code == "subscribe":
        if task["state"] == 1:
            logger.info(f"已完成领取，跳过该任务")
            continue
        logger.info(f"会员购开通，将领取任务")
        resp = client.post("https://api.bilibili.com/pgc/activity/score/task/receive/v2", data={"taskCode":"subscribe"}, headers={"Referer": "https://big.bilibili.com/mobile/bigPoint/task"})
        logger.info(f"提交结果: {resp}")
    elif task_code == "getrights":
        logger.info(f"未知任务，未完成")
    elif task_code == "dress-up":
        if task["state"] == 1:
            logger.info(f"已完成领取，跳过该任务")
            continue
        logger.info(f"装扮试用，将领取任务")
        resp = client.post("https://api.bilibili.com/pgc/activity/score/task/receive/v2", data={"taskCode":"dress-up"}, headers={"Referer": "https://big.bilibili.com/mobile/bigPoint/task"})
        logger.info(f"提交结果: {resp}")
    elif task_code == "dress-buy":
        if task["state"] == 1:
            logger.info(f"已完成领取，跳过该任务")
            continue
        logger.info(f"装扮购买，将领取任务")
        resp = client.post("https://api.bilibili.com/pgc/activity/score/task/receive/v2", data={"taskCode":"dress-buy"}, headers={"Referer": "https://big.bilibili.com/mobile/bigPoint/task"})
        logger.info(f"提交结果: {resp}")
    else:
        logger.warning(f"未知任务 {task['title']} {task_code}")
        continue
