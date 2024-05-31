from datetime import datetime, timedelta
from threading import Event
from typing import Any, Dict, List, Tuple

# from fastapi import Depends
# from sqlalchemy.orm import Session

import pytz
import requests
# from app import schemas
from app.core.config import settings
from app.helper.sites import SitesHelper
from app.log import logger
from app.plugins import _PluginBase
from app.utils.http import RequestUtils
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from app.db.site_oper import SiteOper
from app.utils.string import StringUtils
from app.db.models.site import Site
from app.db.sitestatistic_oper import SiteStatisticOper
from app.helper.browser import PlaywrightHelper
from app.utils.site import SiteUtils
from app.helper.cloudflare import under_challenge
from app.core.event import eventmanager, Event, EventManager
from app.schemas.types import EventType

# from app.db import get_db
# from app.db.models.site import Site
# from app.utils.string import StringUtils

# from app.schemas.types import EventType
# from app.core.event import EventManager
from .utils import check_response_is_valid_json


class Jackett(_PluginBase):
    # 插件名称
    plugin_name = "Jackett 索引器"
    # 插件描述
    plugin_desc = "支持检索 Jackett 站点资源"
    # 插件图标
    plugin_icon = "https://raw.githubusercontent.com/junyuyuan/MoviePilot-Plugins/main/icons/jackett.png"
    # 主题色
    plugin_color = "#000000"
    # 插件版本
    plugin_version = "0.0.15"
    # 插件作者
    plugin_author = "Junyuyuan"
    # 作者主页
    author_url = "https://github.com/junyuyuan"
    # 插件配置项ID前缀
    plugin_config_prefix = "jackett_"
    # 加载顺序
    plugin_order = 1
    # 可使用的用户级别
    auth_level = 1

    # 私有属性
    _event = Event()
    _sites_helper = SitesHelper()
    _scheduler = None
    _enabled = False
    _host = ""
    _api_key = ""
    _password = ""
    _cron = None
    _run_once = False
    _sites = None

    def init_plugin(self, config: dict | None = None):
        if config:
            self._enabled = bool(config.get("enabled"))
            self._api_key = str(config.get("api_key"))
            self._host = str(config.get("host"))
            if not self._host.startswith("http"):
                self._host = "http://" + self._host
            if self._host.endswith("/"):
                self._host = self._host.rstrip("/")
            self._password = str(config.get("password"))
            self._cron = str(config.get("cron"))
            self._run_once = bool(config.get("run_once"))
            self.siteoper = SiteOper()
            self.sitestatistic = SiteStatisticOper()

        if self._enabled:
            logger.info("Jackett 插件初始化完成")
            # logger.info("打印站点列表")
            # logger.info(self.siteoper.list())

            if self._run_once:
                self._scheduler = BackgroundScheduler(timezone=settings.TZ)

                if self._cron:
                    logger.info(f"索引更新服务启动，周期：{self._cron}")
                    self._scheduler.add_job(
                        self.get_status, CronTrigger.from_crontab(self._cron)
                    )

                if self._run_once:
                    logger.info("开始获取索引器状态")
                    self._scheduler.add_job(
                        self.get_status,
                        "date",
                        run_date=datetime.now(tz=pytz.timezone(settings.TZ))
                        + timedelta(seconds=3),
                    )
                    # 关闭一次性开关
                    self._run_once = False
                    self._update_config()

                if self._cron or self._run_once:
                    # 启动服务
                    self._scheduler.print_jobs()
                    self._scheduler.start()

    def _update_config(self):
        self.update_config(
            {
                "enabled": self._enabled,
                "host": self._host,
                "api_key": self._api_key,
                "password": self._password,
                "cron": self._cron,
                "run_once": self._run_once,
            }
        )

    def test(self, url: str) -> Tuple[bool, str]:
        """
        测试站点是否可用
        :param url: 站点域名
        :return: (是否可用, 错误信息)
        """
        # 检查域名是否可用
        domain = StringUtils.get_url_domain(url)
        site_info = self.siteoper.get_by_domain(domain)
        if not site_info:
            return False, f"站点【{url}】不存在"

        # 模拟登录
        try:
            # 开始记时
            start_time = datetime.now()
            # 通用站点测试
            state, message = self.__test(site_info)
            # 统计
            seconds = (datetime.now() - start_time).seconds
            if state:
                self.sitestatistic.success(domain=domain, seconds=seconds)
            else:
                self.sitestatistic.fail(domain)
            return state, message
        except Exception as e:
            return False, f"{str(e)}！"
        
        
    @staticmethod
    def __test(site_info: Site) -> Tuple[bool, str]:
        """
        通用站点测试
        """
        site_url = site_info.url
        site_cookie = site_info.cookie
        ua = site_info.ua or settings.USER_AGENT
        render = site_info.render
        public = site_info.public
        proxies = settings.PROXY if site_info.proxy else None
        proxy_server = settings.PROXY_SERVER if site_info.proxy else None

        # 访问链接
        if render:
            page_source = PlaywrightHelper().get_page_source(url=site_url,
                                                             cookies=site_cookie,
                                                             ua=ua,
                                                             proxies=proxy_server)
            if not public and not SiteUtils.is_logged_in(page_source):
                if under_challenge(page_source):
                    return False, f"无法通过Cloudflare！"
                return False, f"仿真登录失败，Cookie已失效！"
        else:
            res = RequestUtils(cookies=site_cookie,
                               ua=ua,
                               proxies=proxies
                               ).get_res(url=site_url)
            # 判断登录状态
            if res and res.status_code in [200, 500, 403]:
                if not public and not SiteUtils.is_logged_in(res.text):
                    if under_challenge(res.text):
                        msg = "站点被Cloudflare防护，请打开站点浏览器仿真"
                    elif res.status_code == 200:
                        msg = "Cookie已失效"
                    else:
                        msg = f"状态码：{res.status_code}"
                    return False, f"{msg}！"
                elif public and res.status_code != 200:
                    return False, f"状态码：{res.status_code}！"
            elif res is not None:
                return False, f"状态码：{res.status_code}！"
            else:
                return False, f"无法打开网站！"
        return True, "连接成功"
        
    def get_status(self):
        """
        检查连通性
        :return: True、False
        """

        if not self._api_key or not self._host:
            return False
        self._sites = self.get_indexers()
        for site in self._sites:
            logger.info(site["site_link"], site)
            if not site["site_link"] or site["site_link"] == "":
                continue
            domain = site["site_link"].split('//')[-1].split('/')[0]
            # domain = site["domain"].split('//')[-1]
            logger.info((domain, site))
            self._sites_helper.add_indexer(domain, site)
            indexer = self._sites_helper.get_indexer(domain)
            site_info = self.siteoper.get_by_domain(domain)
            if site_info:
                # 站点已存在，检查站点连通性
                status, msg = self.test(domain)
            elif indexer:
                self.siteoper.add(name=indexer.get("name"),
                                  url=site["site_link"],
                                  domain=site["domain"],
                                  cookie="",
                                  rss=site["domain"] + f"api?apikey={self._api_key}&t=search&q={{keyword}}",
                                  public=1 if indexer.get("public") else 0)
            if indexer:
                EventManager().send_event(EventType.SiteUpdated, {
                    "domain": domain,
                })


        return True if isinstance(self._sites, list) and len(self._sites) > 0 else False

    def get_indexers(self):
        """
        获取配置的jackett indexer
        :return: indexer 信息 [(indexerId, indexerName, url)]
        """
        # 获取Cookie
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "User-Agent": settings.USER_AGENT,
            "X-Api-Key": self._api_key,
            "Accept": "application/json, text/javascript, */*; q=0.01",
        }
        cookie = None
        session = requests.session()
        res = RequestUtils(headers=headers, session=session).post_res(
            url=f"{self._host}/UI/Dashboard",
            data={"password": self._password},
            params={"password": self._password},
        )
        if res and session.cookies:
            cookie = session.cookies.get_dict()
        indexer_query_url = f"{self._host}/api/v2.0/indexers?configured=true"
        try:
            ret = RequestUtils(headers=headers, cookies=cookie).get_res(
                indexer_query_url
            )
            if not ret:
                return []
            if not check_response_is_valid_json(ret):
                logger.error("参数设置不正确，请检查所有的参数是否填写正确")
                return []
            if not ret.json():
                return []
            indexers = [
                # IndexerConf(
                {
                    "id": f'{v["id"]}-jackett',
                    "name": f'{v["name"]} (Jackett)',
                    "site_link": f'{v["site_link"]}',
                    "domain": f'{self._host}/api/v2.0/indexers/{v["id"]}/results/torznab/',
                    "public": True if v["type"] == "public" else False,
                    "proxy": True,
                    "result_num": 100,
                    "timeout": 30,
                    "search": {
                        "paths": [
                            {
                                "path": "",
                                "method": "get",
                            }
                        ]
                    },
                    "torrents": {
                        "list": {"selector": "item"},
                        "fields": {
                            "id": {
                                "selector": "link",
                            },
                            "title": {"selector": "title"},
                            "details": {
                                "selector": "comments",
                            },
                            # "download": {
                            #     "selector": 'td:nth-child(3) > a[href*="/download/"]',
                            #     "attribute": "href",
                            # },
                            # "date_added": {"selector": "td:nth-child(5)"},
                            "size": {"selector": "size"},
                            "seeders": {
                                "selector": 'torznab:attr[name="seeders"]',
                                "attribute": "value",
                            },
                            # "leechers": {"selector": "td:nth-child(7)"},
                            # "grabs": {"selector": "td:nth-child(8)"},
                            "downloadvolumefactor": {"case": {"*": 0}},
                            "uploadvolumefactor": {"case": {"*": 1}},
                        },
                    },
                }
                # )
                for v in ret.json()
            ]
            return indexers
        except Exception as e:
            logger.error(f"获取索引器失败：{str(e)}")
            return []

    def get_fake_site(self):
        pass

    def get_state(self) -> bool:
        return self._enabled

    @staticmethod
    def get_command() -> List[Dict[str, Any]] | None:
        pass

    def get_api(self) -> List[Dict[str, Any]] | None:
        # return [
        #     {
        #         "path": "/jackett_fake_site",
        #         "endpoint": self.get_fake_site,
        #         "methods": ["GET"],
        #         "summary": "Jackett 虚假站点",
        #         "description": "Jackett 虚假站点",
        #     }
        # ]
        pass

    def get_service(self) -> List[Dict[str, Any]] | None:
        if self._enabled and self._cron:
            return [
                {
                    "id": "Jaclett",
                    "name": "Jackett 索引更新服务",
                    "trigger": CronTrigger.from_crontab(self._cron),
                    "func": self.get_status,
                    "kwargs": {},
                }
            ]

    # 插件配置页面
    def get_form(self) -> Tuple[List[dict], Dict[str, Any]]:
        """
        拼装插件配置页面，需要返回两块数据：1、页面配置；2、数据结构
        """
        return (
            [
                {
                    "component": "VForm",
                    "content": [
                        {
                            "component": "VRow",
                            "content": [
                                {
                                    "component": "VCol",
                                    "content": [
                                        {
                                            "component": "VSwitch",
                                            "props": {
                                                "model": "enabled",
                                                "label": "启用插件",
                                            },
                                        }
                                    ],
                                },
                            ],
                        },
                        {
                            "component": "VRow",
                            "content": [
                                {
                                    "component": "VCol",
                                    "props": {"cols": 12, "md": 6},
                                    "content": [
                                        {
                                            "component": "VTextField",
                                            "props": {
                                                "model": "host",
                                                "label": "Jackett 地址",
                                                "placeholder": "http://127.0.0.1:9117",
                                            },
                                        }
                                    ],
                                },
                                {
                                    "component": "VCol",
                                    "props": {"cols": 12, "md": 6},
                                    "content": [
                                        {
                                            "component": "VTextField",
                                            "props": {
                                                "model": "api_key",
                                                "label": "Jackett API Key",
                                                "placeholder": "",
                                            },
                                        }
                                    ],
                                },
                            ],
                        },
                        {
                            "component": "VRow",
                            "content": [
                                {
                                    "component": "VCol",
                                    "content": [
                                        {
                                            "component": "VTextField",
                                            "props": {
                                                "model": "password",
                                                "type": "password",
                                                "label": "Jackett 密码",
                                                "placeholder": "password",
                                            },
                                        }
                                    ],
                                },
                            ],
                        },
                        {
                            "component": "VRow",
                            "content": [
                                {
                                    "component": "VCol",
                                    "content": [
                                        {
                                            "component": "VTextField",
                                            "props": {
                                                "model": "cron",
                                                "label": "Cron",
                                                "placeholder": "0 0 */24 * *",
                                            },
                                        }
                                    ],
                                },
                            ],
                        },
                        {
                            "component": "VRow",
                            "content": [
                                {
                                    "component": "VCol",
                                    "content": [
                                        {
                                            "component": "VSwitch",
                                            "props": {
                                                "model": "run_once",
                                                "label": "立即运行一次",
                                            },
                                        }
                                    ],
                                },
                            ],
                        },
                    ],
                }
            ],
            {
                "enabled": False,
                "host": "",
                "api_key": "",
                "password": "",
                "cron": "0 0 */24 * *",
                "run_once": False,
            },
        )

    def get_page(self) -> List[dict] | None:
        pass

    def stop_service(self):
        """
        退出插件
        """
        try:
            if self._scheduler:
                self._scheduler.remove_all_jobs()
                if self._scheduler.running:
                    self._event.set()
                    self._scheduler.shutdown()
                    self._event.clear()
                self._scheduler = None
        except Exception as e:
            logger.error(f"停止插件错误: {str(e)}")