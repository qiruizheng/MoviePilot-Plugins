from datetime import datetime, timedelta
from threading import Event
from typing import Any, Dict, List, Tuple

import pytz
import requests
from app.core.config import settings
from app.helper.sites import SitesHelper
from app.log import logger
from app.plugins import _PluginBase
from app.utils.http import RequestUtils
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from app.db.site_oper import SiteOper

from .utils import check_response_is_valid_json


class Jackett(_PluginBase):
    # 插件名称
    plugin_name = "Jackett 聚合"
    # 插件描述
    plugin_desc = "Jackett 聚合索引器，插件开发中"
    # 插件图标
    plugin_icon = "https://raw.githubusercontent.com/junyuyuan/MoviePilot-Plugins/main/icons/jackett.png"
    # 主题色
    plugin_color = "#000000"
    # 插件版本
    plugin_version = "0.2.4"
    # 插件作者
    plugin_author = "Junyuyuan,Ray"
    # 作者主页
    author_url = "https://github.com/junyuyuan"
    # 插件配置项ID前缀
    plugin_config_prefix = "jackett_"
    # 加载顺序
    plugin_order = 1
    # 可使用的用户级别
    auth_level = 2

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
    _siteoper = SiteOper()

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

        if self._enabled:
            logger.info("Jackett 插件初始化完成")
            # 启动时立即运行一次
            self._run_once = True
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

    def get_status(self):
        """
        检查连通性
        :return: True、False
        """
        if not self._api_key or not self._host:
            return False
        self._sites = self.get_indexers()
        for site in self._sites:
            domain = site["domain"].split("//")[-1].split("/")[0]
            logger.info((domain, site))
            self._sites_helper.add_indexer(domain, site)
            self._siteoper.add(name=site.get("name"),
                               url=site["domain"],
                               domain=domain,
                               cookie="",
                               rss="",
                               public=1 if site.get("public") else 0,
                               render=True),
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
                    "id": f'jackett',
                    "name": f'Jackett 聚合',
                    "domain": f'{self._host}/',
                    "public": True,
                    "proxy": True,
                    "result_num": 100,
                    "timeout": 60,
                    "search": {
                        "paths": [
                            {
                                "path": f"api/v2.0/indexers/all/results/torznab/api?apikey={self._api_key}&t=search&q={{keyword}}",
                                "method": "get",
                            }
                        ]
                    },
                    "torrents": {
                        "list": {"selector": "channel > item"},
                        "fields": {
                            "id": {
                                "selector": "jackettindexer",
                                "attribute": "id",
                            },
                            "title": {"selector": "title"},
                            "details": {
                                "selector": "comments",
                            },
                            "download": {
                                "selector": "enclosure",
                                "attribute": "url",
                            },
                            "size": {"selector": "size"},
                            "seeders": {
                                "selector": 'torznab:attr[name="seeders"]',
                                "attribute": "value",
                            },
                            "downloadvolumefactor": {
                                "selector": 'torznab:attr[name="downloadvolumefactor"]',
                                "attribute": "value",
                            },
                            "uploadvolumefactor": {
                                "selector": 'torznab:attr[name="uploadvolumefactor"]',
                                "attribute": "value",
                            },
                        },
                    },
                }
                # )
                # for v in ret.json()
            ]
            return indexers
        except Exception as e:
            logger.error(f"获取索引器失败：{str(e)}")
            return []
            
    def search(self, indexer,
               keyword,
               page):
        """
        根据关键字多线程检索
        """
        if not indexer or not keyword:
            return None
        self.info(f"【{self.plugin_name}】开始检索Indexer：{indexer.name} ...")
        # 特殊符号处理
        api_url = f"{indexer.domain}?apikey={self._api_key}&t=search&q={keyword}"

        result_array = self.__parse_torznabxml(api_url)

        if len(result_array) == 0:
            self.warn(f"【{self.plugin_name}】{indexer.name} 未检索到数据")
            # self.progress.update(ptype='search', text=f"{indexer.name} 未检索到数据")
            return []
        else:
            self.warn(f"【{self.plugin_name}】{indexer.name} 返回数据：{len(result_array)}")
            return result_array

    
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
        
  @staticmethod
    def __parse_torznabxml(url):
        """
        从torznab xml中解析种子信息
        :param url: URL地址
        :return: 解析出来的种子信息列表
        """
        if not url:
            return []
        try:
            ret = RequestUtils(timeout=10).get_res(url)
        except Exception as e2:
            ExceptionUtils.exception_traceback(e2)
            return []
        if not ret:
            return []
        xmls = ret.text
        if not xmls:
            return []

        torrents = []
        try:
            # 解析XML
            dom_tree = xml.dom.minidom.parseString(xmls)
            root_node = dom_tree.documentElement
            items = root_node.getElementsByTagName("item")
            for item in items:
                try:
                    # indexer id
                    indexer_id = DomUtils.tag_value(item, "jackettindexer", "id",
                                                    default=DomUtils.tag_value(item, "prowlarrindexer", "id", ""))
                    # indexer
                    indexer = DomUtils.tag_value(item, "jackettindexer",
                                                 default=DomUtils.tag_value(item, "prowlarrindexer", default=""))

                    # 标题
                    title = DomUtils.tag_value(item, "title", default="")
                    if not title:
                        continue
                    # 种子链接
                    enclosure = DomUtils.tag_value(item, "enclosure", "url", default="")
                    if not enclosure:
                        continue
                    # 描述
                    description = DomUtils.tag_value(item, "description", default="")
                    # 种子大小
                    size = DomUtils.tag_value(item, "size", default=0)
                    # 种子页面
                    page_url = DomUtils.tag_value(item, "comments", default="")

                    # 做种数
                    seeders = 0
                    # 下载数
                    peers = 0
                    # 是否免费
                    freeleech = False
                    # 下载因子
                    downloadvolumefactor = 1.0
                    # 上传因子
                    uploadvolumefactor = 1.0
                    # imdbid
                    imdbid = ""

                    torznab_attrs = item.getElementsByTagName("torznab:attr")
                    for torznab_attr in torznab_attrs:
                        name = torznab_attr.getAttribute('name')
                        value = torznab_attr.getAttribute('value')
                        if name == "seeders":
                            seeders = value
                        if name == "peers":
                            peers = value
                        if name == "downloadvolumefactor":
                            downloadvolumefactor = value
                            if float(downloadvolumefactor) == 0:
                                freeleech = True
                        if name == "uploadvolumefactor":
                            uploadvolumefactor = value
                        if name == "imdbid":
                            imdbid = value

                    tmp_dict = {'indexer_id': indexer_id,
                                'indexer': indexer,
                                'title': title,
                                'enclosure': enclosure,
                                'description': description,
                                'size': size,
                                'seeders': seeders,
                                'peers': peers,
                                'freeleech': freeleech,
                                'downloadvolumefactor': downloadvolumefactor,
                                'uploadvolumefactor': uploadvolumefactor,
                                'page_url': page_url,
                                'imdbid': imdbid}
                    torrents.append(tmp_dict)
                except Exception as e:
                    ExceptionUtils.exception_traceback(e)
                    continue
        except Exception as e2:
            ExceptionUtils.exception_traceback(e2)
            pass

        return torrents
        
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
            
