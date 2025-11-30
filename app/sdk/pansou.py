import re

import requests

from sdk.common import iso_to_cst


class PanSou:
    """
    PanSou 类，用于获取云盘资源
    """

    def __init__(self, server):
        self.server = server
        self.session = requests.Session()

    def search(self, keyword: str, refresh: bool = False, channels: str = None, plugins: str = None) -> list:
        """搜索资源

        Args:
            keyword (str): 搜索关键字
            refresh (bool): 是否刷新缓存
            channels (str): 频道列表, 逗号分隔
            plugins (str): 插件列表, 逗号分隔

        Returns:
            list: 资源列表
        """
        try:
            url = f"{self.server.rstrip('/')}/api/search"
            # if not channels:
            #     channels = "tgsearchers3,Aliyun_4K_Movies,bdbdndn11,yunpanx,bsbdbfjfjff,yp123pan,sbsbsnsqq,yunpanxunlei,tianyifc,BaiduCloudDisk,txtyzy,peccxinpd,gotopan,PanjClub,kkxlzy,baicaoZY,MCPH01,bdwpzhpd,ysxb48,jdjdn1111,yggpan,MCPH086,zaihuayun,Q66Share,ucwpzy,shareAliyun,alyp_1,dianyingshare,Quark_Movies,XiangxiuNBB,ydypzyfx,ucquark,xx123pan,yingshifenxiang123,zyfb123,tyypzhpd,tianyirigeng,cloudtianyi,hdhhd21,Lsp115,oneonefivewpfx,qixingzhenren,taoxgzy,Channel_Shares_115,tyysypzypd,vip115hot,wp123zy,yunpan139,yunpan189,yunpanuc,yydf_hzl,leoziyuan,pikpakpan,Q_dongman,yoyokuakeduanju,TG654TG,WFYSFX02,QukanMovie,yeqingjie_GJG666,movielover8888_film3,Baidu_netdisk,D_wusun,FLMdongtianfudi,KaiPanshare,QQZYDAPP,rjyxfx,PikPak_Share_Channel,btzhi,newproductsourcing,cctv1211,duan_ju,QuarkFree,yunpanNB,kkdj001,xxzlzn,pxyunpanxunlei,jxwpzy,kuakedongman,liangxingzhinan,xiangnikanj,solidsexydoll,guoman4K,zdqxm,kduanju,cilidianying,CBduanju,SharePanFilms,dzsgx,BooksRealm,Oscar_4Kmovies"
            # if not plugins:
            #     plugins = "ddys,erxiao,hdr4k,jutoushe,labi,libvio,panta,susu,wanou,xuexizhinan,zhizhen,ahhhhfs,ash,clxiong,discourse,djgou,duoduo,hdmoli,huban,leijing,muou,nsgame,ouge,panyq,shandian,xinjuc,yunsou,aikanzy,bixin,cldi,clmao,cyg,fox4k,gying,haisou,hunhepan,jikepan,miaoso,nyaa,pan666,pansearch,panwiki,pianku,quark4k,quarksoo,qupanshe,qupansou,sdso,sousou,thepiratebay,wuji,xb6v,xdpan,xdyh,xiaoji,xiaozhang,xys,yuhuage,javdb,u3c3"

            params = {
                "kw": keyword,
                "cloud_types": ["quark"],
                "res": "merge",
                "refresh": refresh,
                "src": "all",
                "channels": channels,
                "plugins": plugins
            }
            response = self.session.get(url, params=params, timeout=20)
            result = response.json()
            if result.get("code") == 0:
                data = result.get("data", {}).get("merged_by_type", {}).get("quark", [])
                return self.format_search_results(data)
            return []
        except Exception as e:
            print(f"PanSou search error: {e}")
            return []

    def format_search_results(self, search_results: list) -> list:
        """格式化搜索结果

        Args:
            search_results (list): 搜索结果列表

        Returns:
            list: 夸克网盘资源列表
        """
        pattern = (
            r'^(.*?)'
            r'(?:'
            r'[【\[]?'
            r'(?:简介|介绍|描述)'
            r'[】\]]?'
            r'[:：]?'
            r')'
            r'(.*)$'
        )
        format_results = []
        link_array = []
        for item in search_results:
            url = item.get("url", "")
            note = item.get("note", "")
            tm = item.get("datetime", "")
            if tm:
                tm = iso_to_cst(tm)

            match = re.search(pattern, note)
            if match:
                title = match.group(1)
                content = match.group(2)
            else:
                title = note
                content = ""

            if url != "" and url not in link_array:
                link_array.append(url)
                format_results.append({
                    "shareurl": url,
                    "taskname": title,
                    "content": content,
                    "datetime": tm,
                    "channel": item.get("source", ""),
                    "source": "PanSou"
                })

        return format_results


if __name__ == "__main__":
    server: str = "https://so.252035.xyz"
    pansou = PanSou(server)
    results = pansou.search("哪吒")
    for item in results:
        print(f"标题: {item['taskname']}")
        print(f"描述: {item['content']}")
        print(f"链接: {item['shareurl']}")
        print(f"时间: {item['datetime']}")
        print("-" * 50)
