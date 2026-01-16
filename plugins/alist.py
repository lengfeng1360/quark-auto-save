import os
import re
import json
import requests
import time


class Alist:

    default_config = {
        "url": "",  # Alist服务器URL
        "token": "",  # Alist服务器Token
        "storage_id": "",  # Alist 服务器夸克存储 ID
    }
    is_active = False
    # 缓存参数
    storage_mount_path = None
    quark_root_dir = None
    numeric_storage_id = None  # 存储的数字ID，用于 disable/enable 操作
    _refreshing = False  # 并发控制标志：是否正在刷新挂载
    _executor = None  # 后台线程池执行器
    _skip_token_check = False  # 内部验证时跳过 Token 检测（防止循环）

    def __init__(self, **kwargs):
        if kwargs:
            for key, _ in self.default_config.items():
                if key in kwargs:
                    setattr(self, key, kwargs[key])
                else:
                    print(f"{self.__class__.__name__} 模块缺少必要参数: {key}")
            if self.url and self.token:
                self._do_initialize()

    def _do_initialize(self, skip_check=False):
        """
        封装的初始化逻辑，避免代码重复
        Args:
            skip_check: 是否跳过 Token 检测（内部验证时为 True，防止循环）
        Returns:
            bool: 初始化是否成功
        """
        # 临时设置 skip_check 标志
        if skip_check:
            self._skip_token_check = True
        
        try:
            if self.get_info():
                success, result = self.storage_id_to_path(self.storage_id)
                if success:
                    self.storage_mount_path, self.quark_root_dir = result
                    self.is_active = True
                    if not skip_check:
                        print(f"Alist 初始化成功")
                    return True
            if not skip_check:
                self.is_active = False
            return False
        finally:
            # 恢复 skip_check 标志
            if skip_check:
                self._skip_token_check = False

    def set_executor(self, executor):
        """设置后台线程池执行器"""
        self._executor = executor

    def _get_numeric_storage_id(self):
        """
        获取有效的数字存储ID
        优先使用 numeric_storage_id，如果没有则使用 storage_id
        Returns:
            str: 数字存储ID，如果无效返回 None
        """
        storage_id_to_use = self.numeric_storage_id if self.numeric_storage_id else self.storage_id
        if not re.match(r"^\d+$", storage_id_to_use):
            return None
        return storage_id_to_use

    def run(self, task, **kwargs):
        if task.get("savepath") and task.get("savepath").startswith(
            self.quark_root_dir
        ):
            alist_path = os.path.normpath(
                os.path.join(
                    self.storage_mount_path,
                    task["savepath"].replace(self.quark_root_dir, "", 1).lstrip("/"),
                )
            ).replace("\\", "/")
            self.refresh(alist_path)

    def get_info(self):
        url = f"{self.url}/api/admin/setting/list"
        headers = {"Authorization": self.token}
        querystring = {"group": "1"}
        try:
            response = requests.request("GET", url, headers=headers, params=querystring)
            response.raise_for_status()
            response = response.json()
            if response.get("code") == 200:
                print(
                    f"Alist刷新: {response.get('data',[])[1].get('value','')} {response.get('data',[])[0].get('value','')}"
                )
                return True
            else:
                self._check_token_error(response.get("message", ""))
                print(f"Alist刷新: 连接失败❌ {response.get('message')}")
        except requests.exceptions.RequestException as e:
            print(f"获取Alist信息出错: {e}")
        return False

    def storage_id_to_path(self, storage_id):
        storage_mount_path, quark_root_dir = None, None
        # 1. 检查是否符合 /aaa:/bbb 格式
        if match := re.match(r"^(\/[^:]*):(\/[^:]*)$", storage_id):
            # 存储挂载路径, 夸克根文件夹
            storage_mount_path, quark_root_dir = match.group(1), match.group(2)
            # 优先获取数字存储ID（不依赖文件列表，使用 /api/admin/storage/list）
            # 这样即使 Token 无效导致 get_file_list() 失败，numeric_storage_id 也能被正确设置
            self.numeric_storage_id = self.get_storage_id_by_mount_path(storage_mount_path)
            # 尝试验证挂载路径（可能失败，但不影响 numeric_storage_id）
            file_list = self.get_file_list(storage_mount_path)
            if file_list.get("code") != 200:
                self._check_token_error(file_list.get("message", ""))
                print(f"Alist刷新: 获取挂载路径失败❌ {file_list.get('message')}")
                # 即使失败也继续返回 False，numeric_storage_id 已在上一步设置
                return False, (None, None)
        # 2. 检查是否数字，调用 Alist API 获取存储信息
        elif re.match(r"^\d+$", storage_id):
            self.numeric_storage_id = storage_id
            if storage_info := self.get_storage_info(storage_id):
                if storage_info["driver"] == "Quark":
                    addition = json.loads(storage_info["addition"])
                    # 存储挂载路径
                    storage_mount_path = storage_info["mount_path"]
                    # 夸克根文件夹
                    quark_root_dir = self.get_root_folder_full_path(
                        addition["cookie"], addition["root_folder_id"]
                    )
                elif storage_info["driver"] == "QuarkTV":
                    print(
                        f"Alist刷新: [QuarkTV]驱动⚠️ storage_id请手动填入 /Alist挂载路径:/Quark目录路径"
                    )
                else:
                    print(f"Alist刷新: 不支持[{storage_info['driver']}]驱动 ❌")
        else:
            print(f"Alist刷新: storage_id[{storage_id}]格式错误❌")
        # 返回结果
        if storage_mount_path and quark_root_dir:
            return True, (storage_mount_path, quark_root_dir)
        else:
            return False, (None, None)

    def get_storage_id_by_mount_path(self, mount_path):
        """
        根据挂载路径获取存储的数字 ID
        Args:
            mount_path: 存储的挂载路径 (如 /quarktv)
        Returns:
            str: 数字存储 ID，未找到返回 None
        """
        url = f"{self.url}/api/admin/storage/list"
        headers = {"Authorization": self.token}
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            if data.get("code") == 200:
                for storage in data.get("data", {}).get("content", []):
                    if storage.get("mount_path") == mount_path:
                        storage_id_num = str(storage.get("id"))
                        print(f"Alist刷新: 找到存储 [{mount_path}] 的数字ID: {storage_id_num}")
                        return storage_id_num
            else:
                self._check_token_error(data.get("message", ""))
                print(f"Alist刷新: 获取存储列表失败❌ {data.get('message')}")
        except Exception as e:
            print(f"Alist刷新: 获取存储列表失败 {e}")
        print(f"Alist刷新: 未找到挂载路径为 [{mount_path}] 的存储")
        return None

    def get_storage_info(self, storage_id):
        url = f"{self.url}/api/admin/storage/get"
        headers = {"Authorization": self.token}
        querystring = {"id": storage_id}
        try:
            response = requests.request("GET", url, headers=headers, params=querystring)
            response.raise_for_status()
            data = response.json()
            if data.get("code") == 200:
                return data.get("data", [])
            else:
                self._check_token_error(data.get("message", ""))
                print(f"Alist刷新: 存储{storage_id}连接失败❌ {data.get('message')}")
        except Exception as e:
            print(f"Alist刷新: 获取Alist存储出错 {e}")
        return []

    def refresh(self, path):
        data = self.get_file_list(path, True)
        if data.get("code") == 200:
            print(f"📁 Alist刷新：目录[{path}] 成功✅")
            return data.get("data")
        elif "object not found" in data.get("message", ""):
            # 如果是根目录就不再往上查找
            if path == "/" or path == self.storage_mount_path:
                print(f"📁 Alist刷新：根目录不存在，请检查 Alist 配置")
                return False
            # 获取父目录
            parent_path = os.path.dirname(path)
            print(f"📁 Alist刷新：[{path}] 不存在，转父目录 [{parent_path}]")
            # 递归刷新父目录
            return self.refresh(parent_path)
        else:
            self._check_token_error(data.get("message", ""))
            print(f"📁 Alist刷新：失败❌ {data.get('message')}")

    def get_file_list(self, path, force_refresh=False):
        url = f"{self.url}/api/fs/list"
        headers = {"Authorization": self.token}
        payload = {
            "path": path,
            "refresh": force_refresh,
            "password": "",
            "page": 1,
            "per_page": 0,
        }
        try:
            response = requests.request("POST", url, headers=headers, json=payload)
            response.raise_for_status()
            result = response.json()
            # 检查是否为 Token 无效错误
            if result.get("code") != 200:
                self._check_token_error(result.get("message", ""))
            return result
        except Exception as e:
            print(f"📁 Alist刷新: 获取文件列表出错❌ {e}")
        return {}

    def get_root_folder_full_path(self, cookie, pdir_fid):
        if pdir_fid == "0":
            return "/"
        url = "https://drive-h.quark.cn/1/clouddrive/file/sort"
        headers = {
            "cookie": cookie,
            "content-type": "application/json",
        }
        querystring = {
            "pr": "ucpro",
            "fr": "pc",
            "uc_param_str": "",
            "pdir_fid": pdir_fid,
            "_page": 1,
            "_size": "50",
            "_fetch_total": "1",
            "_fetch_sub_dirs": "0",
            "_sort": "file_type:asc,updated_at:desc",
            "_fetch_full_path": 1,
        }
        try:
            response = requests.request(
                "GET", url, headers=headers, params=querystring
            ).json()
            if response["code"] == 0:
                path = ""
                for item in response["data"]["full_path"]:
                    path = f"{path}/{item['file_name']}"
                return path
        except Exception as e:
            print(f"Alist刷新: 获取Quark路径出错 {e}")
        return ""

    def disable_storage(self):
        url = f"{self.url}/api/admin/storage/disable"
        headers = {"Authorization": self.token}
        storage_id_to_use = self._get_numeric_storage_id()
        if not storage_id_to_use:
            print(f"Alist存储: 禁用挂载失败❌ 无法获取有效的数字存储ID")
            return False
        querystring = {"id": storage_id_to_use}
        try:
            response = requests.request("POST", url, headers=headers, params=querystring)
            response.raise_for_status()
            data = response.json()
            if data.get("code") == 200:
                print(f"Alist存储: 已禁用挂载 [{self.storage_id}] ✅")
                return True
            else:
                print(f"Alist存储: 禁用挂载失败❌ {data.get('message')}")
        except Exception as e:
            print(f"Alist存储: 禁用挂载出错 {e}")
        return False

    def enable_storage(self):
        url = f"{self.url}/api/admin/storage/enable"
        headers = {"Authorization": self.token}
        storage_id_to_use = self._get_numeric_storage_id()
        if not storage_id_to_use:
            print(f"Alist存储: 启用挂载失败❌ 无法获取有效的数字存储ID")
            return False
        querystring = {"id": storage_id_to_use}
        try:
            response = requests.request("POST", url, headers=headers, params=querystring)
            response.raise_for_status()
            data = response.json()
            if data.get("code") == 200:
                print(f"Alist存储: 已启用挂载 [{self.storage_id}] ✅")
                return True
            else:
                print(f"Alist存储: 启用挂载失败❌ {data.get('message')}")
        except Exception as e:
            print(f"Alist存储: 启用挂载出错 {e}")
        return False

    def refresh_mount(self):
        """
        刷新 Alist 挂载
        通过禁用后15秒再启用的方式刷新挂载状态
        并发数限制为1
        整个函数在后台执行，不阻塞调用
        """
        # 类级别的并发控制
        if Alist._refreshing:
            print("Alist 挂载正在刷新中，跳过本次请求")
            return

        Alist._refreshing = True
        Alist._skip_token_check = True  # 防止在刷新过程中再次触发 Token 恢复

        def _do_refresh():
            try:
                # 检查是否有有效的数字存储ID
                storage_id_to_use = self._get_numeric_storage_id()
                if not storage_id_to_use:
                    print(f"Alist 挂载刷新失败❌ 无法获取有效的数字存储ID")
                    print(f"建议：检查 Alist storage_id 配置，确保格式为数字ID或 /挂载路径:/夸克路径")
                    Alist._refreshing = False
                    Alist._skip_token_check = False
                    return
                
                # 禁用挂载
                disable_result = self.disable_storage()
                if not disable_result:
                    print("Alist 挂载禁用失败")
                    Alist._refreshing = False
                    Alist._skip_token_check = False
                    return

                # 15秒后自动启用挂载
                time.sleep(15)

                enable_result = self.enable_storage()
                if not enable_result:
                    print("Alist 挂载启用失败")
                    Alist._refreshing = False
                    Alist._skip_token_check = False
                    return

                # 验证并重新初始化（使用 skip_check=True 防止循环）
                # 只有在未初始化成功时才需要重新初始化
                if not self.is_active:
                    print("Alist 未初始化，执行初始化...")
                    if self._do_initialize(skip_check=True):
                        print("✅ Alist 初始化成功")
                    else:
                        print(f"❌ Alist 初始化失败")
                else:
                    print("✅ Alist 挂载刷新成功，服务已恢复正常")

            except Exception as e:
                print(f"刷新 Alist 挂载异常: {str(e)}")
            finally:
                Alist._refreshing = False
                Alist._skip_token_check = False

        # 如果提供了 executor，在后台执行；否则同步执行
        if self._executor:
            self._executor.submit(_do_refresh)
        else:
            # 没有executor时，创建守护线程执行
            import threading
            daemon_thread = threading.Thread(target=_do_refresh, daemon=True)
            daemon_thread.start()

    def _check_token_error(self, msg):
        """检查是否为 Token 无效错误，如果是则触发自动恢复"""
        if not msg or self._skip_token_check:
            return
        error_keywords = ["Access Token无效", "access token invalid", "token expired"]
        msg_lower = msg.lower()
        for keyword in error_keywords:
            if keyword.lower() in msg_lower:
                print(f"检测到 Access Token 无效，触发自动恢复: {msg}")
                self.refresh_mount()
                return
