# !/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import (
    json,
    Flask,
    url_for,
    session,
    jsonify,
    request,
    redirect,
    Response,
    render_template,
    send_from_directory,
    stream_with_context,
)
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from concurrent.futures import ThreadPoolExecutor, as_completed
from sdk.cloudsaver import CloudSaver
from sdk.pansou import PanSou
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import subprocess
import requests
import hashlib
import logging
import traceback
import base64
import secrets
import sys
import os
import re
from datetime import datetime
from collections import defaultdict

parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, parent_dir)
from quark_auto_save import Quark, Config, MagicRename
from plugins.alist import Alist

print(
    r"""
   ____    ___   _____
  / __ \  /   | / ___/
 / / / / / /| | \__ \
/ /_/ / / ___ |___/ /
\___\_\/_/  |_/____/

-- Quark-Auto-Save --
 """
)
sys.stdout.flush()


def get_app_ver():
    """获取应用版本"""
    try:
        with open("build.json", "r") as f:
            build_info = json.loads(f.read())
            BUILD_SHA = build_info["BUILD_SHA"]
            BUILD_TAG = build_info["BUILD_TAG"]
    except Exception as e:
        BUILD_SHA = os.getenv("BUILD_SHA", "")
        BUILD_TAG = os.getenv("BUILD_TAG", "")
    if BUILD_TAG[:1] == "v":
        return BUILD_TAG
    elif BUILD_SHA:
        return f"{BUILD_TAG}({BUILD_SHA[:7]})"
    else:
        return "dev"


# 文件路径
PYTHON_PATH = "python3" if os.path.exists("/usr/bin/python3") else "python"
SCRIPT_PATH = os.environ.get("SCRIPT_PATH", "./quark_auto_save.py")
CONFIG_PATH = os.environ.get("CONFIG_PATH", "./config/quark_config.json")
PLUGIN_FLAGS = os.environ.get("PLUGIN_FLAGS", "")
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = os.environ.get("PORT", 5005)
TASK_TIMEOUT = int(os.environ.get("TASK_TIMEOUT", 1800))

config_data = {}
task_plugins_config_default = {}

app = Flask(__name__)
app.config["APP_VERSION"] = get_app_ver()
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))
app.config["SESSION_COOKIE_NAME"] = "QUARK_AUTO_SAVE_SESSION"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=31)
app.json.ensure_ascii = False
app.json.sort_keys = False
app.jinja_env.variable_start_string = "[["
app.jinja_env.variable_end_string = "]]"

scheduler = BackgroundScheduler()
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="[%(asctime)s][%(levelname)s] %(message)s",
    datefmt="%m-%d %H:%M:%S",
)


_alist_instance = None

def get_alist_client():
    """
    单例模式获取 Alist 客户端实例。
    如果配置未更改，直接返回缓存的实例，避免重复初始化。
    """
    global _alist_instance
    if _alist_instance is None:
        alist_config = config_data.get("plugins", {}).get("alist", {})
        # 只有当配置存在且有效时才初始化
        if alist_config.get("url") and alist_config.get("token"):
            try:
                _alist_instance = Alist(**alist_config)
            except Exception as e:
                logging.error(f"初始化 Alist 插件失败: {e}")
                return None
    return _alist_instance

def reset_alist_client():
    """强制重置 Alist 实例（用于配置更新后）"""
    global _alist_instance
    _alist_instance = None

def refresh_alist_cache(path):
    """
    刷新 Alist 缓存，确保夸克转存后的数据能及时同步到 Alist
    
    Args:
        path: 需要刷新的路径
        
    Returns:
        bool: 刷新是否成功
    """
    try:
        alist_client = get_alist_client()
        if not alist_client:
            logging.warning("Alist 未配置，跳过缓存刷新")
            return False
            
        # 调用 Alist 的 refresh 方法
        refresh_result = alist_client.refresh(path)
        if refresh_result:
            logging.info(f"✅ Alist 缓存刷新成功: {path}")
            return True
        else:
            logging.warning(f"⚠️ Alist 缓存刷新失败: {path}")
            return False
    except Exception as e:
        logging.error(f"❌ Alist 缓存刷新异常: {str(e)}")
        return False

def get_quark_client():
    """
    统一获取 Quark 客户端实例。
    如果 Cookie 未配置，返回 None。
    """
    cookies = config_data.get("cookie")
    if not cookies or not isinstance(cookies, list) or not cookies[0]:
        return None
    # Quark 类的初始化开销很小（主要是字符串解析），直接每次实例化即可，保证线程安全
    return Quark(cookies[0])

def get_fid_by_path(account, path):
    """
    通用辅助函数：根据路径获取目录的fid。
    特殊处理根目录的情况（根目录的fid是固定的"0"）。
    
    Args:
        account: Quark 客户端实例
        path: 要获取fid的路径
    
    Returns:
        str: 目录的fid，如果失败则返回None
    """
    if path == "/":
        return "0"  # 根目录的fid固定为"0"
    
    # 非根目录，使用API获取fid
    fids_res = account.get_fids([path])
    if fids_res:
        return fids_res[0]["fid"]
    return None

# 过滤werkzeug日志输出
if not DEBUG:
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    logging.getLogger("apscheduler").setLevel(logging.ERROR)
    sys.modules["flask.cli"].show_server_banner = lambda *x: None


def gen_md5(string):
    md5 = hashlib.md5()
    md5.update(string.encode("utf-8"))
    return md5.hexdigest()


def get_login_token():
    # 兼容旧API的token，基于第一个管理员用户生成
    admin_user = next((user for user in config_data.get("users", []) if user.get("role") == "admin"), None)
    if admin_user:
        username = admin_user.get("username", "")
        password = admin_user.get("password", "")
        return gen_md5(f"token{username}{password}+-*/")[8:24]
    return None


def is_login():
    # 检查session中是否有用户信息
    return 'user' in session


# 设置icon
@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )


# 登录页面
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        form_username = request.form.get("username")
        form_password = request.form.get("password")
        
        # 从配置中查找匹配的用户
        user_to_check = None
        for user in config_data.get("users", []):
            if user.get("username") == form_username:
                user_to_check = user
                break
        
        if user_to_check:
            password = user_to_check.get("password", "")
            is_password_correct = False
            # 检查密码是哈希值还是旧的明文
            # 尝试直接验证哈希（check_password_hash 会自动识别方法）
            try:
                if check_password_hash(password, form_password):
                    is_password_correct = True
            except:
                # 如果 check_password_hash 抛出异常（例如因为密码是明文而不是哈希），则忽略
                pass

            if not is_password_correct and password == form_password:
                # 如果是旧的明文密码，且匹配
                is_password_correct = True
                # 【关键步骤】为用户自动升级密码为哈希值
                user_to_check["password"] = generate_password_hash(form_password)
                # 将更新后的用户信息写回配置文件
                Config.write_json(CONFIG_PATH, config_data)
                logging.info(f">>> 用户 {form_username} 的密码已自动升级为哈希存储")

            if is_password_correct:
                logging.info(f">>> 用户 {form_username} 登录成功")
                session.permanent = True
                # 存储用户信息到session
                session['user'] = {
                    'username': user_to_check.get("username"),
                    'role': user_to_check.get("role", "user") # 默认为普通用户
                }
                return redirect(url_for("index"))

        logging.info(f">>> 用户 {form_username} 登录失败")
        return render_template("login.html", message="登录失败")

    if is_login():
        return redirect(url_for("index"))
    return render_template("login.html", error=None)


# 注册页面
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        invite_code = request.form.get("invite_code")

        if not all([username, password, confirm_password, invite_code]):
             return render_template("register.html", error="请填写所有字段")

        if password != confirm_password:
            return render_template("register.html", error="两次密码输入不一致")

        # 检查用户名是否已存在
        for user in config_data.get("users", []):
            if user.get("username") == username:
                return render_template("register.html", error="用户名已存在")

        # 验证邀请码
        invite_codes = config_data.get("invite_codes", [])
        valid_code = None
        for code_entry in invite_codes:
            if code_entry.get("code") == invite_code:
                if code_entry.get("type") == "one_time" and code_entry.get("status") == "used":
                    continue # 已失效的一次性码
                valid_code = code_entry
                break
        
        if not valid_code:
            return render_template("register.html", error="无效或已过期的邀请码")

        # 创建用户
        new_user = {
            "username": username,
            "password": generate_password_hash(password),
            "role": "user" # 注册用户默认为普通用户
        }
        config_data["users"].append(new_user)

        # 如果是一次性邀请码，更新状态
        if valid_code.get("type") == "one_time":
            valid_code["status"] = "used"
            # 记录使用者信息，方便追踪（可选）
            valid_code["used_by"] = username
            valid_code["used_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        Config.write_json(CONFIG_PATH, config_data)
        logging.info(f">>> 用户 {username} 使用邀请码 {invite_code} 注册成功")
        
        return render_template("login.html", message="注册成功，请登录")

    if is_login():
        return redirect(url_for("index"))
    return render_template("register.html", error=None)


# 退出登录
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


# 管理页面
@app.route("/old_index")
def old_index():
    if not is_login():
        return redirect(url_for("login"))
    # 检查是否为管理员
    if session.get('user', {}).get('role') != 'admin':
        return redirect(url_for("index")) # 非管理员跳转回主页
    return render_template(
        "index.html", version=app.config["APP_VERSION"], plugin_flags=PLUGIN_FLAGS
    )


@app.route("/")
@app.route("/<path:path>")
def index(path=""):
    if not is_login():
        return redirect(url_for("login"))
    user_info = session.get('user', {})
    is_admin = user_info.get('role') == 'admin'
    username = user_info.get('username', '')
    return render_template("new/index.html", is_admin=is_admin, username=username)


# 获取配置数据 (仅限管理员使用，不要在非管理页面调用)
@app.route("/api/admin/config")
def get_admin_data():
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    # 检查是否为管理员
    if session.get('user', {}).get('role') != 'admin':
        return jsonify({"success": False, "message": "无权访问"}), 403
    data = Config.read_json(CONFIG_PATH)
    if "users" in data:
        del data["users"] # 不返回用户信息
    data["api_token"] = get_login_token()
    data["task_plugins_config_default"] = task_plugins_config_default
    return jsonify({"success": True, "data": data})

@app.route("/api/public_config")
def get_public_config():
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    user_info = session.get('user', {})
    is_admin = user_info.get('role') == 'admin'
    save_path_default = config_data.get("save_path_default", "/") if is_admin else ""
    data = {
        "version": app.config["APP_VERSION"],
        "save_path_default": save_path_default,
        "is_admin": is_admin,
        "username": user_info.get('username')
    }
    return jsonify({"success": True, "data": data})



# 更新数据
def deep_merge(source, destination):
    """
    Recursively merges source dict into destination dict.
    """
    for key, value in source.items():
        if isinstance(value, dict):
            # get node or create one
            node = destination.setdefault(key, {})
            deep_merge(value, node)
        else:
            destination[key] = value
    return destination


@app.route("/update", methods=["POST"])
def update():
    global config_data
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    
    update_data = request.json
    dont_save_keys = ["task_plugins_config_default", "api_token"]
    for key in dont_save_keys:
        if key in update_data:
            del update_data[key]

    config_data = deep_merge(update_data, config_data)
    
    Config.write_json(CONFIG_PATH, config_data)

    # --- 新增：配置更新后，重置 Alist 实例 ---
    reset_alist_client()
    
    # 重新加载任务
    if reload_tasks():
        logging.info(f">>> 配置更新成功")
        return jsonify({"success": True, "message": "配置更新成功"})
    else:
        logging.info(f">>> 配置更新失败")
        return jsonify({"success": False, "message": "配置更新失败"})


# 处理运行脚本请求
@app.route("/run_script_now", methods=["POST"])
def run_script_now():
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    tasklist = request.json.get("tasklist", [])
    command = [PYTHON_PATH, "-u", SCRIPT_PATH, CONFIG_PATH]
    logging.info(
        f">>> 手动运行任务 [{tasklist[0].get('taskname') if len(tasklist)>0 else 'ALL'}] 开始执行..."
    )

    def generate_output():
        # 设置环境变量
        process_env = os.environ.copy()
        process_env["PYTHONIOENCODING"] = "utf-8"
        if request.json.get("quark_test"):
            process_env["QUARK_TEST"] = "true"
            process_env["COOKIE"] = json.dumps(
                request.json.get("cookie", []), ensure_ascii=False
            )
            process_env["PUSH_CONFIG"] = json.dumps(
                request.json.get("push_config", {}), ensure_ascii=False
            )
        if tasklist:
            process_env["TASKLIST"] = json.dumps(tasklist, ensure_ascii=False)
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=process_env,
        )
        try:
            for line in iter(process.stdout.readline, ""):
                logging.info(line.strip())
                yield f"data: {line}\n\n"
            yield "data: [DONE]\n\n"
        finally:
            process.stdout.close()
            process.wait()

    return Response(
        stream_with_context(generate_output()),
        content_type="text/event-stream;charset=utf-8",
    )


@app.route("/task_suggestions")
def get_task_suggestions():
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    query = request.args.get("q", "").lower()
    deep = request.args.get("d", "").lower()
    net_data = config_data.get("source", {}).get("net", {})
    cs_data = config_data.get("source", {}).get("cloudsaver", {})
    ps_data = config_data.get("source", {}).get("pansou", {})

    def net_search():
        if str(net_data.get("enable", "true")).lower() != "false":
            base_url = base64.b64decode("aHR0cHM6Ly9zLjkxNzc4OC54eXo=").decode()
            url = f"{base_url}/task_suggestions?q={query}&d={deep}"
            try:
                response = requests.get(url, timeout=20)
                if response.status_code == 200:
                    return response.json()
            except Exception as e:
                logging.error(f"Net search error: {e}")
        return []

    def cs_search():
        if (
            cs_data.get("server")
            and cs_data.get("username")
            and cs_data.get("password")
        ):
            cs = CloudSaver(cs_data.get("server"))
            cs.set_auth(
                cs_data.get("username", ""),
                cs_data.get("password", ""),
                cs_data.get("token", ""),
            )
            search = cs.auto_login_search(query)
            if search.get("success"):
                if search.get("new_token"):
                    cs_data["token"] = search.get("new_token")
                    Config.write_json(CONFIG_PATH, config_data)
                search_results = cs.clean_search_results(search.get("data"))
                return search_results
        return []

    def ps_search():
        if ps_data.get("server"):
            ps = PanSou(ps_data.get("server"))
            channels = ps_data.get("channels")
            plugins = ps_data.get("plugins")
            return ps.search(query, deep == "1", channels=channels, plugins=plugins)
        return []

    try:
        search_results = []
        with ThreadPoolExecutor(max_workers=3) as executor:
            features = []
            features.append(executor.submit(net_search))
            features.append(executor.submit(cs_search))
            features.append(executor.submit(ps_search))
            for future in as_completed(features):
                result = future.result()
                search_results.extend(result)

        # 按时间排序并去重
        results = []
        link_array = []
        search_results.sort(key=lambda x: x.get("datetime", ""), reverse=True)
        for item in search_results:
            url = item.get("shareurl", "")
            if url != "" and url not in link_array:
                link_array.append(url)
                results.append(item)

        return jsonify({"success": True, "data": results})
    except Exception as e:
        return jsonify({"success": True, "message": f"error: {str(e)}"})


@app.route("/get_share_detail", methods=["POST"])
def get_share_detail():
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    shareurl = request.json.get("shareurl", "")
    stoken = request.json.get("stoken", "")
    pdir_fid = request.json.get("pdir_fid", 0)
    pwd_id = request.json.get("pwd_id", "")
    
    # 这里使用无Cookie初始化，仅用于解析链接
    account = Quark()
    
    if shareurl:
        pwd_id, passcode, pdir_fid, paths = account.extract_url(shareurl)
    else:
        passcode, paths = "", []
    if not stoken:
        get_stoken = account.get_stoken(pwd_id, passcode)
        if get_stoken.get("status") == 200:
            stoken = get_stoken["data"]["stoken"]
        else:
            return jsonify(
                {"success": False, "data": {"error": get_stoken.get("message")}}
            )
    share_detail = account.get_detail(
        pwd_id, stoken, pdir_fid, _fetch_share=1, fetch_share_full_path=1
    )

    if share_detail.get("code") != 0:
        return jsonify(
            {"success": False, "data": {"error": share_detail.get("message")}}
        )

    data = share_detail["data"]
    data["paths"] = [
        {"fid": i["fid"], "name": i["file_name"]}
        for i in share_detail["data"].get("full_path", [])
    ] or paths
    data["stoken"] = stoken
    data["pwd_id"] = pwd_id

    # 正则处理预览
    def preview_regex(data):
        task = request.json.get("task", {})
        magic_regex = request.json.get("magic_regex", {})
        mr = MagicRename(magic_regex)
        mr.set_taskname(task.get("taskname", ""))
        
        # 优化点：使用 helper 获取带Cookie的实例
        account = get_quark_client()
        
        if account:
            savepath_fid = get_fid_by_path(account, task.get("savepath", ""))
            if savepath_fid:
                dir_file_list = account.ls_dir(savepath_fid)["data"]["list"]
                dir_filename_list = [dir_file["file_name"] for dir_file in dir_file_list]
            else:
                dir_file_list = []
                dir_filename_list = []
        else:
            dir_file_list = []
            dir_filename_list = []

        pattern, replace = mr.magic_regex_conv(
            task.get("pattern", ""), task.get("replace", "")
        )
        for share_file in data["list"]:
            search_pattern = (
                task["update_subdir"]
                if share_file["dir"] and task.get("update_subdir")
                else pattern
            )
            if re.search(search_pattern, share_file["file_name"]):
                # 文件名重命名，目录不重命名
                file_name_re = (
                    share_file["file_name"]
                    if share_file["dir"]
                    else mr.sub(pattern, replace, share_file["file_name"])
                )
                if file_name_saved := mr.is_exists(
                    file_name_re,
                    dir_filename_list,
                    (task.get("ignore_extension") and not share_file["dir"]),
                ):
                    share_file["file_name_saved"] = file_name_saved
                else:
                    share_file["file_name_re"] = file_name_re

        # 文件列表排序
        if re.search(r"\{I+\}", replace):
            mr.set_dir_file_list(dir_file_list, replace)
            mr.sort_file_list(data["list"])

    if request.json.get("task"):
        preview_regex(data)

    return jsonify({"success": True, "data": data})


@app.route("/get_savepath_detail")
def get_savepath_detail():
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    
    # 优化点：使用 helper
    account = get_quark_client()
    if not account:
        return jsonify({"success": False, "data": {"error": "未配置Cookie"}})
        
    paths = []
    if path := request.args.get("path"):
        path = re.sub(r"/+", "/", path)
        # 使用辅助函数处理路径获取fid
        fid = get_fid_by_path(account, path)
        if fid is None:
            return jsonify({"success": False, "data": {"error": "获取fid失败"}})
            
        # 处理路径数组
        if path != "/":
            dir_names = path.split("/")
            if dir_names[0] == "":
                dir_names.pop(0)
            path_fids = []
            current_path = ""
            for dir_name in dir_names:
                current_path += "/" + dir_name
                path_fids.append(current_path)
            get_fids = account.get_fids(path_fids)
            if get_fids:
                paths = [
                    {"fid": get_fid["fid"], "name": dir_name}
                    for get_fid, dir_name in zip(get_fids, dir_names)
                ]
            else:
                return jsonify({"success": False, "data": {"error": "获取fid失败"}})
        else:
            paths = []
    else:
        fid = request.args.get("fid", "0")
    file_list = {
        "list": account.ls_dir(fid)["data"]["list"],
        "paths": paths,
    }
    return jsonify({"success": True, "data": file_list})


@app.route("/delete_file", methods=["POST"])
def delete_file():
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    
    # 优化点：使用 helper
    account = get_quark_client()
    if not account:
        return jsonify({"success": False, "message": "未配置Cookie"})

    if fid := request.json.get("fid"):
        response = account.delete([fid])
    else:
        response = {"success": False, "message": "缺失必要字段: fid"}
    return jsonify(response)

##规范夸克的路径
def format_quark_parent_path(path):
    """
    规范化夸克路径，处理多余的斜杠，保持为 Unix 风格。
    """
    # 将反斜杠替换为正斜杠
    path = path.replace('\\', '/')

    # 处理多余的斜杠
    path = re.sub(r'/{2,}', '/', path)
    
    if not path.startswith('/'):
        path = '/' + path

    # 规范化路径，处理多余的斜杠.夸克不能斜杆结尾.不然找不到路径
    if path != "/" and path.endswith('/'):
        path = path[:-1]

    return path

    
def _get_user_path(path, isAlistpath=False):
    """
    根据用户角色和 Alist 插件配置调整路径 (优化版)。
    """
    user_info = session.get('user', {})
    
    # 管理员不需要路径前缀处理，直接返回原路径
    isAdmin = user_info.get('role') != 'user'
        
    username = user_info.get('username')
    if not username:
        return path
        


    save_path_default = config_data.get("save_path_default", "")




    if not path.startswith('/'):
        path = '/' + path
    

    final_path = ''

    if isAlistpath:
        prefix = ""
        # --- 优化点：获取单例实例，不再每次 new ---
        alist = get_alist_client()
        if alist and alist.is_active and alist.storage_mount_path:
            prefix = alist.storage_mount_path
        # ---------------------------------------

        if isAdmin:
            final_path = f"{prefix}{path}"
        else:
            final_path = f"{prefix}/{save_path_default}/{username}{path}"
    else:
        if isAdmin:
            final_path = path
        else:
            final_path = f"{save_path_default}/{username}{path}"

    final_path = format_quark_parent_path(final_path)
    return final_path

def ensure_directory_exists(account, dir_path, created_dirs):
    """
    使用迭代方式确保目录存在，如果不存在则创建。
    返回目录的fid。
    created_dirs 用于缓存已创建的目录 {path: fid}。
    """
    # 使用 Unix 风格的路径分隔符
    # 规范化路径，处理多余的斜杠，但保持为 Unix 风格
    dir_path = dir_path.replace('\\', '/').replace('//', '/')  # 将反斜杠替换为正斜杠，处理重复斜杠
    
    # 如果已经是根目录，直接返回
    if dir_path == "/":
        return "0" # 根目录的fid是"0"

    # 如果已经在缓存中，直接返回
    if dir_path in created_dirs:
        return created_dirs[dir_path]

    # 从根目录开始，逐级构建路径
    path_parts = [part for part in dir_path.split('/') if part]  # 移除空字符串
    
    current_path = "/"
    parent_fid = "0" # 根目录的fid是"0"

    for part in path_parts:
        if current_path == "/":
            current_path = f"/{part}"
        else:
            current_path = f"{current_path}/{part}"

        # 检查当前路径是否已在缓存中
        if current_path in created_dirs:
            parent_fid = created_dirs[current_path]
            continue
        
        # 尝试获取目录，可能它已存在但不在缓存中
        new_fid = get_fid_by_path(account, current_path)
        if new_fid:
            created_dirs[current_path] = new_fid
            parent_fid = new_fid
            print(f"ℹ️ 目录已存在: {current_path} (fid: {new_fid})")
            continue

        # 如果不存在，则创建它
        mkdir_res = account.mkdir(current_path)
        
        if mkdir_res and mkdir_res.get("code") == 0:
            new_fid = mkdir_res["data"]["fid"]
            created_dirs[current_path] = new_fid
            parent_fid = new_fid
            print(f"✅ 目录已创建: {current_path} (fid: {new_fid})")
        else:
            error_msg = mkdir_res.get('message', 'Unknown error') if mkdir_res else 'Failed to get response'
            raise Exception(f"❌ 无法创建或获取目录: {current_path}. 错误: {error_msg}")

    return created_dirs[dir_path]

@app.route("/api/transfer_with_structure", methods=["POST"])
def transfer_files_with_structure():
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    
    data = request.json
    items = data.get("items", [])
    stoken = data.get("stoken", "")
    pwd_id = data.get("pwd_id", "")
    base_save_path = data.get("base_save_path", "/")

    if not items or not stoken or not pwd_id:
        return jsonify({"success": False, "message": "Missing required parameters."})

    save_path = _get_user_path(base_save_path, False)
    

    logging.info(f"save_path: {save_path}")

    # 优化点：使用 helper
    account = get_quark_client()
    if not account:
        return jsonify({"success": False, "message": "未配置Cookie"})

    # --- 步骤 1: 获取基础保存路径 save_path 的真实 fid ---
    # 使用 ensure_directory_exists 确保路径存在（如果是多级路径也能正确创建）
    try:
        save_path_fid = ensure_directory_exists(account, save_path, {})
        if save_path_fid:
            logging.info(f"成功获取或创建保存路径: {save_path}")
    except Exception as e:
        return jsonify({"success": False, "message": f"无法创建或找到保存路径: {save_path}, 错误: {str(e)}"})
    
    # --- 步骤 2: 统一的转存逻辑 ---
    # 不再需要区分单个目录转存和选择性转存，所有情况都用此逻辑处理
    logging.info(f"开始转存，共 {len(items)} 个项目。")
    
    created_dirs = {save_path: save_path_fid}
    
    for item in items:
        file_name = item.get("file_name", "")
        is_dir = item.get("is_dir", False)
        path_array = item.get('path', [])
        
        # 从路径数组中获取父目录路径数组
        parent_path_array = path_array[:-1]
        
        # 将父目录数组拼接成字符串
        parent_path_str = "/".join(parent_path_array)
        
        # 计算目标目录路径 - 使用 Unix 风格的路径分隔符
        if save_path == "/":
            target_dir_path = f"/{parent_path_str.lstrip('/')}" if parent_path_str else "/"
        else:
            target_dir_path = f"{save_path.rstrip('/')}/{parent_path_str.lstrip('/')}" if parent_path_str else save_path
        
        # 确保目标目录存在
        if target_dir_path not in created_dirs:
            # 使用 ensure_directory_exists 函数来确保目录存在（会自动处理父目录创建）
            try:
                fid = ensure_directory_exists(account, target_dir_path, created_dirs)
                created_dirs[target_dir_path] = fid
            except Exception as e:
                return jsonify({
                    "success": False,
                    "message": f"无法创建目录 {target_dir_path}: {str(e)}"
                })
        
        target_dir_fid = created_dirs[target_dir_path]
        
        save_res = account.save_file(
            [item["fid"]], 
            [item["fid_token"]], 
            target_dir_fid, 
            pwd_id, 
            stoken
        )
        
        if save_res.get("code") != 0:
            return jsonify({
                "success": False, 
                "message": f"转存 {file_name} 失败: {save_res.get('message')}"
            })
        
        # 如果是目录，需要更新created_dirs字典
        if is_dir:
            task_id = save_res["data"]["task_id"]
            query_task_res = account.query_task(task_id)
            if query_task_res.get("code") == 0:
                save_as_top_fids = query_task_res["data"]["save_as"]["save_as_top_fids"]
                if save_as_top_fids:
                    if target_dir_path == "/":
                        new_dir_path = f"/{file_name}"
                    else:
                        new_dir_path = f"{target_dir_path.rstrip('/')}/{file_name}"
                    created_dirs[new_dir_path] = save_as_top_fids[0]
    
    # --- 方案1：转存成功后自动刷新alist缓存 ---
    # 转存成功后，刷新alist缓存以确保数据同步
    try:
        alist_save_path = _get_user_path(base_save_path, True)
        refresh_alist_cache(alist_save_path)
        logging.info(f"已自动刷新 Alist 缓存: {alist_save_path}")
    except Exception as e:
        logging.warning(f"转存成功但刷新 Alist 缓存失败: {str(e)}")
    
    return jsonify({
        "success": True,
        "message": f"成功转存 {len(items)} 个项目。"
    })

@app.route("/api/transfer", methods=["POST"])
def transfer_files():
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    
    data = request.json
    fids = data.get("fids", [])
    fid_tokens = data.get("fid_tokens", [])
    stoken = data.get("stoken", "")
    pwd_id = data.get("pwd_id", "")
    save_path = data.get("save_path", "/")

    # 根据用户角色调整保存路径
    save_path = _get_user_path(save_path,False)
    
    if not fids or not stoken or not pwd_id:
        return jsonify({"success": False, "message": "Missing required parameters: fids, stoken, or pwd_id"})

    if len(fids) != len(fid_tokens):
        return jsonify({"success": False, "message": "Mismatch between fids and fid_tokens count"})

    # 优化点：使用 helper
    account = get_quark_client()
    if not account:
        return jsonify({"success": False, "message": "未配置Cookie"})
    
    # 1. 获取或创建保存路径 ID
    save_path = re.sub(r"/{2,}", "/", f"/{save_path}")
    # 使用 ensure_directory_exists 确保路径存在（如果是多级路径也能正确创建）
    try:
        to_pdir_fid = ensure_directory_exists(account, save_path, {})
    except Exception as e:
        return jsonify({"success": False, "message": f"Create save path failed: {str(e)}"})
            
    # 2. 执行转存
    total_success = 0
    errors = []
    
    batch_size = 50 # 稍微保守一点
    for i in range(0, len(fids), batch_size):
        batch_fids = fids[i:i + batch_size]
        batch_tokens = fid_tokens[i:i + batch_size]
        
        try:
            res = account.save_file(batch_fids, batch_tokens, to_pdir_fid, pwd_id, stoken)
            if res["code"] == 0:
                task_id = res["data"]["task_id"]
                task_status = account.query_task(task_id)
                if task_status["code"] == 0:
                     # 检查是否有 save_as_top_fids (表示成功的部分)
                     if task_status["data"] and task_status["data"].get("save_as"):
                         total_success += len(task_status["data"]["save_as"].get("save_as_top_fids", []))
                     else:
                         # 假设全部成功如果没报错
                         total_success += len(batch_fids)
                else:
                    errors.append(f"Batch {i//batch_size + 1} task query failed: {task_status.get('message')}")
            else:
                 errors.append(f"Batch {i//batch_size + 1} save failed: {res.get('message')}")
        except Exception as e:
            logging.error(traceback.format_exc())
            errors.append(f"Batch {i//batch_size + 1} error: {str(e)}")
            
    # --- 方案1：转存成功后自动刷新alist缓存 ---
    # 如果有文件成功转存，刷新alist缓存以确保数据同步
    if total_success > 0:
        try:
            alist_save_path = _get_user_path(save_path, True)
            refresh_alist_cache(alist_save_path)
            logging.info(f"已自动刷新 Alist 缓存: {alist_save_path}")
        except Exception as e:
            logging.warning(f"转存成功但刷新 Alist 缓存失败: {str(e)}")
    
    if len(errors) == 0:
        return jsonify({"success": True, "message": f"Successfully transferred {total_success} items."})
    else:
        msg = f"Completed with errors. Success: {total_success}. Errors: {'; '.join(errors)}"
        return jsonify({"success": False, "message": msg})


# Library 相关 API
@app.route("/api/library/storage_info")
def get_storage_info():
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    
    try:
        # 优化点：使用 helper 获取 Alist 单例
        alist_client = get_alist_client()
        if not alist_client:
            return jsonify({"success": False, "message": "Alist 未配置"})
        
        # 获取存储信息 (使用 client.url 和 client.token)
        url = f"{alist_client.url}/api/admin/storage/list"
        headers = {"Authorization": alist_client.token}
        
        logging.info(f"Getting storage info from: {url}")
        response = requests.get(url, headers=headers)
        logging.info(f"Storage info response status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get("code") == 200:
                storage_list = data.get("data", [])
                quark_storage = None
                for storage in storage_list:
                    if storage.get("driver") == "Quark":
                        quark_storage = storage
                        break
               
                if quark_storage:
                    return jsonify({
                        "success": True,
                        "data": {
                            "storage": quark_storage
                        }
                    })
                else:
                    return jsonify({
                        "success": False,
                        "message": "未找到 Quark 存储驱动"
                    })
        
        return jsonify({"success": False, "message": "获取存储信息失败"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

#alist 获取文件列表
# @app.route("/api/library/fs/list", methods=["POST"])
def get_fs_list():
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    
    try:
        data = request.json
        path = data.get("path", "/")
        
        # 根据用户角色调整路径
        path = _get_user_path(path,True)
        refresh = data.get("refresh", False)
        
        alist_config = config_data.get("plugins", {}).get("alist", {})
        if not alist_config.get("url") or not alist_config.get("token"):
            return jsonify({"success": False, "message": "Alist 未配置"})
        
        # 获取文件列表
        url = f"{alist_config['url']}/api/fs/list"
        headers = {"Authorization": alist_config['token']}
        payload = {
            "path": path,
            "refresh": refresh,
            "password": "",
            "page": 1,
            "per_page": 0,
        }
        
        logging.info(f"Getting file list from: {url}, path: {path}")
        response = requests.post(url, headers=headers, json=payload)
        logging.info(f"File list response status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            if result.get("code") == 200:
                return jsonify({"success": True, "data": result.get("data", {})})
        
        return jsonify({"success": False, "message": result.get("message", "获取文件列表失败")})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/api/library/fs/list", methods=["POST"])
def get_fs_qklist():
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    
    try:
        # 1. 检查并初始化 Quark 实例
        account = get_quark_client()
        if not account:
            return jsonify({"success": False, "message": "夸克 Cookie 未配置"})

        data = request.json
        raw_path = data.get("path", "/")
        logging.info(f"Listing raw_path: {raw_path}")

        # 2. 获取真实路径
        # 注意：这里 isAlistpath 设为 False，因为我们直接操作夸克网盘，不需要 Alist 的挂载前缀
        path = _get_user_path(raw_path, isAlistpath=False)

        


        logging.info(f"Listing Quark path: {path}")
        # 3. 将路径转换为 fid (File ID)
        target_fid = get_fid_by_path(account, path)
        if not target_fid:
            logging.info("路径不存在，返回空列表，模仿 Alist 行为")
            # 路径不存在，返回空列表，模仿 Alist 行为
            return jsonify({
                "success": True,
                "data": {
                    "content": [],
                    "total": 0,
                    "readme": "",
                    "write": True,
                    "provider": "QuarkDirect"
                }
            })

        # 4. 获取文件列表
        # ls_dir 内部已经处理了翻页逻辑，会返回该目录下所有文件
        ls_res = account.ls_dir(target_fid)
        
        if ls_res.get("code") != 0:
            return jsonify({"success": False, "message": ls_res.get("message", "获取文件列表失败")})
        
        quark_files = ls_res.get("data", {}).get("list", [])
        
        # 5. 格式化数据以适配前端 (模拟 Alist 格式)
        content = []
        for item in quark_files:
            # 转换时间戳
            mod_time = ""
            if item.get("updated_at"):
                try:
                    # 夸克通常返回毫秒级时间戳
                    mod_time = datetime.fromtimestamp(item["updated_at"] / 1000).strftime('%Y-%m-%d %H:%M:%S')
                except:
                    pass

            entry = {
                "name": item["file_name"],
                "size": item["size"],
                "is_dir": item["dir"],
                "modified": mod_time,
                "created": mod_time,
                "sign": "", 
                "thumb": item.get("thumbnail_url", ""), # 夸克有的接口会返回缩略图
                "type": 1 if item["dir"] else 0,
                "raw_fid": item["fid"] 
            }
            content.append(entry)

        # 返回结构需符合前端预期
        return jsonify({
            "success": True, 
            "data": {
                "content": content,
                "total": len(content),
                "readme": "",
                "write": True,
                "provider": "QuarkDirect"
            }
        })

    except Exception as e:
        logging.error(f"List FS error: {str(e)}")
        logging.error(traceback.format_exc())
        return jsonify({"success": False, "message": str(e)})

@app.route("/api/library/fs/get", methods=["POST"])
def get_file_info():
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    
    try:
        data = request.json
        path = data.get("path", "")
        
        # 根据用户角色调整路径
        path = _get_user_path(path,True)
        password = data.get("password", "")
        
        # 优化点：使用 helper 获取 Alist 单例
        alist_client = get_alist_client()
        if not alist_client:
            return jsonify({"success": False, "message": "Alist 未配置"})
        
        # 获取文件信息
        url = f"{alist_client.url}/api/fs/get"
        headers = {"Authorization": alist_client.token}
        payload = {
            "path": path,
            "password": password,
        }
        
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code == 200:
            result = response.json()
            if result.get("code") == 200:
                return jsonify({"success": True, "data": result.get("data", {})})
        
        return jsonify({"success": False, "message": result.get("message", "获取文件信息失败")})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/api/library/fs/download", methods=["GET", "POST"])
def get_download_url():
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    
    try:
        # 支持 GET 和 POST 两种方法
        if request.method == "GET":
            path = request.args.get("path", "")
        else:
            data = request.json
            path = data.get("path", "")
        
        # 根据用户角色调整路径
        path = _get_user_path(path,True)

        # 优化点：使用 helper 获取 Alist 单例
        alist_client = get_alist_client()
        if not alist_client:
            return jsonify({"success": False, "message": "Alist 未配置"})
        
        # 首先使用 POST 方法获取文件信息，包含 raw_url
        get_url = f"{alist_client.url}/api/fs/get"
        headers = {"Authorization": alist_client.token}
        payload = {
            "path": path,
            "password": ""
        }
        
        logging.info(f"Getting file info from: {get_url}, path: {path}")
        response = requests.post(get_url, headers=headers, json=payload)
        logging.info(f"File info response status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            logging.info(f"File info response: {result}")
            if result.get("code") == 200:
                raw_url = result.get("data", {}).get("raw_url", "")
                if raw_url:
                    return jsonify({"success": True, "data": {"download_url": raw_url}})
                else:
                    # 如果没有 raw_url，尝试使用下载接口
                    download_url = f"{alist_client.url}/api/fs/download"
                    params = {"path": path}
                    
                    logging.info(f"Getting download URL from: {download_url}")
                    download_response = requests.get(download_url, headers=headers, params=params)
                    
                    if download_response.status_code == 200:
                        download_result = download_response.json()
                        if download_result.get("code") == 200:
                            download_url = download_result.get("data", {}).get("raw_url", "")
                            if download_url:
                                return jsonify({"success": True, "data": {"download_url": download_url}})
        
        return jsonify({"success": False, "message": result.get("message", "获取下载链接失败")})
    except Exception as e:
        logging.error(f"Error getting download URL: {str(e)}")
        return jsonify({"success": False, "message": str(e)})

@app.route("/api/library/fs/delete", methods=["POST"])
def delete_fs_items():
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    
    try:
        # 1. 检查配置并初始化 Quark
        # 优化点：使用 helper
        account = get_quark_client()
        if not account:
            return jsonify({"success": False, "message": "夸克 Cookie 未配置，无法执行删除操作"})

        data = request.json
        paths_to_delete = data.get("paths", [])
        if not paths_to_delete:
            return jsonify({"success": False, "message": "缺少 'paths' 参数"})

        # 2. 预处理：按父目录分组，减少网络请求次数
        # 结构: { "父目录路径": ["文件名1", "文件名2"] }
        from collections import defaultdict
        files_by_parent = defaultdict(list)

        for raw_path in paths_to_delete:
            # 【关键修改】isAlistpath=False
            # 我们需要网盘内的真实路径（如 /save/user/file），而不是 Alist 的挂载路径（如 /quarktv/save/user/file）
            real_path = _get_user_path(raw_path, False) 
            
            # 分离父目录和文件名
            parent_dir = os.path.dirname(real_path)
            file_name = os.path.basename(real_path)
            
            # 根目录修正
            if parent_dir == "/" or parent_dir == "":
                parent_dir = "/"
                
            files_by_parent[parent_dir].append(file_name)

        logging.info(f">>> 正在解析 {len(paths_to_delete)} 个文件的 FID...")

        fids_to_delete = []

        # 3. 遍历父目录，查找目标文件的 FID
        for parent_dir, file_names in files_by_parent.items():
            # 获取父目录的 FID
            parent_fid = get_fid_by_path(account, parent_dir)
            if not parent_fid:
                logging.warning(f"无法找到父目录: {parent_dir}，跳过该目录下的文件")
                continue

            # 列出父目录下的所有文件
            ls_res = account.ls_dir(parent_fid)
            if ls_res.get('code') != 0:
                logging.warning(f"列出目录失败: {parent_dir}, 错误: {ls_res.get('message')}")
                continue

            # 构建 {文件名: FID} 映射表
            current_dir_files = ls_res.get('data', {}).get('list', [])
            name_to_fid = {item['file_name']: item['fid'] for item in current_dir_files}

            # 匹配我们要删除的文件
            for target_name in file_names:
                if target_name in name_to_fid:
                    fids_to_delete.append(name_to_fid[target_name])
                else:
                    logging.warning(f"文件未在网盘中找到: {target_name} (位于 {parent_dir})")

        if not fids_to_delete:
            return jsonify({"success": False, "message": "未找到任何有效的文件FID，无法删除"})

        logging.info(f">>> 准备删除 FID 列表: {fids_to_delete}")

        # 4. 执行删除
        result = account.delete(fids_to_delete)

        # 5. 处理结果
        # Quark API 通常 code=0 表示成功，或者 result 为 True
        if isinstance(result, dict):
            if result.get("code") == 0 or result.get("errno") == 0:
                return jsonify({"success": True, "message": f"成功删除 {len(fids_to_delete)} 个项目"})
            else:
                msg = result.get("message") or result.get("error") or "未知错误"
                return jsonify({"success": False, "message": f"删除失败: {msg}"})
        elif result is True:
             return jsonify({"success": True, "message": "删除成功"})
        else:
             return jsonify({"success": False, "message": f"删除返回异常: {result}"})

    except Exception as e:
        logging.error(f"删除操作异常: {str(e)}")
        logging.error(traceback.format_exc())
        return jsonify({"success": False, "message": f"服务端异常: {str(e)}"})

# AI排序相关函数
COMPREHENSIVE_AI_SORT_PROMPT = """
你是一个视频文件排序专家，请分析以下视频文件列表并生成排序规则。

分析要求：
1. 识别所有不同的文件命名模式和规律
2. 处理混合命名模式（如数字序号、中英文集数、季集标识等）
3. 为每种模式生成对应的排序规则
4. 确保规则能正确处理各种边界情况
5. 规则应适用于整个文件集

请返回JSON格式结果：
{
  "analysis": "对文件命名模式和混合情况的全面分析",
  "filePatterns": [
    {
      "patternName": "模式名称",
      "description": "模式描述",
      "sampleFiles": ["符合此模式的示例文件"],
      "count": 10
    }
  ],
  "sortingStrategy": "统一排序|分组排序|混合排序",
  "sortingRules": [
    {
      "ruleName": "规则名称",
      "description": "规则描述",
      "type": "regex|extract|compare",
      "priority": 1,
      "pattern": "正则表达式或提取模式",
      "extractKey": "提取的键名",
      "sortOrder": "asc|desc",
      "dataType": "number|string|date|tuple",
      "confidence": 0.9,
      "applicablePatterns": ["适用的文件模式列表"]
    }
  ],
  "fallbackRules": [当主规则不匹配时使用的备选规则],
  "alternativeRules": [2-3种备选规则集]
}

常见混合模式示例：
- 纯数字序号：01.mp4, 02.mp4, 03.mp4
- 中英混合：第一集.mp4, 第2集.mp4, E03.mp4
- 季集标识：S01E01.mp4, Season 2 Episode 3.mp4, 第1季第4集.mp4
- 日期命名：2023-01-15.mp4, 2023.01.16.mp4
- 电影系列：Movie.Part1.mp4, Movie Part II.mp4, 电影(中).mp4
"""

@app.route("/api/library/comprehensive-ai-sort", methods=["POST"])
def call_ai_service():
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    
    """
    调用AI服务获取排序规则
    """
    try:
        data = request.json
        files = data.get("files", [])
        path = data.get("path", "/")
        prompt = COMPREHENSIVE_AI_SORT_PROMPT
        ai_config = config_data.get("ai_service", {})
        api_key = ai_config.get("api_key", "")
        base_url = ai_config.get("base_url", "https://api.openai.com/v1")
        model = ai_config.get("model", "gpt-3.5-turbo")
        timeout = ai_config.get("timeout", 30)
        
        if not api_key:
            logging.warning("AI服务未配置API密钥")
            return {"success": False, "message": "AI服务未配置API密钥"}
        
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": model,
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": files}
            ],
            "temperature": 0.3
        }
        
        response = requests.post(
            f"{base_url}/chat/completions",
            headers=headers,
            json=data,
            timeout=timeout
        )
        
        if response.status_code == 200:
            result = response.json()
            content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            
            # 尝试解析JSON
            try:
                # 提取JSON部分（处理可能的额外文本）
                import json
                start_idx = content.find("{")
                end_idx = content.rfind("}") + 1
                if start_idx != -1 and end_idx > start_idx:
                    json_str = content[start_idx:end_idx]
                    rules_data = json.loads(json_str)
                    return {"success": True, "data": rules_data}
                else:
                    return {"success": False, "message": "AI返回的内容中未找到有效的JSON"}
            except json.JSONDecodeError as e:
                logging.error(f"解析AI返回的JSON失败: {str(e)}")
                return {"success": False, "message": f"解析AI返回的JSON失败: {str(e)}"}
        else:
            error_msg = f"AI服务请求失败: {response.status_code} - {response.text}"
            logging.error(error_msg)
            return {"success": False, "message": error_msg}
            
    except requests.exceptions.Timeout:
        error_msg = "AI服务请求超时"
        logging.error(error_msg)
        return {"success": False, "message": error_msg}
    except Exception as e:
        error_msg = f"调用AI服务异常: {str(e)}"
        logging.error(error_msg)
        return {"success": False, "message": error_msg}


# 添加任务接口
@app.route("/api/add_task", methods=["POST"])
def add_task():
    global config_data
    # 验证token
    if not is_login():
        return jsonify({"success": False, "code": 1, "message": "未登录"}), 401
    # 必选字段
    request_data = request.json
    required_fields = ["taskname", "shareurl", "savepath"]
    for field in required_fields:
        if field not in request_data or not request_data[field]:
            return (
                jsonify(
                    {"success": False, "code": 2, "message": f"缺少必要字段: {field}"}
                ),
                400,
            )
    if not request_data.get("addition"):
        request_data["addition"] = task_plugins_config_default
    # 添加任务
    config_data["tasklist"].append(request_data)
    Config.write_json(CONFIG_PATH, config_data)
    logging.info(f">>> 通过API添加任务: {request_data['taskname']}")
    return jsonify(
        {"success": True, "code": 0, "message": "任务添加成功", "data": request_data}
    )


# 定时任务执行的函数
def run_python(args):
    logging.info(f">>> 定时运行任务")
    try:
        result = subprocess.run(
            f"{PYTHON_PATH} {args}",
            shell=True,
            timeout=TASK_TIMEOUT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        # 输出执行日志
        if result.stdout:
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    logging.info(line)

        if result.returncode == 0:
            logging.info(f">>> 任务执行成功")
        else:
            logging.error(f">>> 任务执行失败，返回码: {result.returncode}")
            if result.stderr:
                logging.error(f"错误信息: {result.stderr[:500]}")
    except subprocess.TimeoutExpired as e:
        logging.error(f">>> 任务执行超时(>{TASK_TIMEOUT}s)，强制终止")
        # 尝试终止进程
        if e.process:
            try:
                e.process.kill()
                logging.info(">>> 已终止超时进程")
            except:
                pass
    except Exception as e:
        logging.error(f">>> 任务执行异常: {str(e)}")
        logging.error(traceback.format_exc())
    finally:
        # 确保函数能够正常返回
        logging.debug(f">>> run_python 函数执行完成")


# 重新加载任务
def reload_tasks():
    # 读取定时规则
    if crontab := config_data.get("crontab"):
        if scheduler.state == 1:
            scheduler.pause()  # 暂停调度器
        trigger = CronTrigger.from_crontab(crontab)
        scheduler.remove_all_jobs()
        scheduler.add_job(
            run_python,
            trigger=trigger,
            args=[f"{SCRIPT_PATH} {CONFIG_PATH}"],
            id=SCRIPT_PATH,
            max_instances=1,  # 最多允许1个实例运行
            coalesce=True,  # 合并错过的任务，避免堆积
            misfire_grace_time=300,  # 错过任务的宽限期(秒)，超过则跳过
            replace_existing=True,  # 替换已存在的同ID任务
        )
        if scheduler.state == 0:
            scheduler.start()
        elif scheduler.state == 2:
            scheduler.resume()
        scheduler_state_map = {0: "停止", 1: "运行", 2: "暂停"}
        logging.info(">>> 重载调度器")
        logging.info(f"调度状态: {scheduler_state_map[scheduler.state]}")
        logging.info(f"定时规则: {crontab}")
        logging.info(f"现有任务: {scheduler.get_jobs()}")
        return True
    else:
        logging.info(">>> no crontab")
        return False


def init():
    global config_data, task_plugins_config_default
    logging.info(">>> 初始化配置")
    # 检查配置文件是否存在
    if not os.path.exists(CONFIG_PATH):
        if not os.path.exists(os.path.dirname(CONFIG_PATH)):
            os.makedirs(os.path.dirname(CONFIG_PATH))
        with open("quark_config.json", "rb") as src, open(CONFIG_PATH, "wb") as dest:
            dest.write(src.read())

    # 读取配置
    config_data = Config.read_json(CONFIG_PATH)
    Config.breaking_change_update(config_data)
    if not config_data.get("magic_regex"):
        config_data["magic_regex"] = MagicRename().magic_regex

    # 用户配置初始化和迁移
    if "users" not in config_data or not config_data["users"]:
        # 从旧的 webui 配置迁移
        if "webui" in config_data and config_data["webui"].get("username"):
            config_data["users"] = [{
                "username": config_data["webui"]["username"],
                "password": config_data["webui"]["password"],
                "role": "admin"
            }]
            del config_data["webui"] # 删除旧配置
            logging.info(">>> 已将旧的 webui 配置迁移到新的 users 列表")
        else:
            # 创建一个默认管理员账户
            config_data["users"] = [{
                "username": os.environ.get("WEBUI_USERNAME", "admin"),
                "password": generate_password_hash(os.environ.get("WEBUI_PASSWORD", "admin123")),
                "role": "admin"
            }]
            logging.info(">>> 已创建默认管理员账户")

    # 初始化邀请码配置
    if "invite_codes" not in config_data:
        config_data["invite_codes"] = [
            # 示例：通用邀请码
            # {"code": "quark_share", "type": "generic", "note": "公开邀请码"},
            # 示例：一次性邀请码
            # {"code": "vip_only_001", "type": "one_time", "status": "unused", "note": "VIP专属"}
        ]

    # 默认定时规则
    if not config_data.get("crontab"):
        config_data["crontab"] = "0 8,18,20 * * *"

    # 初始化插件配置
    _, plugins_config_default, task_plugins_config_default = Config.load_plugins()
    plugins_config_default.update(config_data.get("plugins", {}))
    config_data["plugins"] = plugins_config_default

    # 更新配置
    Config.write_json(CONFIG_PATH, config_data)


if __name__ == "__main__":
    init()
    reload_tasks()
    logging.info(">>> 启动Web服务")
    # 打印明显的版本号日志，方便在 Docker logs 中查看
    logging.info("========================================")
    logging.info(f"   Current Version: {app.config['APP_VERSION']}")
    logging.info("========================================")
    logging.info(f"运行在: http://{HOST}:{PORT}")
    app.run(
        debug=DEBUG,
        host=HOST,
        port=PORT,
    )