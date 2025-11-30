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

parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, parent_dir)
from quark_auto_save import Quark, Config, MagicRename

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
        
        # 从配置中查找用户
        for user in config_data.get("users", []):
            password = user.get("password", "")
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
                user["password"] = generate_password_hash(form_password)
                # 将更新后的用户信息写回配置文件
                Config.write_json(CONFIG_PATH, config_data)
                logging.info(f">>> 用户 {form_username} 的密码已自动升级为哈希存储")

            if is_password_correct:
                logging.info(f">>> 用户 {form_username} 登录成功")
                session.permanent = True
                # 存储用户信息到session
                session['user'] = {
                    'username': user.get("username"),
                    'role': user.get("role", "user") # 默认为普通用户
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
    data = {
        "version": app.config["APP_VERSION"],
        "save_path_default": config_data.get("save_path_default", "/"),
        "is_admin": user_info.get('role') == 'admin',
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
            response = requests.get(url)
            return response.json()
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
            return ps.search(query, deep == "1")
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
        account = Quark(config_data["cookie"][0])
        get_fids = account.get_fids([task.get("savepath", "")])
        if get_fids:
            dir_file_list = account.ls_dir(get_fids[0]["fid"])["data"]["list"]
            dir_filename_list = [dir_file["file_name"] for dir_file in dir_file_list]
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
    account = Quark(config_data["cookie"][0])
    paths = []
    if path := request.args.get("path"):
        path = re.sub(r"/+", "/", path)
        if path == "/":
            fid = 0
        else:
            dir_names = path.split("/")
            if dir_names[0] == "":
                dir_names.pop(0)
            path_fids = []
            current_path = ""
            for dir_name in dir_names:
                current_path += "/" + dir_name
                path_fids.append(current_path)
            if get_fids := account.get_fids(path_fids):
                fid = get_fids[-1]["fid"]
                paths = [
                    {"fid": get_fid["fid"], "name": dir_name}
                    for get_fid, dir_name in zip(get_fids, dir_names)
                ]
            else:
                return jsonify({"success": False, "data": {"error": "获取fid失败"}})
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
    account = Quark(config_data["cookie"][0])
    if fid := request.json.get("fid"):
        response = account.delete([fid])
    else:
        response = {"success": False, "message": "缺失必要字段: fid"}
    return jsonify(response)
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
    user_info = session.get('user', {})
    if user_info.get('role') == 'user':
        username = user_info.get('username')
        if username:
            # 确保路径以斜杠开头且不重复
            if not save_path.startswith('/'):
                save_path = '/' + save_path
            save_path = f'/{username}{save_path}'
    
    if not fids or not stoken or not pwd_id:
        return jsonify({"success": False, "message": "Missing required parameters: fids, stoken, or pwd_id"})

    if len(fids) != len(fid_tokens):
        return jsonify({"success": False, "message": "Mismatch between fids and fid_tokens count"})

    account = Quark(config_data["cookie"][0])
    
    # 1. 获取或创建保存路径 ID
    save_path = re.sub(r"/{2,}", "/", f"/{save_path}")
    if save_path == "/":
         to_pdir_fid = "0"
    else:
        get_fids = account.get_fids([save_path])
        if get_fids:
            to_pdir_fid = get_fids[0]["fid"]
        else:
            # 尝试创建
            mkdir_res = account.mkdir(save_path)
            if mkdir_res["code"] == 0:
                to_pdir_fid = mkdir_res["data"]["fid"]
            else:
                return jsonify({"success": False, "message": f"Create save path failed: {mkdir_res.get('message')}"})
            
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
        alist_config = config_data.get("plugins", {}).get("alist", {})
        if not alist_config.get("url") or not alist_config.get("token"):
            return jsonify({"success": False, "message": "Alist 未配置"})
        
        # 获取存储信息
        url = f"{alist_config['url']}/api/admin/storage/list"
        headers = {"Authorization": alist_config['token']}
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

@app.route("/api/library/fs/list", methods=["POST"])
def get_fs_list():
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    
    try:
        data = request.json
        path = data.get("path", "/")
        
        # 根据用户角色调整路径
        user_info = session.get('user', {})
        if user_info.get('role') == 'user':
            username = user_info.get('username')
            if username:
                if not path.startswith('/'):
                    path = '/' + path
                path = f'/{username}{path}'
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

@app.route("/api/library/fs/get", methods=["POST"])
def get_file_info():
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    
    try:
        data = request.json
        path = data.get("path", "")
        
        # 根据用户角色调整路径
        user_info = session.get('user', {})
        if user_info.get('role') == 'user':
            username = user_info.get('username')
            if username:
                if not path.startswith('/'):
                    path = '/' + path
                path = f'/{username}{path}'
        password = data.get("password", "")
        
        alist_config = config_data.get("plugins", {}).get("alist", {})
        if not alist_config.get("url") or not alist_config.get("token"):
            return jsonify({"success": False, "message": "Alist 未配置"})
        
        # 获取文件信息
        url = f"{alist_config['url']}/api/fs/get"
        headers = {"Authorization": alist_config['token']}
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
        
        alist_config = config_data.get("plugins", {}).get("alist", {})
        if not alist_config.get("url") or not alist_config.get("token"):
            return jsonify({"success": False, "message": "Alist 未配置"})
        
        # 首先使用 POST 方法获取文件信息，包含 raw_url
        get_url = f"{alist_config['url']}/api/fs/get"
        headers = {"Authorization": alist_config['token']}
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
                    download_url = f"{alist_config['url']}/api/fs/download"
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
    logging.info(f"运行在: http://{HOST}:{PORT}")
    app.run(
        debug=DEBUG,
        host=HOST,
        port=PORT,
    )
