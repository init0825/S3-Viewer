from flask import Flask, jsonify, request, send_file, render_template, redirect, url_for,session,Response
from megfile import smart_glob, smart_open, smart_isdir, smart_isfile,smart_stat,smart_scandir
import mimetypes
import os
import traceback
import cv2
import numpy as np
import tempfile
import shutil
import io
from urllib.parse import urlparse
from dotenv import load_dotenv
import requests
from datetime import timedelta, datetime,timezone
from functools import wraps
import re
import logging
import redis
from flask_session import Session
import json
import hashlib
import subprocess
import threading

#这个用来作数据缓存
r=redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
TENANT_TOKEN_KEY = "feishu_tenant_access_token"
USER_TOKEN_KEY ="feishu_user_access_token"

#这个用来做用户登录态缓存
redis_client = redis.Redis(host='localhost', port=6379, db=1)

#加logger调试
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('debug.log', encoding='utf-8', mode='a') 
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
fh.setFormatter(formatter)

load_dotenv()
app = Flask(__name__)
app.secret_key=os.getenv('FLASK_SECRET_KEY')

# --- Flask-Session 配置 ---
app.config['SESSION_TYPE'] = 'redis'         # 指定后端为 redis
app.config['SESSION_REDIS'] = redis_client   # 传入连接实例
app.config['SESSION_USE_SIGNER'] = True      # 对 Cookie 中的 session_id 进行签名
app.config['SESSION_KEY_PREFIX'] = 'sess:'   # Redis 中 key 的前缀

# 设置 Session 的有效期
session_hours = int(os.getenv('SESSION_HOURS', 48))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=session_hours)

# 初始化 Session 扩展
Session(app)

#===================== 配置区 ===================#
# 根目录配置
ROOT_BUCKET = os.getenv('ROOT_BUCKET')

SUPPORTED_EXTENSIONS = {
    # 图片
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg',
    # 视频
    '.mp4', '.webm', '.mov', '.ogg', '.mkv',
    # 文本/代码
    '.json', '.jsonl', '.md', '.py', '.js', '.log', '.csv', '.sh', '.yml', '.yaml', '.txt', '.xml',
    # 文档
    '.pdf'
}

# 注册常见类型
for ext in ['.json', '.jsonl', '.md', '.py', '.js', '.log', '.csv', '.sh', '.yml', '.yaml']:
    mimetypes.add_type('text/plain', ext)
mimetypes.add_type('application/pdf', '.pdf')
mimetypes.add_type('video/x-matroska', '.mkv')

APP_ID = os.getenv('APP_ID')         
APP_SECRET = os.getenv('APP_SECRET') 
# 确保此地址与飞书后台一致
REDIRECT_URI = os.getenv('REDIRECT_URI')
app.secret_key = os.getenv("FLASK_SECRET_KEY")
session_hours = int(os.getenv('SESSION_HOURS', 12))
app.permanent_session_lifetime = timedelta(hours=session_hours)

# === 全局请求拦截 ===
@app.before_request
def check_login():
    # 1. 白名单
    allow_list = ['static', 'login', 'callback', 'logout']

    # 2. 如果当前请求的 Endpoint 在白名单里，直接放行
    if request.endpoint in allow_list:
        return None

    user_info = session.get('user_info')
    created_at = session.get('created_at')
    # 3. 检查 Session (核心鉴权逻辑)
    if not user_info:
        # 3.1 如果是 API 请求，返回 401 JSON (方便前端处理刷新)
        if request.path.startswith('/api/'):
            return jsonify({"status": "error", "message": "Unauthorized", "code": 401}), 401
        
        # 3.2 如果是普通页面请求，跳转去飞书认证
        # 记录用户原本想去的 URL，存入 next 参数
        next_url = request.url
        return redirect(url_for('login', next=next_url))
    
    if created_at is None:
        # 如果没有时间戳（旧 Session），为了安全，强制重新登录
        # 或者也可以选择在这里补一个：session['created_at'] = datetime.now(timezone.utc).timestamp()
        logger.warning(f"用户 {user_info.get('name')} 的 Session 缺少创建时间，强制重连")
        session.clear()
        return redirect(url_for('login', next=request.url))
    #超过7天强制退出
    start_time = datetime.fromtimestamp(created_at, tz=timezone.utc)
    now = datetime.now(timezone.utc)
    if now - start_time > timedelta(days=7):
        logger.info(f"Session 达到 7 天硬上限，强制退出。用户: {user_info.get('name')}")
        session.clear()  # 清空 Redis 中的数据
        return redirect(url_for('login')) # 强制重新登录

    # 4. 如果没超过 7 天，Flask-Session 会在响应时自动把 Redis TTL 重置为 48 小时

def feishu_auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session['user_info'].get('open_id')
        
        # 1. 尝试从 Redis 获取缓存的 Token
        tenant_access_token = r.get(TENANT_TOKEN_KEY)
        remaining_ttl = r.ttl(TENANT_TOKEN_KEY) # 返回剩余秒数

        # 2. 如果 Token 不存在，或者有效期不足 30 分钟 (1800秒)
        if not tenant_access_token or remaining_ttl < 1800:
            logger.info("Token 不存在或即将过期，正在重新获取...")
            tenant_url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
            
            try:
                tenant_resp = requests.post(
                    tenant_url,
                    headers={"Content-Type": "application/json; charset=utf-8"},
                    json={
                        "app_id": APP_ID,
                        "app_secret": APP_SECRET
                    }
                )
                tenant_data = tenant_resp.json()
                
                if tenant_data.get("code") == 0:
                    tenant_access_token = tenant_data.get("tenant_access_token")
                    # expire 单位通常是秒
                    expire_seconds = tenant_data.get("expire")
                    
                    # 3. 将新 Token 写入 Redis，设置过期时间
                    r.set(TENANT_TOKEN_KEY, tenant_access_token, ex=expire_seconds)
                    logger.info(f"Token 已更新，现过期时间: {expire_seconds}s")
                else:
                    logger.error(f"获取 Tenant Token 失败: {tenant_data.get('msg')}")
                    return jsonify({"status": "error", "message": "Auth Config Error"}), 500
            except Exception as e:
                logger.error(f"API 请求异常: {str(e)}")
                return jsonify({"status": "error", "message": "Network Error"}), 500
        
        # 4. 执行后续的权限检查逻辑
        quanxian=r.get(USER_TOKEN_KEY)
        ramaining_ttl2=r.ttl(USER_TOKEN_KEY)
        #十分钟内无需再次检查
        if not quanxian or ramaining_ttl2 ==0:
            logger.info("User Token不存在或过期，正在重新校验...")

            feishu_quanxian_url = (
                f"https://open.feishu.cn/open-apis/application/v6/applications/{APP_ID}/visibility/check_white_black_list?user_id_type=open_id")
            
            feishu_resp = requests.post(
                feishu_quanxian_url,
                headers={
                    "Authorization": f"Bearer {tenant_access_token}",
                    "Content-Type": "application/json; charset=utf-8"
                },
                json={"user_ids": [user_id]}
            )
            
            resp_data = feishu_resp.json()
            if resp_data.get("code") != 0:
                logger.error(f"检查权限失败: {resp_data.get('msg')}")
                return redirect(url_for('login'))

            user_info_list = resp_data.get("data", {}).get("user_visibility_list", [])
            quanxian = user_info_list[0].get("in_white_list", False)
            if not user_info_list or not quanxian:
                session.clear()
                return redirect(url_for('login'))
            
            r.set(USER_TOKEN_KEY,int(quanxian),ex=600)
            return f(*args, **kwargs)
        return f(*args, **kwargs)
    
    return decorated_function

# === 飞书认证路由 ===

@app.route('/login')
def login():
    """跳转到飞书认证页"""
    # 获取用户原本想去的地址，如果没有则默认为首页
    next_url = request.args.get('next', '/')
    # 将 next_url 存入 session，以便 callback 使用，或者也可以放在 state 参数里传给飞书
    session['final_redirect'] = next_url
    
    # 构造飞书登录链接
    feishu_auth_url = (
        f"https://open.feishu.cn/open-apis/authen/v1/index?"
        f"app_id={APP_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"state=STATE"
    )
    return redirect(feishu_auth_url)

@app.route('/callback')
def callback():
    #注：无权限会直接被飞书拦住，不会进入回调
    code = request.args.get('code')
    if not code:
        return "未收到code", 400

    try:
        # 第一步：拿App Token
        app_token_url = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal"
        app_resp = requests.post(app_token_url, json={
            "app_id": APP_ID, 
            "app_secret": APP_SECRET
        })
        app_data = app_resp.json()
        if app_data.get("code") != 0:
            return f"Feishu App Token Error: {app_data.get('msg')}", 500
        
        app_access_token = app_data.get("app_access_token")

        # 第二步：拿user Token和用户身份 (open_id)
        user_token_url = "https://open.feishu.cn/open-apis/authen/v1/access_token"
        user_resp = requests.post(
            user_token_url,
            headers={"Authorization": f"Bearer {app_access_token}"},
            json={"grant_type": "authorization_code", "code": code}
        )
        user_data = user_resp.json()
        
        if user_data.get("data", {}).get("open_id"):
            # === 认证成功 ===
            # 1. 设置 session 有效 (遵循 app.permanent_session_lifetime 配置)
            session.permanent = True
            
            # 2. 保存用户信息到 session
            user_info = user_data.get("data")
            session['user_info'] = {
                'name': user_info.get('name', 'Feishu User'),
                'open_id': user_info.get('open_id'),
                'avatar': user_info.get('avatar_url'),
                'app_access_token': app_access_token,
                'code':code
            }
            
            if 'created_at' not in session:
                session['created_at'] = datetime.now(timezone.utc).timestamp()
            
            # 记录登录历史
            current_time=datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
            username=user_info.get('name', 'Feishu User')
            sessionTime=app.permanent_session_lifetime
            log_line=f"[{current_time}] 用户 '{username}' 登录成功，Session 有效期: {sessionTime}\n"
            with open("loginHistory.log","a",encoding="utf-8") as f:
                f.write(log_line)

            # 3. 获取之前记录的跳转地址，如果没有则回首页
            final_redirect = session.pop('final_redirect', url_for('index'))
            return redirect(final_redirect)
        else:
            return "<h3>认证失败：无法获取用户信息，请检查您是否在应用的可用范围内。</h3>", 403

    except Exception as e:
        traceback.print_exc()
        return f"Login Process Error: {str(e)}", 500

@app.route('/logout')
def logout():
    """登出"""
    session.clear()
    return redirect(url_for('login'))

def parse_tos_to_s3(address):
    """辅助函数：将 tos:// 或 https://tos... 转为 s3://"""
    if not address:
        return None
    
    # 1. 处理 HTTPS 格式
    # 例如: https://dexmal-sharefs-pdd.tos-cn-beijing.volces.com/path/file.ext
    if address.startswith('http'):
        try:
            parsed = urlparse(address)
            # hostname: dexmal-sharefs-pdd.tos-cn-beijing.volces.com
            hostname = parsed.hostname
            # path: /path/file.ext
            path_name = parsed.path
            
            # 假设 Bucket 是 hostname 的第一部分
            if hostname:
                bucket_name = hostname.split('.')[0]
                return f"s3://{bucket_name}{path_name}"
        except:
            pass
    
    # 2. 处理 tos:// 格式
    if address.startswith('tos://'):
        return address.replace('tos://', 's3://')
    
    # 3. 已经是 s3://
    if address.startswith('s3://'):
        return address
        
    return None

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>') 
def index(path):
    if path.startswith('api/'):
        return "API endpoint not found", 404
    
    #拦截直接带tos路径的，统一传参处理
    if 'tos:/' in path:
        # 1. 找到 tos:/ 出现的位置
        start_idx = path.find('tos:/')
        # 2. 提取它之前的部分作为 bucket 路径 (例如 "dexmal-sa-xzh-data/")
        prefix_path = path[:start_idx].rstrip('/')
        # 3. 提取它之后的部分作为真正的 tos 地址 (例如 "tos://dexmal-sa-xzh-data/sample.pdf")
        # 确保格式是 tos:// (补齐斜杠)
        raw_tos = path[start_idx:]
        tos_addr = raw_tos.replace('tos:/', 'tos://', 1) if 'tos://' not in raw_tos else raw_tos
        
        # 4. 强制重定向到规范的参数格式
        return redirect(url_for('index', path=prefix_path, tos_address=tos_addr))

   # 1. 优先获取参数中的 tos_address
    tos_address = request.args.get('tos_address')
    
    # 2. 增强型 Bucket 判定逻辑
    current_root = ROOT_BUCKET # 默认值
    
    if tos_address:
        # 如果传了 tos_address，尝试从中提取 bucket
        # 例如: tos://dexmal-sa-xzh-data/sample.pdf -> s3://dexmal-sa-xzh-data
        s3_full = parse_tos_to_s3(tos_address)
        if s3_full:
            # 找到 s3:// 后的第一个路径段
            parts = s3_full.replace('s3://', '').split('/')
            if parts[0]:
                current_root = f"s3://{parts[0]}"
                logger.info(f"从参数提取到 Bucket: {current_root}")

    elif path and not path.startswith('tos:/'):
       path_parts = path.strip('/').split('/')
       if path_parts[0]:
            bucket_name = path_parts[0]
            current_root = f"s3://{bucket_name}"
            logger.info(f"从路径提取到根 Bucket: {current_root}")
    
    init_path = current_root
    init_preview_file = "" # 默认不自动预览

    if tos_address:
        # 转换为标准 s3 路径
        s3_full_path = parse_tos_to_s3(tos_address)

        if s3_full_path:
            if smart_isfile(s3_full_path):
                # -> 是文件
                # init_path 设为父目录
                init_path = os.path.dirname(s3_full_path)
                # init_preview_file 设为该文件路径
                init_preview_file = s3_full_path
            else:
                # -> 是目录
                init_path = s3_full_path
                init_preview_file = ""

    # 将两个变量注入模板
    return render_template('index.html', 
                           root_bucket=current_root, 
                           init_path=init_path,
                           init_preview_file=init_preview_file,
                           user=session.get('user_info')
                           )


@app.route('/api/list', methods=['GET'])
def list_files():
    req_path = request.args. get('path', '')
    page = request.args.get('page', 1, type=int)
    page_size = request. args.get('page_size', 100, type=int)
    
    page_size = min(max(page_size, 10), 500)
    
    if 'tos: /' in req_path: 
        req_path = req_path.replace('tos://', 's3://').replace('tos: /', 's3://')

    if req_path.startswith('s3://'):
        full_path = req_path
    else:
        clean_rel_path = req_path.lstrip('/')
        if not clean_rel_path:
            full_path = ROOT_BUCKET
        else:
            full_path = os.path.join(ROOT_BUCKET, clean_rel_path)
    full_path = full_path.rstrip('/')

    try:
        # 生成缓存 key
        cache_key = f"dirlist:{hashlib.md5(full_path.encode()).hexdigest()}"
        
        # 尝试从缓存获取
        cached_data = r.get(cache_key)
        
        if cached_data:
            # 缓存命中，直接使用
            all_entries = json. loads(cached_data)
        else:
            # 缓存未命中，遍历目录
            all_entries = []
            for entry in smart_scandir(full_path):
                all_entries.append({
                    "name": entry.name,
                    "path": entry.path,
                    "is_dir": entry. is_dir()
                })
            
            # 排序：文件夹在前，然后按名称排序
            all_entries.sort(key=lambda x: (not x['is_dir'], x['name']))
            
            # 写入缓存，设置5分钟过期
            r.set(cache_key, json.dumps(all_entries), ex=300)
        
        # 计算分页
        total_count = len(all_entries)
        total_pages = (total_count + page_size - 1) // page_size
        total_pages = max(total_pages, 1)
        page = max(1, min(page, total_pages))
        
        # 切片获取当前页数据
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        page_entries = all_entries[start_idx:end_idx]
        
        return jsonify({
            "status": "success",
            "current_path": full_path,
            "data": page_entries,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_count": total_count,
                "total_pages": total_pages,
                "has_prev": page > 1,
                "has_next": page < total_pages
            }
        })
    except Exception as e: 
        traceback.print_exc()
        return jsonify({"status":  "error", "message": str(e)}), 500

def stream_file(path, mime_type):
    """支持 Range 请求的流式传输函数"""
    try:
        # 1. 获取文件大小
        file_stat = smart_stat(path)
        file_size = file_stat.st_size  # <--- 修正：直接访问 .st_size
        
        # 2. 处理 Range 头
        range_header = request.headers.get('Range', None)
        if not range_header:
            # 如果没有 Range 头，直接返回整个文件流
            file_obj = smart_open(path, 'rb')
            return send_file(file_obj, mimetype=mime_type)

        # 3. 解析 Range (格式: bytes=0-1024)
        byte1, byte2 = 0, None
        m = range_header.replace('bytes=', '').split('-')
        if m[0]: byte1 = int(m[0])
        if m[1]: byte2 = int(m[1])
        
        # 计算长度
        if byte2 is None:
            byte2 = file_size - 1
        length = byte2 - byte1 + 1

        # 4. 读取指定范围的数据
        # smart_open 支持 seek，所以我们可以跳到指定位置读取
        file_obj = smart_open(path, 'rb')
        file_obj.seek(byte1)
        data = file_obj.read(length)
        
        # 5. 返回部分内容 (206 Partial Content)
        rv = Response(data, 206, mimetype=mime_type, direct_passthrough=True)
        rv.headers.add('Content-Range', f'bytes {byte1}-{byte2}/{file_size}')
        rv.headers.add('Accept-Ranges', 'bytes')
        return rv

    except Exception as e:
        traceback.print_exc()
        return f"Stream Error: {str(e)}", 500

def stream_mkv_to_mp4(path):
    # 1. 准备 FFmpeg 命令
    # 注意：输入变成了 'pipe:0'，表示从标准输入读取数据
    command = [
        'ffmpeg',
        '-y',
        '-i', 'pipe:0',        # <--- 关键修改：从管道读取输入
        '-c:v', 'libx264',
        '-preset', 'ultrafast',
        '-tune', 'zerolatency',
        '-vf', 'scale=-2:720,format=yuv420p',
        '-g', '30',            # 关键：设置关键帧间隔为30，方便流式切片
        '-c:a', 'aac',
        '-ac', '2',
        '-ar', '44100',
        '-f', 'mp4',
        '-movflags', 'frag_keyframe+empty_moov+default_base_moof',
        'pipe:1'               # 输出到标准输出
    ]

    # 2. 启动 FFmpeg 进程
    # stdin=subprocess.PIPE 允许我们写入数据
    process = subprocess.Popen(
        command, 
        stdin=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE # 依然建议捕获 stderr 以防占满缓冲区
    )

    # 3. 定义写入线程：负责从 S3 读取数据并喂给 FFmpeg
    def write_input_to_ffmpeg():
        try:
            # 使用 smart_open 打开远程文件 (它处理了 s3/tos 认证)
            with smart_open(path, 'rb') as src_file:
                while True:
                    # 每次读取 64KB
                    chunk = src_file.read(64 * 1024)
                    if not chunk:
                        break
                    # 写入 FFmpeg 的 stdin
                    try:
                        process.stdin.write(chunk)
                    except (BrokenPipeError, OSError):
                        # 如果 FFmpeg 挂了或退出了，停止写入
                        break
        except Exception as e:
            print(f"Read S3 Error: {e}")
        finally:
            # 写完后一定要关闭 stdin，告诉 FFmpeg "文件结束了"
            try:
                process.stdin.close()
            except:
                pass

    # 启动后台线程进行写入，这样不会阻塞主线程的读取
    writer_thread = threading.Thread(target=write_input_to_ffmpeg, daemon=True)
    writer_thread.start()

    # 4. 定义生成器：读取 FFmpeg 的转码结果并返回给浏览器
    def generate():
        try:
            # 专门开一个线程或者非阻塞读取 stderr 比较麻烦，
            # 这里简单处理：如果 stdout 没数据，可能就是报错了。
            while True:
                chunk = process.stdout.read(64 * 1024)
                if not chunk:
                    # 检查是否正常退出
                    if process.poll() is not None:
                        break
                    # 如果进程还在但读不到数据，可能是刚开始或正在缓冲，短暂休眠避免死循环空转
                    # 但通常 read 是阻塞的，所以这里没拿到 chunk 基本就是结束了
                    break
                yield chunk
        finally:
            # 清理：确保杀死进程
            if process.poll() is None:
                process.kill()

    headers = {
        'Content-Type': 'video/mp4',
        'Cache-Control': 'no-cache',
    }
    
    return Response(generate(), mimetype='video/mp4', headers=headers)

@app.route('/api/preview', methods=['GET'])
@feishu_auth_required
def preview_file():
    path = request.args.get('path')
    if not path: return "Path required", 400
    if 'tos:/' in path: path = path.replace('tos://', 's3://').replace('tos:/', 's3://')

    try:
        ext = os.path.splitext(path)[1].lower()
        if ext not in SUPPORTED_EXTENSIONS:
            return "此文件格式不支持在线预览，感谢支持！", 200

        # === 针对视频文件，使用流式传输 ===
        if ext in ['.mp4','.mkv']:
            if ext == '.mkv':
                # MKV 不支持 Range 请求下的直接播放，调用实时转流
                return stream_mkv_to_mp4(path)
            
            # MP4 维持原有的 Range 流式传输
            mime_type, _ = mimetypes.guess_type(path)
            if not mime_type: mime_type = 'application/octet-stream'
            return stream_file(path, mime_type)

        # === 其他文件 (图片/文本) ===
        mime_type, _ = mimetypes.guess_type(path)
        if not mime_type: mime_type = 'text/plain'
        file_obj = smart_open(path, 'rb')
        return send_file(file_obj, mimetype=mime_type)

    except Exception as e:
        traceback.print_exc()
        return str(e), 500

if __name__ == '__main__':
    app.url_map.merge_slashes = False
    app.run(host='0.0.0.0', port=3030, debug=False)