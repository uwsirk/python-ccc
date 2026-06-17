# -*- coding: utf-8 -*-
"""
密码管理器 - Web 版 v2
=======================
Flask + SQLite + cryptography 本地密码管理工具（浏览器端）

新增功能:
  - 会话自动锁定（10分钟无操作）
  - 密码分类（社交/邮箱/金融/购物/工作/学习/娱乐/其他）
  - 安全审计面板（弱密码/重复密码/过期密码检测）
  - 导入导出（CSV + 加密JSON备份）
  - 密码历史记录

启动方式:
    python app.py
    浏览器访问 http://localhost:5000
"""

import os
import io
import csv
import json
import time
from functools import wraps
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, Response, send_file,
)

import database as db
from crypto_utils import (
    derive_key, generate_salt, create_cipher,
    encrypt, decrypt, generate_password, check_password_strength,
)


# ============================================================
# Flask 应用初始化
# ============================================================

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 分钟

# 自动锁定时间（秒）
AUTO_LOCK_TIMEOUT = 600  # 10 分钟
AUTO_LOCK_WARNING = 540   # 9 分钟时前端开始警告


# ============================================================
# 会话自动锁定
# ============================================================

@app.before_request
def check_auto_lock():
    """检查会话是否超时，超时则自动登出。"""
    if not session.get('authenticated'):
        return None

    # 跳过 API 请求
    if request.path.startswith('/api/'):
        session['last_activity'] = time.time()
        return None

    now = time.time()
    last = session.get('last_activity', now)

    if now - last > AUTO_LOCK_TIMEOUT:
        session.clear()
        flash('🔒 长时间未操作，已自动锁定。请重新登录', 'warning')
        return redirect(url_for('login'))

    session['last_activity'] = now
    return None


@app.route('/api/session-status')
def api_session_status():
    """AJAX: 获取会话剩余时间。"""
    if not session.get('authenticated'):
        return jsonify({'authenticated': False, 'remaining': 0})
    last = session.get('last_activity', time.time())
    elapsed = time.time() - last
    remaining = max(0, AUTO_LOCK_TIMEOUT - int(elapsed))
    return jsonify({'authenticated': True, 'remaining': remaining})


# ============================================================
# 装饰器
# ============================================================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def first_run_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if db.is_first_run():
            return redirect(url_for('register'))
        return f(*args, **kwargs)
    return decorated


# ============================================================
# 辅助函数
# ============================================================

def get_cipher():
    master_pwd = session.get('master_password')
    if not master_pwd:
        return None
    salt_hex = db.get_setting('salt')
    salt = bytes.fromhex(salt_hex)
    key = derive_key(master_pwd, salt)
    return create_cipher(key)


# ============================================================
#  首页
# ============================================================

@app.route('/')
def index():
    if db.is_first_run():
        return redirect(url_for('register'))
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))


# ============================================================
#  注册
# ============================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if not db.is_first_run():
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')

        if len(password) < 6:
            flash('主密码至少需要 6 个字符', 'warning')
        elif password != confirm:
            flash('两次输入的密码不一致', 'warning')
        else:
            salt = generate_salt()
            key = derive_key(password, salt)
            cipher = create_cipher(key)
            token = encrypt(cipher, 'MASTER_PASSWORD_VERIFICATION')

            db.set_setting('salt', salt.hex())
            db.set_setting('verification_token', token)

            session['authenticated'] = True
            session['master_password'] = password
            session['last_activity'] = time.time()
            session.permanent = True

            flash('主密码设置成功！欢迎使用密码管理器', 'success')
            return redirect(url_for('dashboard'))

    return render_template('register.html')


# ============================================================
#  登录
# ============================================================

@app.route('/login', methods=['GET', 'POST'])
@first_run_required
def login():
    if request.method == 'POST':
        password = request.form.get('password', '')

        if not password:
            flash('请输入主密码', 'warning')
        else:
            try:
                salt_hex = db.get_setting('salt')
                token = db.get_setting('verification_token')
                salt = bytes.fromhex(salt_hex)
                key = derive_key(password, salt)
                cipher = create_cipher(key)

                if decrypt(cipher, token) == 'MASTER_PASSWORD_VERIFICATION':
                    session['authenticated'] = True
                    session['master_password'] = password
                    session['last_activity'] = time.time()
                    session.permanent = True
                    flash('登录成功', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('主密码错误', 'danger')
            except Exception:
                flash('验证失败，请重试', 'danger')

    return render_template('login.html')


# ============================================================
#  登出
# ============================================================

@app.route('/logout')
def logout():
    session.clear()
    flash('已安全退出', 'info')
    return redirect(url_for('login'))


# ============================================================
#  仪表盘（带分类筛选）
# ============================================================

@app.route('/dashboard')
@login_required
def dashboard():
    query = request.args.get('q', '').strip()
    category = request.args.get('category', '').strip() or None

    if query:
        entries = db.search_entries(query, category)
    else:
        entries = db.get_all_entries(category)

    # 计算密码年龄
    now = datetime.now()
    for entry in entries:
        updated = entry.get('updated_at', '')
        if updated:
            try:
                dt = datetime.strptime(updated[:19], '%Y-%m-%d %H:%M:%S')
                entry['age_days'] = (now - dt).days
            except Exception:
                entry['age_days'] = 0
        else:
            entry['age_days'] = 0

    cat_stats = db.get_category_stats()
    stats = db.get_stats()

    return render_template('index.html',
                           entries=entries, query=query,
                           current_category=category,
                           categories=db.CATEGORIES,
                           cat_stats=cat_stats, stats=stats,
                           auto_lock_timeout=AUTO_LOCK_TIMEOUT,
                           auto_lock_warning=AUTO_LOCK_WARNING)


# ============================================================
#  添加密码（含分类 + 强度 + 历史）
# ============================================================

@app.route('/entry/add', methods=['GET', 'POST'])
@login_required
def add_entry():
    if request.method == 'POST':
        website = request.form.get('website', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        notes = request.form.get('notes', '').strip()
        category = request.form.get('category', '其他').strip()

        errors = []
        if not website:
            errors.append('请输入网站/应用名称')
        if not username:
            errors.append('请输入用户名/邮箱')
        if not password:
            errors.append('请输入密码')
        if errors:
            for e in errors:
                flash(e, 'warning')
            return render_template('entry.html', entry=None,
                                   website=website, username=username,
                                   notes=notes, category=category)

        cipher = get_cipher()
        enc_pwd = encrypt(cipher, password)
        score, _ = check_password_strength(password)
        db.add_entry(website, username, enc_pwd, notes, category, score)

        flash(f'✅ 已添加: {website}', 'success')
        return redirect(url_for('dashboard'))

    return render_template('entry.html', entry=None, categories=db.CATEGORIES)


# ============================================================
#  编辑密码（含历史记录保存）
# ============================================================

@app.route('/entry/<int:entry_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_entry(entry_id):
    entry = db.get_entry(entry_id)
    if entry is None:
        flash('记录不存在', 'danger')
        return redirect(url_for('dashboard'))

    cipher = get_cipher()
    try:
        current_password = decrypt(cipher, entry['encrypted_password'])
    except Exception:
        current_password = ''

    if request.method == 'POST':
        website = request.form.get('website', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        notes = request.form.get('notes', '').strip()
        category = request.form.get('category', '其他').strip()

        errors = []
        if not website:
            errors.append('请输入网站/应用名称')
        if not username:
            errors.append('请输入用户名/邮箱')
        if not password:
            errors.append('请输入密码')
        if errors:
            for e in errors:
                flash(e, 'warning')
            return render_template('entry.html', entry=entry,
                                   website=website, username=username,
                                   notes=notes, category=category)

        # 如果密码有变化，保存旧密码到历史
        if password != current_password:
            db.add_password_history(entry_id, entry['encrypted_password'])

        enc_pwd = encrypt(cipher, password)
        score, _ = check_password_strength(password)
        db.update_entry(entry_id, website, username, enc_pwd, notes, category, score)

        flash(f'✅ 已更新: {website}', 'success')
        return redirect(url_for('dashboard'))

    return render_template('entry.html', entry=entry,
                           current_password=current_password,
                           categories=db.CATEGORIES)


# ============================================================
#  删除
# ============================================================

@app.route('/entry/<int:entry_id>/delete', methods=['POST'])
@login_required
def delete_entry(entry_id):
    entry = db.get_entry(entry_id)
    if entry is None:
        flash('记录不存在', 'danger')
    else:
        db.delete_entry(entry_id)
        flash(f'🗑 已删除: {entry["website"]}', 'info')
    return redirect(url_for('dashboard'))


# ============================================================
#  🔍 安全审计（新功能）
# ============================================================

@app.route('/audit')
@login_required
def audit():
    """安全审计：检测弱密码、重复密码、过期密码。"""
    cipher = get_cipher()
    rows = db.get_all_encrypted_passwords_with_meta()

    weak_passwords = []
    reused_passwords = []
    old_passwords = []
    seen_plain = {}  # plaintext → list of websites

    now = datetime.now()

    for entry in rows:
        try:
            plain = decrypt(cipher, entry['encrypted_password'])
        except Exception:
            continue

        eid = entry['id']
        website = entry['website']
        username = entry['username']
        score = entry.get('strength_score', 0)
        updated = entry.get('updated_at', '')

        # 弱密码检测
        if score <= 2:
            if not plain:
                score, label = check_password_strength(plain)
                db.update_entry(eid, website, username, entry['encrypted_password'],
                                db.get_entry(eid).get('notes', ''),
                                db.get_entry(eid).get('category', '其他'), score)
            weak_passwords.append({
                'id': eid, 'website': website, 'username': username,
                'score': score, 'length': len(plain),
            })

        # 重复密码检测
        if plain in seen_plain:
            if seen_plain[plain] is not None:
                reused_passwords.append(seen_plain[plain])
                seen_plain[plain] = None  # 标记已报告
            reused_passwords.append({
                'id': eid, 'website': website, 'username': username,
                'shared_with': '',
            })
        else:
            seen_plain[plain] = {
                'id': eid, 'website': website, 'username': username,
                'shared_with': '',
            }

        # 过期密码检测 (>90天未更新)
        try:
            dt = datetime.strptime(updated[:19], '%Y-%m-%d %H:%M:%S')
            age = (now - dt).days
            if age > 90:
                old_passwords.append({
                    'id': eid, 'website': website, 'username': username,
                    'age_days': age,
                })
        except Exception:
            pass

    # 完善重复密码的 shared_with
    for item in reused_passwords:
        for other in reused_passwords:
            if other['id'] != item['id']:
                item['shared_with'] = other['website']

    total = len(rows)
    safe_count = total - len(set(
        [w['id'] for w in weak_passwords] +
        [r['id'] for r in reused_passwords] +
        [o['id'] for o in old_passwords]
    ))

    # 安全评分
    if total == 0:
        score = 100
    else:
        score = max(0, min(100, round(safe_count / total * 100)))

    return render_template('audit.html',
                           weak_passwords=weak_passwords,
                           reused_passwords=reused_passwords,
                           old_passwords=old_passwords,
                           total_entries=total,
                           security_score=score,
                           score_color=_score_color(score))


def _score_color(score: int) -> str:
    if score >= 80:
        return 'success'
    elif score >= 50:
        return 'warning'
    return 'danger'


# ============================================================
#  📥📤 导入导出（新功能）
# ============================================================

@app.route('/export')
@login_required
def export_page():
    return render_template('export.html')


@app.route('/export/csv')
@login_required
def export_csv():
    """导出为未加密 CSV。"""
    cipher = get_cipher()
    entries = db.export_all_entries()

    output = io.StringIO()
    output.write('﻿')  # UTF-8 BOM for Excel
    writer = csv.writer(output)
    writer.writerow(['网站/应用', '用户名', '密码', '备注', '分类', '创建时间', '更新时间'])

    for e in entries:
        try:
            plain = decrypt(cipher, e['encrypted_password'])
        except Exception:
            plain = '[解密失败]'
        writer.writerow([
            e['website'], e['username'], plain, e.get('notes', ''),
            e.get('category', '其他'),
            (e.get('created_at', '') or '')[:19],
            (e.get('updated_at', '') or '')[:19],
        ])

    output.seek(0)
    return Response(
        output.getvalue().encode('utf-8-sig'),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment;filename=passwords_export.csv'}
    )


@app.route('/export/encrypted')
@login_required
def export_encrypted():
    """导出加密备份（JSON格式）。"""
    entries = db.export_all_entries()
    backup = {
        'version': db.SCHEMA_VERSION,
        'exported_at': datetime.now().isoformat(),
        'entries': [],
    }
    for e in entries:
        backup['entries'].append({
            'website': e['website'],
            'username': e['username'],
            'encrypted_password': e['encrypted_password'],
            'notes': e.get('notes', ''),
            'category': e.get('category', '其他'),
            'strength_score': e.get('strength_score', 0),
            'created_at': e.get('created_at', ''),
            'updated_at': e.get('updated_at', ''),
        })

    json_str = json.dumps(backup, ensure_ascii=False, indent=2)
    return Response(
        json_str,
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment;filename=passwords_backup.json'}
    )


@app.route('/import', methods=['POST'])
@login_required
def import_csv():
    """从 CSV 导入密码。"""
    file = request.files.get('file')
    if not file or not file.filename.endswith('.csv'):
        flash('请选择 CSV 文件', 'warning')
        return redirect(url_for('export_page'))

    try:
        content = file.read().decode('utf-8-sig')
        reader = csv.reader(io.StringIO(content))
        header = next(reader, None)

        if header is None:
            flash('CSV 文件为空', 'warning')
            return redirect(url_for('export_page'))

        cipher = get_cipher()
        imported = 0
        skipped = 0

        for row in reader:
            if len(row) < 3:
                skipped += 1
                continue
            website = row[0].strip()
            username = row[1].strip()
            password = row[2].strip()
            notes = row[3].strip() if len(row) > 3 else ''
            category = row[4].strip() if len(row) > 4 else '其他'

            if not website or not username or not password:
                skipped += 1
                continue

            enc_pwd = encrypt(cipher, password)
            score, _ = check_password_strength(password)
            db.add_entry(website, username, enc_pwd, notes, category, score)
            imported += 1

        flash(f'✅ 导入完成：{imported} 条成功，{skipped} 条跳过', 'success')
    except Exception as e:
        flash(f'导入失败: {e}', 'danger')

    return redirect(url_for('dashboard'))


# ============================================================
#  API 接口
# ============================================================

@app.route('/api/entry/<int:entry_id>/password')
@login_required
def api_get_password(entry_id):
    enc_pwd = db.get_encrypted_password(entry_id)
    if enc_pwd is None:
        return jsonify({'error': '记录不存在'}), 404
    try:
        cipher = get_cipher()
        plain = decrypt(cipher, enc_pwd)
        return jsonify({'password': plain})
    except Exception as e:
        return jsonify({'error': f'解密失败: {e}'}), 500


@app.route('/api/entry/<int:entry_id>/history')
@login_required
def api_get_history(entry_id):
    """获取密码历史记录。"""
    history = db.get_password_history(entry_id)
    cipher = get_cipher()
    result = []
    for h in history:
        try:
            plain = decrypt(cipher, h['encrypted_password'])
            masked = plain[:2] + '***' + plain[-2:] if len(plain) > 4 else '****'
        except Exception:
            masked = '[解密失败]'
        result.append({
            'changed_at': (h.get('changed_at', '') or '')[:19],
            'password_masked': masked,
        })
    return jsonify(result)


@app.route('/api/generate-password')
@login_required
def api_generate_password():
    length = request.args.get('length', 16, type=int)
    length = max(8, min(64, length))
    pwd = generate_password(length)
    score, label = check_password_strength(pwd)
    return jsonify({'password': pwd, 'strength': score, 'strength_label': label})


@app.route('/api/check-strength')
@login_required
def api_check_strength():
    pwd = request.args.get('password', '')
    score, label = check_password_strength(pwd)
    return jsonify({'strength': score, 'strength_label': label})


@app.route('/api/stats')
@login_required
def api_stats():
    """获取仪表盘统计数据。"""
    stats = db.get_stats()
    cat_stats = db.get_category_stats()
    return jsonify({
        'total': stats['total_entries'],
        'categories': stats['total_categories'],
        'category_breakdown': cat_stats,
    })


# ============================================================
#  修改主密码
# ============================================================

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form.get('current', '')
        new = request.form.get('new', '')
        confirm = request.form.get('confirm', '')

        if not current or not new or not confirm:
            flash('请填写所有字段', 'warning')
        elif new != confirm:
            flash('两次输入的新密码不一致', 'warning')
        elif len(new) < 6:
            flash('新主密码至少需要 6 个字符', 'warning')
        elif current == new:
            flash('新密码与当前密码相同', 'warning')
        else:
            old_cipher = get_cipher()
            try:
                token = db.get_setting('verification_token')
                if decrypt(old_cipher, token) != 'MASTER_PASSWORD_VERIFICATION':
                    flash('当前主密码验证失败', 'danger')
                    return render_template('change_password.html')
            except Exception:
                flash('当前主密码验证失败', 'danger')
                return render_template('change_password.html')

            try:
                new_salt = generate_salt()
                new_key = derive_key(new, new_salt)
                new_cipher = create_cipher(new_key)
                new_token = encrypt(new_cipher, 'MASTER_PASSWORD_VERIFICATION')

                entries = db.get_all_entries()
                for entry in entries:
                    full = db.get_entry(entry['id'])
                    plain_pwd = decrypt(old_cipher, full['encrypted_password'])
                    new_enc = encrypt(new_cipher, plain_pwd)
                    db.update_entry(
                        entry['id'], full['website'], full['username'],
                        new_enc, full.get('notes', ''),
                        full.get('category', '其他'),
                        full.get('strength_score', 0),
                    )

                db.set_setting('salt', new_salt.hex())
                db.set_setting('verification_token', new_token)
                session['master_password'] = new
                session['last_activity'] = time.time()

                flash('✅ 主密码修改成功！所有数据已用新密钥加密', 'success')
                return redirect(url_for('dashboard'))
            except Exception as e:
                flash(f'修改失败: {e}', 'danger')

    return render_template('change_password.html')


# ============================================================
#  启动
# ============================================================

def main():
    db.init_db()
    print('=' * 55)
    print('  🔐 密码管理器 v2 (Web版)')
    print(f'  访问地址: http://localhost:5000')
    print(f'  自动锁定: {AUTO_LOCK_TIMEOUT // 60} 分钟无操作')
    print(f'  新功能: 分类 | 审计 | 导入导出 | 密码历史 | 自动锁定')
    print('  按 Ctrl+C 停止服务器')
    print('=' * 55)
    app.run(host='127.0.0.1', port=5000, debug=True)


if __name__ == '__main__':
    main()
