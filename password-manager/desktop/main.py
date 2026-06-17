# -*- coding: utf-8 -*-
"""密码管理器 - 桌面版 (tkinter)"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))

import tkinter as tk
from tkinter import ttk, messagebox
import database as db
from crypto_utils import *

class LoginWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title('密码管理器 - 登录')
        self.root.configure(bg='#f5f6fa')
        self.root.geometry('420x400')
        self.root.resizable(False, False)
        self.cipher = None
        self.attempts = 0
        self._build_ui()

    def _build_ui(self):
        f = tk.Frame(self.root, bg='#f5f6fa')
        f.pack(pady=(35,15))
        tk.Label(f, text='🔐 密码管理器', font=('Microsoft YaHei',22,'bold'), bg='#f5f6fa', fg='#2c3e50').pack()
        tk.Label(f, text='本地安全存储您的所有密码', font=('Microsoft YaHei',9), bg='#f5f6fa', fg='#95a5a6').pack(pady=(5,0))
        self.mf = tk.Frame(self.root, bg='#f5f6fa')
        self.mf.pack(pady=10, padx=45, fill=tk.X)
        if db.is_first_run():
            self._reg_ui()
        else:
            self._login_ui()

    def _reg_ui(self):
        tk.Label(self.mf, text='🔒 首次使用，请设置主密码\n主密码用于加密所有数据，请务必牢记！', font=('Microsoft YaHei',9), bg='#f5f6fa', fg='#e74c3c', justify=tk.LEFT).pack(pady=(0,15), anchor='w')
        tk.Label(self.mf, text='主密码', font=('Microsoft YaHei',10,'bold'), bg='#f5f6fa').pack(anchor='w')
        self.pwd = tk.StringVar()
        ttk.Entry(self.mf, textvariable=self.pwd, show='*', font=('Microsoft YaHei',11)).pack(fill=tk.X, ipady=4, pady=(3,12))
        tk.Label(self.mf, text='确认主密码', font=('Microsoft YaHei',10,'bold'), bg='#f5f6fa').pack(anchor='w')
        self.cfm = tk.StringVar()
        ttk.Entry(self.mf, textvariable=self.cfm, show='*', font=('Microsoft YaHei',11)).pack(fill=tk.X, ipady=4, pady=(3,10))
        self.sv = tk.StringVar()
        self.sl = tk.Label(self.mf, textvariable=self.sv, font=('Microsoft YaHei',9), bg='#f5f6fa')
        self.sl.pack()
        self.pwd.trace_add('write', self._strength)
        ttk.Button(self.mf, text='设 置 主 密 码', command=self._create).pack(fill=tk.X, ipady=6, pady=(8,0))
        self.pwd.focus_set()

    def _login_ui(self):
        tk.Label(self.mf, text='主密码', font=('Microsoft YaHei',10,'bold'), bg='#f5f6fa').pack(anchor='w')
        self.pwd = tk.StringVar()
        ttk.Entry(self.mf, textvariable=self.pwd, show='*', font=('Microsoft YaHei',11)).pack(fill=tk.X, ipady=4, pady=(3,10))
        self.ev = tk.StringVar()
        tk.Label(self.mf, textvariable=self.ev, font=('Microsoft YaHei',9), bg='#f5f6fa', fg='#e74c3c').pack()
        ttk.Button(self.mf, text='🔓 解 锁', command=self._verify).pack(fill=tk.X, ipady=6, pady=(8,0))
        self.pwd.focus_set()
        self.pwd.bind('<Return>', lambda e: self._verify())

    def _strength(self, *args):
        p = self.pwd.get()
        if not p: self.sv.set(''); return
        s, l = check_password_strength(p)
        colors = {0:'#e74c3c',1:'#e67e22',2:'#f39c12',3:'#2ecc71',4:'#27ae60',5:'#27ae60'}
        bars = {0:'○○○○○',1:'●○○○○',2:'●●○○○',3:'●●●○○',4:'●●●●○',5:'●●●●●'}
        self.sv.set(f'密码强度: {bars[s]}  {l}')
        self.sl.config(fg=colors[s])

    def _create(self):
        p = self.pwd.get().strip(); c = self.cfm.get().strip()
        if len(p) < 6: messagebox.showwarning('警告','主密码至少需要 6 个字符！'); return
        if p != c: messagebox.showwarning('警告','两次输入的密码不一致！'); return
        salt = generate_salt(); key = derive_key(p, salt); cipher = create_cipher(key)
        db.set_setting('salt', salt.hex())
        db.set_setting('verification_token', encrypt(cipher, 'MASTER_PASSWORD_VERIFICATION'))
        self.cipher = cipher; self.root.destroy()

    def _verify(self):
        p = self.pwd.get().strip()
        if not p: self.ev.set('请输入主密码'); return
        try:
            salt = bytes.fromhex(db.get_setting('salt'))
            key = derive_key(p, salt); cipher = create_cipher(key)
            if decrypt(cipher, db.get_setting('verification_token')) == 'MASTER_PASSWORD_VERIFICATION':
                self.cipher = cipher; self.root.destroy()
            else: self._fail()
        except: self._fail()

    def _fail(self):
        self.attempts += 1; r = 3 - self.attempts
        if r > 0: self.ev.set(f'❌ 主密码错误！还剩 {r} 次机会'); self.pwd.set(''); self.pwd.focus_set()
        else: messagebox.showerror('已锁定','尝试次数过多，程序即将退出。'); self.root.destroy()

    def run(self):
        self.root.mainloop()
        return self.cipher

class EntryDialog:
    def __init__(self, parent, cipher, entry=None):
        self.cipher = cipher; self.entry = entry; self.result = None
        self.dlg = tk.Toplevel(parent)
        self.dlg.title('编辑密码' if entry else '添加密码')
        self.dlg.configure(bg='#f5f6fa')
        self.dlg.geometry('470x400'); self.dlg.resizable(False, False)
        self.dlg.transient(parent); self.dlg.grab_set()
        self._build(); self.dlg.wait_window()

    def _build(self):
        self.wv = tk.StringVar(value=self.entry['website'] if self.entry else '')
        self.uv = tk.StringVar(value=self.entry['username'] if self.entry else '')
        self.pv = tk.StringVar()
        self.nv = tk.StringVar(value=self.entry.get('notes','') if self.entry else '')
        self.show = tk.BooleanVar(value=False)

        tk.Label(self.dlg, text='网站 / 应用', font=('Microsoft YaHei',10,'bold'), bg='#f5f6fa').pack(anchor='w', padx=35, pady=(20,0))
        ttk.Entry(self.dlg, textvariable=self.wv, font=('Microsoft YaHei',11)).pack(padx=35, fill=tk.X, ipady=4, pady=(3,10))
        tk.Label(self.dlg, text='用户名 / 邮箱', font=('Microsoft YaHei',10,'bold'), bg='#f5f6fa').pack(anchor='w', padx=35)
        ttk.Entry(self.dlg, textvariable=self.uv, font=('Microsoft YaHei',11)).pack(padx=35, fill=tk.X, ipady=4, pady=(3,10))
        tk.Label(self.dlg, text='密码', font=('Microsoft YaHei',10,'bold'), bg='#f5f6fa').pack(anchor='w', padx=35)
        pf = tk.Frame(self.dlg, bg='#f5f6fa'); pf.pack(padx=35, pady=(3,0), fill=tk.X)
        self.pe = ttk.Entry(pf, textvariable=self.pv, show='*', font=('Microsoft YaHei',11))
        self.pe.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=4)
        self.eb = tk.Button(pf, text='👁', width=4, relief=tk.FLAT, bg='#e0e0e0', command=self._toggle)
        self.eb.pack(side=tk.LEFT, padx=(5,0))
        tk.Button(pf, text='🎲', width=4, relief=tk.FLAT, bg='#e0e0e0', command=self._gen).pack(side=tk.LEFT, padx=(5,0))
        if self.entry:
            try: self.pv.set(decrypt(self.cipher, self.entry['encrypted_password']))
            except: pass
        else: self._gen()
        self.sv2 = tk.StringVar(); self.sl2 = tk.Label(self.dlg, textvariable=self.sv2, font=('Microsoft YaHei',9), bg='#f5f6fa')
        self.sl2.pack(anchor='w', padx=35, pady=(2,0)); self.pv.trace_add('write', self._strength); self._strength()
        tk.Label(self.dlg, text='备注（可选）', font=('Microsoft YaHei',10,'bold'), bg='#f5f6fa').pack(anchor='w', padx=35, pady=(5,0))
        ttk.Entry(self.dlg, textvariable=self.nv, font=('Microsoft YaHei',11)).pack(padx=35, fill=tk.X, ipady=4, pady=(3,15))
        bf = tk.Frame(self.dlg, bg='#f5f6fa'); bf.pack(pady=(0,20), padx=35, fill=tk.X)
        ttk.Button(bf, text='取消', command=self.dlg.destroy).pack(side=tk.RIGHT, padx=(8,0))
        ttk.Button(bf, text='💾 保存', command=self._save).pack(side=tk.RIGHT)

    def _toggle(self):
        s = not self.show.get(); self.show.set(s); self.pe.config(show='' if s else '*'); self.eb.config(text='🙈' if s else '👁')

    def _gen(self):
        p = generate_password(); self.pv.set(p); self.show.set(True); self.pe.config(show=''); self.eb.config(text='🙈')

    def _strength(self, *args):
        p = self.pv.get()
        if not p: self.sv2.set(''); return
        s, l = check_password_strength(p)
        colors = {0:'#e74c3c',1:'#e67e22',2:'#f39c12',3:'#2ecc71',4:'#27ae60',5:'#27ae60'}
        self.sv2.set(f'密码强度: {l}'); self.sl2.config(fg=colors.get(s,'#000'))

    def _save(self):
        w = self.wv.get().strip(); u = self.uv.get().strip(); p = self.pv.get(); n = self.nv.get().strip()
        if not w: messagebox.showwarning('警告','请输入网站/应用名称！'); return
        if not u: messagebox.showwarning('警告','请输入用户名！'); return
        if not p: messagebox.showwarning('警告','请输入密码！'); return
        self.result = (w, u, encrypt(self.cipher, p), n); self.dlg.destroy()

class MainWindow:
    def __init__(self, cipher):
        self.cipher = cipher; self.root = tk.Tk()
        self.root.title('密码管理器'); self.root.configure(bg='#f5f6fa')
        self.root.geometry('840x560')
        self._ct = None; self._st = None
        self._menu(); self._toolbar(); self._tree(); self._ctx_menu(); self._status()
        self.root.bind('<Control-f>', lambda e: self.se.focus())
        self.root.bind('<Control-n>', lambda e: self._add())
        self.root.bind('<Escape>', lambda e: self.sv.set(''))
        self.tree.bind('<Double-1>', lambda e: self._edit())
        self.tree.bind('<Button-3>', self._rclick)
        self.tree.bind('<Delete>', lambda e: self._delete())
        self.tree.bind('<Control-c>', lambda e: self._copypwd())
        self._refresh()

    def _menu(self):
        m = tk.Menu(self.root); fm = tk.Menu(m, tearoff=0)
        fm.add_command(label='修改主密码...', command=self._chpwd); fm.add_separator()
        fm.add_command(label='退出', command=self.root.destroy); m.add_cascade(label='文件', menu=fm)
        hm = tk.Menu(m, tearoff=0); hm.add_command(label='关于', command=self._about); m.add_cascade(label='帮助', menu=hm)
        self.root.config(menu=m)

    def _toolbar(self):
        tb = tk.Frame(self.root, bg='#e8ecf1', height=48); tb.pack(fill=tk.X); tb.pack_propagate(False)
        tk.Label(tb, text='🔍', font=('Microsoft YaHei',13), bg='#e8ecf1').pack(side=tk.LEFT, padx=(18,5), pady=10)
        self.sv = tk.StringVar(); self.sv.trace_add('write', self._search)
        self.se = ttk.Entry(tb, textvariable=self.sv, font=('Microsoft YaHei',11), width=28)
        self.se.pack(side=tk.LEFT, padx=(0,12), ipady=3)
        ttk.Button(tb, text='➕ 添加密码', command=self._add).pack(side=tk.LEFT, padx=4, ipady=2)
        ttk.Button(tb, text='🔄 刷新', command=self._refresh).pack(side=tk.LEFT, padx=4, ipady=2)
        self.cv = tk.StringVar(); tk.Label(tb, textvariable=self.cv, font=('Microsoft YaHei',9), bg='#e8ecf1', fg='#7f8c8d').pack(side=tk.RIGHT, padx=18)

    def _tree(self):
        tf = tk.Frame(self.root, bg='#ffffff'); tf.pack(fill=tk.BOTH, expand=True, padx=3, pady=(0,3))
        self.tree = ttk.Treeview(tf, columns=('website','username','notes','created'), show='headings', selectmode='browse')
        for c, h, w in [('website','网站/应用',200),('username','用户名',180),('notes','备注',240),('created','创建时间',155)]:
            self.tree.heading(c, text=h); self.tree.column(c, width=w, minwidth=80)
        sb = ttk.Scrollbar(tf, orient=tk.VERTICAL, command=self.tree.yview); self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y); self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.tag_configure('oddrow', background='#f9fafb'); self.tree.tag_configure('evenrow', background='#ffffff')

    def _ctx_menu(self):
        self.cm = tk.Menu(self.root, tearoff=0)
        self.cm.add_command(label='📋 复制密码', command=self._copypwd)
        self.cm.add_command(label='📋 复制用户名', command=self._copyusr)
        self.cm.add_separator()
        self.cm.add_command(label='✏️ 编辑', command=self._edit)
        self.cm.add_command(label='🗑 删除', command=self._delete)

    def _status(self):
        self.stv = tk.StringVar(value='就绪')
        tk.Label(self.root, textvariable=self.stv, font=('Microsoft YaHei',9), bg='#e8ecf1', fg='#555', anchor=tk.W, padx=12).pack(fill=tk.X, side=tk.BOTTOM)

    def _search(self, *args):
        if self._st: self.root.after_cancel(self._st)
        self._st = self.root.after(250, self._refresh)

    def _refresh(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        q = self.sv.get().strip()
        entries = db.search_entries(q) if q else db.get_all_entries()
        for i, e in enumerate(entries):
            tag = 'oddrow' if i%2==0 else 'evenrow'; ct = e.get('created_at','')
            self.tree.insert('', tk.END, values=(e['website'],e['username'],e.get('notes',''),ct[:19] if ct else ''), tags=(str(e['id']), tag))
        self.cv.set(f'共 {len(entries)} 条记录'); self.stv.set(f'搜索: {q} — 找到 {len(entries)} 条' if q else '就绪')

    def _sid(self):
        sel = self.tree.selection(); return int(self.tree.item(sel[0],'tags')[0]) if sel else None

    def _rclick(self, ev):
        i = self.tree.identify_row(ev.y)
        if i: self.tree.selection_set(i); self.cm.post(ev.x_root, ev.y_root)

    def _add(self):
        d = EntryDialog(self.root, self.cipher)
        if d.result: w,u,p,n = d.result; db.add_entry(w,u,p,n); self._refresh(); self.stv.set(f'✅ 已添加: {w}')

    def _edit(self):
        eid = self._sid()
        if not eid: messagebox.showinfo('提示','请先选择一条记录'); return
        entry = db.get_entry(eid)
        if entry:
            d = EntryDialog(self.root, self.cipher, entry)
            if d.result: w,u,p,n = d.result; db.update_entry(eid,w,u,p,n); self._refresh(); self.stv.set(f'✅ 已更新: {w}')

    def _delete(self):
        eid = self._sid()
        if not eid: messagebox.showinfo('提示','请先选择一条记录'); return
        entry = db.get_entry(eid)
        if entry and messagebox.askyesno('确认删除',f'确定要删除「{entry["website"]}」的密码记录吗？\n\n此操作不可恢复！'):
            db.delete_entry(eid); self._refresh(); self.stv.set(f'🗑 已删除: {entry["website"]}')

    def _copypwd(self):
        eid = self._sid()
        if not eid: return
        enc = db.get_encrypted_password(eid)
        if enc:
            try:
                plain = decrypt(self.cipher, enc); self.root.clipboard_clear(); self.root.clipboard_append(plain)
                if self._ct: self.root.after_cancel(self._ct)
                self._ct = self.root.after(30000, lambda: (self.root.clipboard_clear(), setattr(self,'stv',tk.StringVar(value='🔒 剪贴板已自动清除'))))
                entry = db.get_entry(eid); self.stv.set(f'📋 密码已复制 — 30 秒后自动清除 — {entry["website"]}')
            except Exception as e: messagebox.showerror('错误',f'解密失败: {e}')

    def _copyusr(self):
        sel = self.tree.selection()
        if sel: u = self.tree.item(sel[0],'values')[1]; self.root.clipboard_clear(); self.root.clipboard_append(u); self.stv.set('📋 用户名已复制到剪贴板')

    def _chpwd(self): messagebox.showinfo('提示','修改主密码功能请使用 Web 版 (localhost:5000/change-password)')

    def _about(self):
        messagebox.showinfo('关于','🔐 密码管理器 v1.0\n\n基于 Python 开发的本地密码管理工具\n技术栈: tkinter + SQLite + cryptography\n\n数据使用 AES-128 加密，仅存储在本地')

    def run(self): self.root.mainloop()

def main():
    db.init_db(); login = LoginWindow(); cipher = login.run()
    if cipher: MainWindow(cipher).run()

if __name__ == '__main__':
    main()
