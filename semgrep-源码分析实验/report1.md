人工漏洞分析及缺陷判据：

db.py中存在多处将用户输入直接拼接到SQL语句中执行的情况，属于SQL注入漏洞。

db.py: find_user 函数 — %格式化拼接
```python
def find_user(username):
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cur.execute(query)
```

db.py: find_user_by_email 函数 — f-string 拼接
```python
def find_user_by_email(email):
    query = f"SELECT * FROM users WHERE email = '{email}'"
    cur.execute(query)
```

db.py: create_user 函数 — `.format()` 拼接
```python
def create_user(username, pw_hash, email):
    query = "INSERT INTO users (username, pw_hash, email) VALUES ('{}', '{}', '{}')".format(
        username, pw_hash, email
    )
    cur.execute(query)
```

app.py: /users 路由 — 用户输入直达find_user
```python
q = request.args.get("q", "")
row = db.find_user(q)   # q来自HTTP参数，未经过滤
```

SQL注入模式特征明确，适合用Semgrep规则表达，SQL注入的典型模式是：外部输入 → 字符串格式化 → 数据库执行。这个三阶段模式在语法层面有明确的标识：Source：函数参数、request.args.get()、request.form[]等外部输入
Propagator（传播）：Python的字符串格式化操作符（%、.format()、f-string）
Sink：cursor.execute()、connection.execute()等数据库执行方法

触发缺陷的判据：满足以下条件即判定为SQL注入缺陷：
1. 存在数据库执行操作：代码中调用了 cursor.execute() 或 connection.execute()
2. SQL语句经由字符串格式化构造：传给 execute()`的第一个参数（SQL语句）使用了 %、.format()或 f-string 进行字符串格式化
3. 格式化操作中含外部可控数据：格式化的参数来自函数形参（可被调用方传入任意值）

当以上三个条件同时满足时，即触发告警。
