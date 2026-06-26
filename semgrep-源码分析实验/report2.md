 Semgrep扫描结果分析
所有命中均位于 cur.execute(query)`调用处，与SQL语句经过字符串格式化后传入 execute()的漏洞模式完全对应。

人工分析（report1.md）中识别了以下SQL注入点：
1. db.py: find_user — % 格式化 
2. db.py: find_user_by_email — f-string 
3. db.py: create_user — .format() 

三个漏洞点全部命中，与初次分析完全一致。项目中的安全函数store_token 和 list_tokens（使用参数化查询）未被误报。

规则的漏报情形：无法检测非函数参数来源的污点
当前规则以函数参数作为污点源（pattern-sources`匹配函数形参）。如果攻击者可控数据来自 request.args、request.form 等Web框架输入，且SQL拼接发生在同一函数内部（不经过函数调用边界），则无法检测。