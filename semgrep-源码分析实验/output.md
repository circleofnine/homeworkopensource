               
               
┌─────────────┐
│ Scan Status │
└─────────────┘
  Scanning 20 files tracked by git with 1 Code rule:
  Scanning 4 files.
                
                
┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
 • Findings: 6 (6 blocking)
 • Rules run: 1
 • Targets scanned: 4
 • Parsed lines: ~100.0%
 • No ignore information available
Ran 1 rule on 4 files: 6 findings.
                   
                   
┌─────────────────┐
│ 6 Code Findings │
└─────────────────┘
                             
    F:\ho\code-repo_lab\db.py
   ❯❯❱ python-sql-injection-string-format
          ❰❰ Blocking ❱❱
          SQL injection detected: user-controlled data concatenated into SQL via string formatting    
          (%%/.format()/f-string). Use parameterized queries (placeholders + parameter tuple) instead.
                                                                                                      
           40┆ cur.execute(query)
            ⋮┆----------------------------------------
           51┆ cur.execute(query)
            ⋮┆----------------------------------------
           64┆ cur.execute(query)
                                             
    F:\ho\code-repo_lab\test_sql_injection.py
   ❯❯❱ python-sql-injection-string-format
          ❰❰ Blocking ❱❱
          SQL injection detected: user-controlled data concatenated into SQL via string formatting    
          (%%/.format()/f-string). Use parameterized queries (placeholders + parameter tuple) instead.
                                                                                                      
            9┆ cur.execute(query)
            ⋮┆----------------------------------------
           16┆ cur.execute(query)
            ⋮┆----------------------------------------
           23┆ cur.execute(query)

