import sys; sys.path.insert(0, '/opt/class')
from app import app

with app.test_client() as c:
    # 1. 首页
    r = c.get('/')
    assert r.status_code == 200
    assert '请先登录' in r.data.decode()  # 请先登录
    print('[OK] 首页 - 未登录显示请先登录')

    # 2. 登录页含 success 参数
    r = c.get('/login?success=注册成功，请登录')
    assert r.status_code == 200
    assert '注册成功' in r.data.decode()
    print('[OK] 登录页 - 显示成功消息')

    # 3. 注册页
    r = c.get('/register')
    assert r.status_code == 200
    assert '用户注册' in r.data.decode()
    print('[OK] 注册页 - 正常访问')

    # 4. 注册新用户
    r = c.post('/register', data={'username': 'testuser', 'password': 'test123', 'email': 'test@test.com', 'phone': '13900001111'}, follow_redirects=True)
    assert r.status_code == 200
    assert '注册成功' in r.data.decode()
    print('[OK] 注册 - 成功后跳转登录页并提示')

    # 5. 新用户可登录
    r = c.post('/login', data={'username': 'testuser', 'password': 'test123'}, follow_redirects=True)
    assert r.status_code == 200
    assert 'testuser' in r.data.decode()
    print('[OK] 登录 - 新用户可正常登录')

    # 6. 搜索功能（登录状态下）
    with c.session_transaction() as sess:
        sess['username'] = 'admin'
    r = c.get('/search?keyword=admin')
    assert r.status_code == 200
    assert '搜索结果' in r.data.decode()
    print('[OK] 搜索 - GET请求正常')

    # 7. 搜索无结果
    r = c.get('/search?keyword=xxxxxxxxx')
    assert r.status_code == 200
    assert '无搜索结果' in r.data.decode()
    print('[OK] 搜索 - 无结果时显示提示')

    # 8. SQL 注入测试
    r = c.get("/search?keyword=' OR '1'='1")
    assert r.status_code == 200
    assert '搜索结果' in r.data.decode()
    print('[OK] SQL注入 - 可查出全部用户')

    # 9. 导航栏有注册链接
    c.get('/logout')
    r = c.get('/')
    assert '注册' in r.data.decode()
    print('[OK] 导航栏 - 未登录显示注册链接')

    # 10. 数据库已创建
    import os
    assert os.path.exists('data/users.db')
    print('[OK] 数据库 - data/users.db 已创建')

    # 11. 表格只显示4列（ID、用户名、邮箱、手机）
    with c.session_transaction() as sess:
        sess['username'] = 'admin'
    r = c.get('/search?keyword=a')
    html = r.data.decode()
    assert html.count('<th>') == 4
    assert '角色' not in html  # 角色不应该出现
    print('[OK] 搜索结果表格 - 仅显示ID/用户名/邮箱/手机')

print()
print('All tests passed!')
