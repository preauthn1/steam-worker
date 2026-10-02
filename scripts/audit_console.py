#!/usr/bin/env python3
"""Single-browser synthetic regression. Requires Playwright; never calls Steam.
Build /tmp/steam-server-audit first, then run with browser-venv/bin/python.
An isolated temporary database, random test token and loopback port are used.
Only the 35-operation catalog and synthetic account management reach Go HTTP.
All operation requests are intercepted in the browser, including writes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', default='/tmp/steam-server-audit')
parser.add_argument('--output', default='/tmp/steam-console-regression')
parser.add_argument('--no-screenshots', action='store_true', help='Run functional assertions without another visual capture pass')
args = parser.parse_args()
out = Path(args.output)
out.mkdir(parents=True, exist_ok=True)
records, errors, console_errors, calls = [], [], [], []
synthetic = 'audit-synthetic-01'
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
base = f'http://127.0.0.1:{port}'
token = secrets.token_hex(24)

def api(method, path, body=None):
    headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
    if method in ('PUT', 'DELETE'):
        headers.update({'X-Confirm-Write': 'true', 'Idempotency-Key': 'audit-' + uuid.uuid4().hex})
    req = urllib.request.Request(base + path, method=method, headers=headers,
                                 data=None if body is None else json.dumps(body).encode())
    try:
        response = urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    return response.status, json.load(response)

with tempfile.TemporaryDirectory(prefix='steam-audit-') as data_dir:
    env = os.environ.copy()
    env.update({'API_KEYS_JSON': json.dumps([{'id': 'audit', 'sha256': hashlib.sha256(token.encode()).hexdigest(), 'scopes': ['admin'], 'accounts': ['*']}]),
                'STATE_KEY_HEX': secrets.token_hex(32), 'DATA_DIR': data_dir, 'BIND': f'127.0.0.1:{port}', 'GOMAXPROCS': '2'})
    # Never inherit a production external-asset override.
    env.pop('CONSOLE_HTML_FILE', None)
    env.pop('CONSOLE_CSP', None)
    process = subprocess.Popen([args.binary], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                if api('GET', '/health')[0] == 200:
                    break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError('isolated Go server did not start')
        catalog = api('GET', '/v1/operations')[1]
        assert len(catalog['operations']) == 35
        assert api('PUT', '/v1/accounts/audit-existing', {})[0] == 200
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, args=['--disable-dev-shm-usage', '--renderer-process-limit=2'])
            context = browser.new_context(viewport={'width': 1440, 'height': 1000})
            page = context.new_page()
            page.set_default_timeout(5000)
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('console', lambda message: console_errors.append(message.text) if message.type == 'error' and 'Content Security Policy' in message.text else None)
            fixtures = {}

            def intercept(route):
                name = route.request.url.rsplit('/', 1)[-1]
                headers = route.request.headers
                call = {'name': name, 'arguments': route.request.post_data_json['arguments'],
                        'key': headers.get('idempotency-key'), 'confirmed': headers.get('x-confirm-write')}
                calls.append(call)
                status, result = fixtures.get(name, (200, {'result': {'pending': True}}))
                route.fulfill(status=status, json=result)

            page.route('**/v1/accounts/*/operations/*', intercept)
            page.route('**/v1/accounts', lambda route: route.continue_())
            http = []
            def on_response(response):
                if '/v1/' not in response.url:
                    return
                entry = {'method': response.request.method, 'path': response.url.split(base)[-1], 'status': response.status,
                         'fixture': '/operations/' in response.url}
                if response.status >= 400:
                    try:
                        entry['code'] = response.json()['error']['code']
                    except (KeyError, ValueError):
                        pass
                http.append(entry)
            page.on('response', on_response)

            def idle():
                deadline = time.monotonic() + 5
                while page.locator('#connect').is_disabled() and time.monotonic() < deadline:
                    page.wait_for_timeout(20)
                assert not page.locator('#connect').is_disabled(), 'busy failed to recover'

            def record(label):
                page.wait_for_timeout(30)
                records.append({'step': label, 'state': page.locator('#connection-state').inner_text(), 'status': page.locator('#status').inner_text(),
                                'account': page.locator('#account').input_value(), 'dialog': page.locator('#write-dialog').evaluate('(e)=>e.open'),
                                'run_disabled': page.locator('#run').is_disabled(), 'retry_disabled': page.locator('#retry').is_disabled(),
                                'poll_disabled': page.locator('#poll-login').is_disabled(), 'http': list(http)})
                http.clear()

            def select(name):
                page.locator('[data-group=advanced]').click()
                page.locator('#operation').select_option(name)

            def account(value):
                page.locator('#account').fill(value)
                page.locator('#account').press('Tab')

            def review():
                page.locator('#run').click()
                assert page.locator('#write-dialog').evaluate('(e)=>e.open')
                assert page.locator('#confirm-write').is_disabled()

            def approve():
                page.locator('#acknowledge').check()
                page.locator('#confirm-write').click()
                idle()

            def fill_buy():
                select('market.place_buy_order')
                for name, value in {'app': '730', 'market_hash_name': 'audit-item', 'price': '1', 'currency': '1'}.items():
                    page.locator('#arg-' + name).fill(value)

            page.goto(base)
            page.locator('.skip').focus()
            page.locator('.skip').press('Enter')
            assert page.locator('#workspace').evaluate('(e)=>document.activeElement===e')
            page.locator('#token').fill(token)
            page.locator('#connect').click()
            idle()
            assert page.locator('#account').input_value() == 'audit-existing'
            assert page.locator('#token').input_value() == ''
            record('连接：35 个操作，自动选择已有账户')
            page.locator('#account-info').click()
            idle()
            record('查看已有账户')
            account('mytest')
            page.locator('#account-info').click()
            idle()
            assert '账户尚未创建' in page.locator('#status').inner_text()
            assert 'account_not_found' in page.locator('#output').inner_text()
            record('不存在账户：404 保留错误码')
            for invalid in ('', '_bad'):
                account(invalid)
                page.locator('#account-info').click()
                assert page.locator('#account').get_attribute('aria-invalid') == 'true'
                record('账户前端校验：' + repr(invalid))
            account(synthetic)
            page.locator('#create-account').click()
            assert page.locator('#confirm-write').is_disabled()
            page.locator('#cancel-write').click()
            assert '未发送' in page.locator('#status').inner_text()
            record('创建取消：旧错误提示清除')
            page.locator('#create-account').click()
            approve()
            assert page.locator('#accounts button').filter(has_text=synthetic).count() == 1
            record('创建确认：200 后自动刷新列表')
            for group in ('login', 'inventory', 'market', 'trade', 'confirmations', 'advanced'):
                page.locator('[data-group=' + group + ']').click()
                assert page.locator('[data-group=' + group + ']').get_attribute('aria-pressed') == 'true'
                record('标签页：' + group)
            schema_rows = []
            for op in catalog['operations']:
                page.locator('#operation').select_option(op['name'])
                rendered = page.locator('[data-argument]').evaluate_all('(els)=>els.map(e=>({name:e.name,type:e.type,tag:e.tagName,required:e.required,help:!!e.getAttribute("aria-describedby")}))')
                assert sorted(field['name'] for field in rendered) == sorted(op['schema']['properties'])
                for field in rendered:
                    assert field['required'] == (field['name'] in op['schema']['required'])
                    schema = op['schema']['properties'][field['name']]
                    if schema['type'] == 'boolean':
                        assert field['tag'] == 'SELECT'
                    if schema['type'] in ('array', 'object'):
                        assert field['tag'] == 'TEXTAREA'
                    if schema['type'] in ('integer', 'number'):
                        assert field['type'] == 'number'
                schema_rows.append({'operation': op['name'], 'rendered': rendered})
            (out / 'schemas.json').write_text(json.dumps(schema_rows, ensure_ascii=False, indent=2))
            fill_buy()
            page.locator('#account').fill('audit-changed')
            page.locator('#arg-market_hash_name').fill('preserved-item')
            assert page.locator('#arg-market_hash_name').input_value() == 'preserved-item'
            account(synthetic)
            assert page.locator('#arg-market_hash_name').input_value() == 'preserved-item'
            record('账户输入/失焦保留普通字段')
            review()
            page.locator('#cancel-write').click()
            review()
            page.keyboard.press('Escape')
            assert not page.locator('#write-dialog').evaluate('(e)=>e.open')
            assert len(calls) == 0
            record('多字段写入：取消、重开、Escape 均未请求')
            # Exercise the queued native dialog close event before it is delivered.
            page.evaluate("() => {document.getElementById('run').click();document.getElementById('cancel-write').click();document.getElementById('run').click();}")
            page.wait_for_timeout(50)
            fixtures['market.place_buy_order'] = (409, {'error': {'code': 'outcome_unknown'}})
            approve()
            assert len(calls) == 1 and calls[-1]['confirmed'] == 'true'
            assert page.locator('#retry').is_enabled()
            original = calls[-1]
            record('快速关闭/重开审核后确认；不确定写入保留重试')
            page.locator('#retry').click()
            page.locator('#cancel-write').click()
            assert len(calls) == 1
            page.locator('#retry').click()
            approve()
            assert calls[-1] == original
            record('手动重试取消/提交；原参数与幂等键一致')
            fixtures['market.place_buy_order'] = (400, {'error': {'code': 'invalid_arguments'}})
            review()
            approve()
            assert page.locator('#retry').is_disabled()
            assert '此次写入被拒绝' in page.locator('#status').inner_text()
            record('400 明确拒绝：恢复按钮，无不确定写入误报')
            for status, code in ((401, 'unauthorized'), (403, 'scope_denied'), (404, 'account_not_found'), (429, 'rate_limited'), (409, 'succeeded_result_not_cached'), (502, 'upstream_failed')):
                fixtures['market.place_buy_order'] = (status, {'error': {'code': code}})
                review()
                approve()
                assert code in page.locator('#status').inner_text()
                assert page.locator('#retry').is_enabled() == (status == 502)
                record(f'写入错误：{status} {code}')
            select('trade.get_multiple')
            page.locator('#arg-sent').select_option('false')
            page.locator('#run').click()
            idle()
            assert calls[-1]['arguments'] == {'sent': False}
            record('选填布尔：显式 false 与省略区分')
            select('confirmations.send_multiple')
            page.locator('#arg-confirmation_ids').fill('[]')
            before = len(calls)
            page.locator('#run').click()
            assert not page.locator('#write-dialog').evaluate('(e)=>e.open')
            assert len(calls) == before
            assert '项目数量' in page.locator('#status').inner_text()
            page.locator('#arg-confirmation_ids').fill('["1"]')
            page.locator('#arg-accept').select_option('false')
            review()
            approve()
            assert calls[-1]['arguments'] == {'accept': False, 'confirmation_ids': ['1']}
            record('JSON 数组范围与必填 false')
            page.locator('#arg-confirmation_ids').fill('["1","1"]')
            page.locator('#run').click()
            assert not page.locator('#write-dialog').evaluate('(e)=>e.open')
            assert '重复' in page.locator('#status').inner_text()
            record('JSON 唯一项目：审核前阻止重复')
            select('session.code')
            page.locator('#arg-login_handle').fill('fixture-handle')
            page.locator('#arg-auth_code').fill('!')
            page.locator('#run').click()
            assert not page.locator('#write-dialog').evaluate('(e)=>e.open')
            assert '格式' in page.locator('#status').inner_text()
            record('验证码 pattern 校验：审核前阻止')
            select('session.status')
            fixtures['session.status'] = (200, {'result': {'status': 'unauthenticated', 'guard_configured': False, 'ready_for_web': False}})
            page.locator('#run').click()
            idle()
            assert 'unauthenticated' in page.locator('#output').inner_text()
            record('会话状态：保留状态枚举，无认证机密')
            fixtures['session.qr'] = (200, {'result': {'status': 'pending', 'login_handle': 'fixture-handle', 'challenge_url': 'https://s.team/q/1/audit', 'expires_at': time.time() + 600}})
            fixtures['session.poll'] = (200, {'result': {'status': 'pending', 'login_handle': 'fixture-handle'}})
            select('session.qr')
            review()
            approve()
            assert page.locator('#challenge-qr').is_visible()
            assert 'fixture-handle' not in page.locator('#output').inner_text()
            record('二维码：本地 canvas，无外部二维码服务')
            page.locator('#poll-login').click()
            page.locator('#cancel-write').click()
            assert page.locator('#poll-login').is_enabled()
            record('轮询审核取消')
            page.locator('#poll-login').click()
            page.locator('#acknowledge').check()
            page.locator('#confirm-write').click()
            page.wait_for_timeout(100)
            assert page.locator('#account').is_disabled()
            assert page.locator('#poll-login').is_disabled()
            assert page.locator('#run').is_disabled()
            assert page.locator('#stop-poll').is_enabled()
            record('轮询中：冻结上下文、防并发；停止可用')
            page.locator('#stop-poll').click()
            page.wait_for_timeout(50)
            idle()
            record('停止轮询：按钮恢复')
            fixtures['session.poll'] = (409, {'error': {'code': 'login_required'}})
            page.locator('#poll-login').click()
            approve()
            assert page.locator('#challenge').is_hidden()
            record('失效句柄：清除挑战，不再提供旧轮询入口')
            select('session.qr')
            review()
            approve()
            fixtures['session.poll'] = (200, {'result': {'status': 'authenticated'}})
            page.locator('#poll-login').click()
            approve()
            assert 'Steam 登录已完成' in page.locator('#status').inner_text()
            assert page.locator('#challenge').is_hidden()
            record('完成轮询：完成状态不被通用文字覆盖')
            # Speed only the bounded poll delays, not HTTP request timeouts.
            page.evaluate('''() => {const original=window.setTimeout;window.setTimeout=(callback,delay,...args)=>original(callback,delay>=3000 && delay<=30000 ? 0 : delay,...args);}''')
            select('session.qr')
            review()
            approve()
            fixtures['session.poll'] = (200, {'result': {'status': 'pending', 'login_handle': 'fixture-handle'}})
            before = len([call for call in calls if call['name'] == 'session.poll'])
            page.locator('#poll-login').click()
            approve()
            polled = [call for call in calls if call['name'] == 'session.poll'][before:]
            assert len(polled) == 20
            assert len({call['key'] for call in polled}) == 20
            assert all(call['confirmed'] == 'true' for call in polled)
            assert '上限' in page.locator('#status').inner_text()
            record('轮询 20 次上限：每次新幂等键，正常恢复')
            select('session.qr')
            review()
            approve()
            select('session.cancel')
            fixtures['session.cancel'] = (200, {'result': {'status': 'cancelled'}})
            review()
            approve()
            assert page.locator('#challenge').is_hidden()
            assert page.locator('#poll-login').is_disabled()
            assert page.locator('#arg-login_handle').input_value() == ''
            record('取消登录：二维码、句柄、轮询按钮清除')
            # A successful QR fixture with an untrusted URL never exposes a link/canvas.
            fixtures['session.qr'] = (200, {'result': {'login_handle': 'fixture-handle', 'challenge_url': 'https://example.invalid/qr'}})
            select('session.qr')
            review()
            approve()
            assert page.locator('#challenge-qr').is_hidden()
            assert page.locator('#challenge-link').is_hidden()
            fixtures['session.qr'] = (200, {'result': {'login_handle': 'fixture-handle', 'challenge_url': 'https://s.team/q/1/audit', 'expires_at': time.time() - 1}})
            select('session.qr')
            review()
            approve()
            before = len(calls)
            page.locator('#poll-login').click()
            approve()
            assert len(calls) == before
            assert page.locator('#challenge').is_hidden()
            assert '过期' in page.locator('#status').inner_text()
            record('过期挑战：首个轮询前清除状态，无请求')
            select('session.credentials')
            page.locator('#arg-account_name').fill('synthetic-user')
            page.locator('#arg-password').fill('synthetic-password')
            review()
            assert page.locator('#arg-password').input_value() == ''
            assert 'synthetic-password' not in page.locator('#review-arguments').inner_text()
            page.locator('#cancel-write').click()
            record('密码：提交即清空，审核脱敏，取消不请求')
            # Network failure and malformed response recover without unlocking an old write.
            select('session.status')
            page.route('**/operations/session.status', lambda route: route.abort())
            page.locator('#run').click()
            idle()
            assert '网络' in page.locator('#status').inner_text()
            page.unroute('**/operations/session.status')
            record('网络失败恢复')
            page.route('**/operations/session.status', lambda route: route.fulfill(body='not-json', content_type='application/json'))
            page.locator('#run').click()
            idle()
            assert 'JSON' in page.locator('#status').inner_text()
            page.unroute('**/operations/session.status')
            record('非 JSON 响应恢复')
            page.locator('#disconnect').click()
            # A real new-page document navigation plus fresh connection reuses no state.
            page.locator('#token').fill(token)
            page.route('**/v1/accounts', lambda route: route.fulfill(status=503, json={'error': {'code': 'internal_error'}}))
            page.locator('#connect').click()
            idle()
            assert '读取失败' in page.locator('#status').inner_text()
            assert '管理员' not in page.locator('#status').inner_text()
            record('账户列表 503：不伪报权限问题')
            page.unroute('**/v1/accounts')
            page.locator('#disconnect').click()
            page.locator('#token').fill(token)
            page.locator('#connect').click()
            idle()
            account(synthetic)
            fill_buy()
            measurements = []
            for width, height in ((1440, 1000), (390, 844), (320, 740)):
                page.set_viewport_size({'width': width, 'height': height})
                metrics = page.evaluate('''() => ({width:innerWidth,overflow:document.documentElement.scrollWidth>innerWidth,
                    buttonWidths:['connect','disconnect'].map(id=>document.getElementById(id).getBoundingClientRect().width),
                    supportSize:getComputedStyle(document.querySelector('small')).fontSize,
                    inputSize:getComputedStyle(document.getElementById('account')).fontSize,
                    nav:[...document.querySelectorAll('[data-group]')].map(e=>({label:e.textContent,height:e.getBoundingClientRect().height,border:getComputedStyle(e).borderBottomWidth})),
                    storage:[localStorage.length,sessionStorage.length]})''')
                assert not metrics['overflow']
                assert abs(metrics['buttonWidths'][0] - metrics['buttonWidths'][1]) <= 1
                assert min(tab['height'] for tab in metrics['nav']) >= 44
                assert metrics['storage'] == [0, 0]
                measurements.append(metrics)
                if not args.no_screenshots:
                    page.screenshot(path=str(out / f'console-{width}.png'), full_page=True)
            (out / 'layout.json').write_text(json.dumps(measurements, ensure_ascii=False, indent=2))
            # Body/support text and primary-action contrast (normal-sized text >=4.5).
            def contrast(foreground, background):
                def luminance(color):
                    channels = [int(color[i:i+2], 16)/255 for i in (1, 3, 5)]
                    channels = [value/12.92 if value<=.04045 else ((value+.055)/1.055)**2.4 for value in channels]
                    return sum(value*weight for value, weight in zip(channels, (.2126,.7152,.0722)))
                light, dark = sorted((luminance(foreground), luminance(background)), reverse=True)
                return (light+.05)/(dark+.05)
            contrasts = {name: contrast(foreground, background) for name, foreground, background in (
                ('body', '#edf3f9', '#171d25'), ('support', '#b7c8d9', '#202e3d'),
                ('primary', '#edf3f9', '#126391'), ('primary_hover', '#edf3f9', '#176c9d'),
                ('selected_navigation', '#edf3f9', '#254b69'), ('blue_text', '#66c0f4', '#202e3d'))}
            assert min(contrasts.values()) >= 4.5
            (out / 'contrast.json').write_text(json.dumps(contrasts, indent=2))
            # At 200% text scale narrow layouts still expand without document overflow.
            page.evaluate("() => document.documentElement.style.fontSize='32px'")
            assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
            page.evaluate("() => document.documentElement.style.fontSize=''")
            page.set_viewport_size({'width': 390, 'height': 844})
            review()
            if not args.no_screenshots:
                page.screenshot(path=str(out / 'review-mobile.png'), full_page=True)
            page.locator('#cancel-write').click()
            # Cancel an in-flight response, reconnect, then deliver the stale response.
            held = []
            select('session.status')
            page.route('**/operations/session.status', lambda route: held.append(route))
            page.locator('#run').click()
            page.wait_for_timeout(80)
            assert held
            page.locator('#disconnect').click()
            page.locator('#token').fill(token)
            page.locator('#connect').click()
            idle()
            for route in held:
                route.fulfill(json={'result': {'status': 'authenticated'}})
            page.wait_for_timeout(80)
            assert '已连接' in page.locator('#status').inner_text()
            assert 'authenticated' not in page.locator('#output').inner_text()
            record('请求中断开并重连：旧响应不覆盖新状态')
            page.locator('#disconnect').click()
            assert page.locator('#account').input_value() == ''
            assert page.locator('#poll-login').is_disabled()
            assert page.locator('#run').is_disabled()
            assert page.locator('#retry').is_disabled()
            record('断开连接：清除所有上下文')
            assert not errors, errors
            assert not console_errors, console_errors
            browser.close()
        assert api('DELETE', '/v1/accounts/' + synthetic, {})[0] == 200
        assert api('GET', '/v1/accounts/' + synthetic)[0] == 404
        assert api('DELETE', '/v1/accounts/audit-existing', {})[0] == 200
    finally:
        (out / 'results.json').write_text(json.dumps({'steps': records, 'pageerrors': errors, 'csp_errors': console_errors}, ensure_ascii=False, indent=2))
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
print(json.dumps({'steps': len(records), 'operations': len(catalog['operations']), 'pageerrors': errors, 'csp_errors': console_errors, 'output': str(out)}, ensure_ascii=False))
