"""Temporary fixture-only WSGI app. No production imports, network clients or database."""
import hashlib
import hmac
import html
import json
import mimetypes
import os
import re
import secrets
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parent
CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; media-src 'self' blob:; connect-src 'self'; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
COOKIE = 'saphi_test'


class FixtureApp:
    def __init__(self, root=ROOT, config=None, clock=time.time):
        self.root = Path(root)
        self.config = dict(os.environ if config is None else config)
        self.clock = clock
        self.lock = threading.RLock()
        self.sessions = {}
        self.entries = {}
        self.failures = []
        self.catalog = json.loads((self.root / 'fixture-catalog.json').read_text()) if (self.root / 'fixture-catalog.json').is_file() else []
        self.static = {'/'+str(p.relative_to(self.root/'public')): p for p in (self.root/'public').rglob('*') if p.is_file() and not p.is_symlink()}
        if '/index.html' in self.static:
            self.static['/'] = self.static['/index.html']

    def reply(self, start, status, body=b'', mime='application/json', headers=None, method='GET'):
        if isinstance(body, dict) or isinstance(body, list):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        common = [('Content-Type', mime), ('Content-Length', str(len(body))), ('Cache-Control', 'no-store, private'), ('X-Content-Type-Options', 'nosniff'), ('Referrer-Policy', 'same-origin'), ('Content-Security-Policy', CSP), ('X-Frame-Options', 'DENY'), ('X-Robots-Tag', 'noindex, nofollow, noarchive')]
        start(f'{status} {HTTPStatus(status).phrase}', common + (headers or []))
        return [b'' if method == 'HEAD' else body]

    def cookie(self, value, age=7200):
        return ('Set-Cookie', f'{COOKIE}={value}; Path=/; Max-Age={age}; Secure; HttpOnly; SameSite=Lax')

    def configured(self):
        c = self.config
        try:
            valid = c.get('TEST_ENABLED') == 'true' and int(c.get('TEST_EXPIRES_AT', '0')) > self.clock()
        except ValueError:
            return False
        return bool(valid and re.fullmatch(r'[a-z0-9.-]+(?::[0-9]{1,5})?', c.get('TEST_HOST', '')) and re.fullmatch(r'[0-9a-f]{32}', c.get('TEST_PIN_SALT', '')) and re.fullmatch(r'[0-9a-f]{64}', c.get('TEST_PIN_HASH', '')))

    def session(self, environ):
        cookie = SimpleCookie()
        try:
            cookie.load(environ.get('HTTP_COOKIE', ''))
            token = cookie[COOKIE].value if COOKIE in cookie else ''
        except Exception:
            return None
        with self.lock:
            now = self.clock()
            self.sessions = {k:v for k,v in self.sessions.items() if v['expires'] > now}
            return self.sessions.get(token)

    def portal(self, start, message='', status=200):
        with self.lock:
            now = self.clock()
            self.entries = {k:v for k,v in self.entries.items() if v > now}
            if len(self.entries) >= 128:
                return self.reply(start, 429, {'error':'Please retry later.'})
            nonce = secrets.token_urlsafe(24)
            self.entries[nonce] = now + 600
        body = ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                '<title>Neni Stream test access</title><link rel="stylesheet" href="/access.css"><main><h1>Neni Stream TV test</h1>'
                '<p>Enter the temporary test passcode. Your Neni Stream password is not needed.</p>'
                '<form action="/access" method="post"><input type="hidden" name="nonce" value="'+nonce+'">'
                '<label>Test passcode<input name="passcode" type="password" inputmode="numeric" pattern="[0-9]{12}" maxlength="12" required autocomplete="off" autofocus></label>'
                '<div class="keypad" aria-label="Passcode keypad">'+''.join('<button type="button" class="digit" value="'+str(n)+'">'+str(n)+'</button>' for n in [1,2,3,4,5,6,7,8,9])+'<button type="button" id="erase">Delete</button><button type="button" class="digit" value="0">0</button><button type="submit" id="open-test">Open test</button></div></form><script src="/access.js"></script><p role="alert">'+html.escape(message)+'</p>'
                '<p>Sample content only. This test expires automatically.</p></main></html>')
        return self.reply(start, status, body, 'text/html; charset=utf-8')

    def gate_login(self, environ, start, raw):
        with self.lock:
            now = self.clock()
            self.failures = [t for t in self.failures if t > now-600]
            if len(self.failures) >= 20:
                return self.reply(start, 429, {'error':'Too many attempts. Wait ten minutes.'}, headers=[('Retry-After','600')])
            data = parse_qs(raw.decode('utf-8', errors='replace'))
            nonce = data.get('nonce', [''])[0]
            if self.entries.pop(nonce, 0) <= now:
                return self.portal(start, 'Reload this form and try again.', 403)
            code = data.get('passcode', [''])[0]
            digest = hashlib.pbkdf2_hmac('sha256', code.encode(), bytes.fromhex(self.config['TEST_PIN_SALT']), 200000).hex()
            if not re.fullmatch(r'[0-9]{12}', code) or not hmac.compare_digest(digest, self.config['TEST_PIN_HASH']):
                self.failures.append(now)
                return self.portal(start, 'Passcode not recognised. Try again.', 403)
            if len(self.sessions) >= 32:
                return self.reply(start, 429, {'error':'Test session limit reached.'})
            token = secrets.token_urlsafe(32)
            self.sessions[token] = dict(expires=min(now+7200, int(self.config['TEST_EXPIRES_AT'])), user=False, progress=[], lists=[])
            return self.reply(start, 303, b'', headers=[self.cookie(token), ('Location','/')])

    def file(self, environ, start, target):
        if not target.is_file():
            return self.reply(start, 404, {'error':'not_found'})
        size = target.stat().st_size
        left, right, status = 0, size-1, 200
        extra = [('Accept-Ranges','bytes')]
        requested = environ.get('HTTP_RANGE', '')
        if requested:
            match = re.fullmatch(r'bytes=(\d+)-(\d*)', requested)
            if not match:
                return self.reply(start, 416, {'error':'invalid_range'}, headers=[('Content-Range',f'bytes */{size}')])
            left = int(match[1]); right = min(int(match[2]) if match[2] else right, right)
            if left > right:
                return self.reply(start, 416, {'error':'invalid_range'}, headers=[('Content-Range',f'bytes */{size}')])
            status = 206
            extra.append(('Content-Range', f'bytes {left}-{right}/{size}'))
        mime = {'.ts':'video/mp2t','.m3u8':'application/vnd.apple.mpegurl','.mp4':'video/mp4','.mp3':'audio/mpeg'}.get(target.suffix) or mimetypes.guess_type(str(target))[0] or 'application/octet-stream'
        start(f'{status} {HTTPStatus(status).phrase}', [('Content-Type',mime), ('Content-Length',str(right-left+1)), ('Cache-Control','no-store, private'), ('Content-Security-Policy',CSP), ('X-Content-Type-Options','nosniff'), ('Referrer-Policy','same-origin'), ('X-Robots-Tag','noindex, nofollow, noarchive')] + extra)
        if environ['REQUEST_METHOD'] == 'HEAD':
            return [b'']
        def chunks():
            with target.open('rb') as stream:
                stream.seek(left)
                remaining = right-left+1
                while remaining > 0:
                    data = stream.read(min(65536, remaining))
                    if not data:
                        break
                    remaining -= len(data)
                    yield data
        return chunks()

    def __call__(self, environ, start):
        path = environ.get('PATH_INFO', '/')
        method = environ['REQUEST_METHOD']
        if path == '/healthz' and method in ('GET', 'HEAD'):
            return self.reply(start, 200, b'OK', 'text/plain', method=method)
        if not self.configured():
            return self.reply(start, 410, {'error':'This temporary test is disabled or expired.'})
        host = self.config['TEST_HOST']
        if environ.get('HTTP_HOST') != host:
            return self.reply(start, 403, {'error':'invalid_host'})
        # Gunicorn trusts forwarded scheme only from the hosting proxy; test harness sets it directly.
        if environ.get('wsgi.url_scheme') != 'https':
            return self.reply(start, 403, {'error':'https_required'})
        origin = environ.get('HTTP_ORIGIN')
        if origin and origin != 'https://'+host or environ.get('HTTP_SEC_FETCH_SITE') == 'cross-site':
            return self.reply(start, 403, {'error':'cross_site_request'})
        if method not in ('GET','HEAD','POST'):
            return self.reply(start, 405, {'error':'method_not_allowed'}, headers=[('Allow','GET, HEAD, POST')])
        if path in ('/access.css','/access.js') and method in ('GET','HEAD'):
            return self.file(environ, start, self.root/path[1:])
        try:
            size = int(environ.get('CONTENT_LENGTH') or '0')
        except ValueError:
            return self.reply(start, 400, {'error':'invalid_length'})
        if size < 0 or size > 16384:
            return self.reply(start, 413, {'error':'request_too_large'})
        raw = environ['wsgi.input'].read(size) if method == 'POST' else b''
        if path == '/access' and method == 'POST':
            if environ.get('CONTENT_TYPE','').split(';')[0] != 'application/x-www-form-urlencoded':
                return self.reply(start, 415, {'error':'invalid_content_type'})
            return self.gate_login(environ, start, raw)
        session = self.session(environ)
        if not session:
            if path.startswith('/api/') or path == '/client-config':
                return self.reply(start, 401, {'error':'test_access_required'})
            return self.portal(start)
        if path == '/client-config' and method == 'GET':
            return self.reply(start, 200, {'demo':True,'upstream':''})
        if path.startswith('/api/'):
            if method == 'HEAD':
                return self.reply(start, 405, {'error':'method_not_allowed'})
            if method == 'POST':
                if environ.get('CONTENT_TYPE','').split(';')[0] != 'application/json':
                    return self.reply(start, 415, {'error':'invalid_content_type'})
                try:
                    payload = json.loads(raw)
                    if not isinstance(payload, dict):
                        raise ValueError()
                except (ValueError, UnicodeDecodeError):
                    return self.reply(start, 400, {'error':'invalid_json'})
            else:
                payload = None
            with self.lock:
                return self.api(path[4:], payload, session, environ, start)
        if method == 'POST':
            return self.reply(start, 405, {'error':'method_not_allowed'})
        target = self.static.get(path)
        if target:
            return self.file(environ, start, target)
        return self.reply(start, 404, {'error':'not_found'})

    def api(self, path, payload, session, environ, start):
        send = lambda data, status=200, mime='application/json': self.reply(start,status,data,mime)
        if path == '/demo/session' and payload is not None:
            session.update(user=True,progress=[],lists=[])
            return send({'username':'Temporary sample viewer','role':'member'})
        if not session['user']:
            return send({'error':'sign_in_required'},401)
        if payload is not None:
            if path == '/auth/logout':
                session.update(user=False,progress=[],lists=[])
                return send({'ok':True})
            if path == '/playback':
                return send({'commands':[]})
            media = str(payload.get('media',''))
            if not any(i['id']==media for i in self.catalog):
                return send({'error':'unknown_fixture'},400)
            if path == '/progress':
                try:
                    position=float(payload.get('position',0));duration=float(payload.get('duration',0))
                    if not (0<=position<=86400 and 0<=duration<=86400):
                        raise ValueError()
                except (ValueError, TypeError):
                    return send({'error':'invalid_progress'},400)
                session['progress'] = [dict(media=media,position=position,duration=duration,watched=bool(payload.get('watched')),updated=self.clock())]+[p for p in session['progress'] if p['media']!=media]
                return send(session['progress'])
            if path == '/lists' and payload.get('kind') in ('favourite','watchlist'):
                session['lists']=[p for p in session['lists'] if not (p['media']==media and p['kind']==payload['kind'])]
                if payload.get('enabled') is True:
                    session['lists'].append(dict(media=media,kind=payload['kind']))
                return send(session['lists'])
            return send({'error':'fixture_endpoint_only'},404)
        query = parse_qs(environ.get('QUERY_STRING',''))
        if path == '/auth/me': return send({'username':'Temporary sample viewer','role':'member'})
        if path == '/media': return send(dict(items=self.catalog,libraries=[dict(name=n) for n in ['Movies','TV Shows','Maltese Drama','Music Videos','Music']],revision=1))
        if path in ('/progress','/lists'): return send(session[path[1:]])
        if path == '/live-tv/access': return send({'allowed':True})
        if path == '/live-tv': return send(dict(sources=[dict(id='sample',name='Sample playlist')],channels=[dict(id='live:sample'+str(n),title='Sample channel '+str(n+1),source='sample',image='/api/artwork?path=channel',streamUrl='/api/stream/live'+str(n)+'.mp4') for n in range(3)]))
        media = query.get('path',[''])[0]
        if path == '/probe':
            if not any(i['id']==media for i in self.catalog):return send({'error':'unknown_fixture'},404)
            audio=media.endswith('.mp3')
            tracks=[dict(index=1,type='audio',codec='mp3' if audio else 'aac',language='mlt',default=True)]
            if not audio:tracks=[dict(index=0,type='video',codec='h264',pixelFormat='yuv420p')]+tracks+[dict(index=2,type='subtitle',codec='webvtt',language='mlt',title='Maltese')]
            return send(dict(duration=24,container='mp3' if audio else 'mp4',tracks=tracks))
        if path == '/prepare' and any(i['id']==media for i in self.catalog):return send(dict(state='ready',url='/api/stream/compatible.mp4',progressive=False))
        if path == '/subtitle':return send('WEBVTT\n\n00:00.000 --> 00:20.000\nMerhba! Dan huwa test lokali.\n',mime='text/vtt')
        if path == '/artwork':
            item=next((i for i in self.catalog if i['id']==media),{})
            name=item.get('sampleArtwork')
            target=self.root/'public'/'artwork'/name if name in ('metropolis.jpg','caligari.jpg','caligari-red.jpg') else self.root/'public/sample-poster.svg'
            return self.file(environ,start,target)
        if path.startswith('/stream/'):
            name=path.rsplit('/',1)[-1]
            if name=='sample-hls.m3u8' or re.fullmatch(r'sample-hls-\d{3}\.ts',name):target=self.root/'fixtures'/name
            elif name.endswith('.mp3'):target=self.root/'fixtures/sample.mp3'
            else:target=self.root/'fixtures/sample.mp4'
            return self.file(environ,start,target)
        return send({'error':'fixture_endpoint_only'},404)


application = FixtureApp()
