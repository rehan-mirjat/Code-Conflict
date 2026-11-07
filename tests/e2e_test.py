"""End-to-end tests for the Code & Conflict site (Selenium + headless Chromium).

Run:  python3 tests/e2e_test.py
Works offline: CDN assets (Bootstrap etc.) are unreachable in that case, so
errors that only come from the missing CDN are ignored.
"""
import functools, glob, http.server, json, os, re, socketserver, sys, threading, time

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select, WebDriverWait

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 8765
BASE = 'http://127.0.0.1:%d/' % PORT


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a, **k):
        pass


class Srv(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


srv = Srv(('127.0.0.1', PORT), functools.partial(Quiet, directory=ROOT))
threading.Thread(target=srv.serve_forever, daemon=True).start()

results = []


def check(name, cond, extra=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + ('' if cond or not extra else '  -> ' + str(extra)))


def new_driver():
    o = webdriver.ChromeOptions()
    o.binary_location = '/usr/bin/chromium'
    for a in ('--headless=new', '--no-sandbox', '--disable-gpu', '--window-size=1280,900'):
        o.add_argument(a)
    o.set_capability('goog:loggingPrefs', {'browser': 'ALL'})
    o.page_load_strategy = 'eager'
    d = webdriver.Chrome(service=Service('/usr/bin/chromedriver'), options=o)
    d.set_page_load_timeout(30)
    return d


def wait(d, t=8):
    return WebDriverWait(d, t)


def page_problems(d):
    out = []
    for e in d.get_log('browser'):
        m = e['message']
        if e['level'] != 'SEVERE':
            continue
        if re.search(r'cdn\.|cdnjs|jsdelivr|(bootstrap|FullCalendar|Chart) is not defined|favicon', m):
            continue  # offline CDN
        out.append(m)
    return out


def text(d, sel):
    return d.find_element(By.CSS_SELECTOR, sel).text


def js_text(d, sel):  # textContent works even for off-screen elements
    return d.execute_script('return document.querySelector(arguments[0]).textContent', sel)


def click(d, sel):
    el = d.find_element(By.CSS_SELECTOR, sel)
    d.execute_script('arguments[0].scrollIntoView({block:"center"})', el)
    d.execute_script('arguments[0].click()', el)


def fill(d, sel, val):
    el = d.find_element(By.CSS_SELECTOR, sel)
    d.execute_script('arguments[0].scrollIntoView({block:"center"})', el)
    el.clear()
    el.send_keys(val)


def ls(d, key):
    return d.execute_script('return localStorage.getItem(arguments[0])', key)


pages = sorted(os.path.relpath(p, ROOT) for p in glob.glob(ROOT + '/**/*.html', recursive=True))
d = new_driver()
try:
    # 1. Every page loads cleanly (no JS errors / failed local requests)
    for pg in pages:
        d.get(BASE + pg)
        time.sleep(0.4)
        probs = page_problems(d)
        local404 = d.execute_script(
            "return performance.getEntriesByType('resource')"
            ".filter(r=>r.name.startsWith(location.origin) && r.responseStatus>=400).map(r=>r.name)")
        check('loads cleanly: ' + pg, not probs and not local404, probs + local404)

    # 2. Homepage dynamic features
    d.get(BASE + 'index.html')
    time.sleep(1.5)
    n0 = len(d.find_elements(By.CSS_SELECTOR, '#liveFeed li'))
    check('live feed has initial items', n0 >= 3, n0)
    time.sleep(4.5)
    c0 = int(js_text(d, '#feedCount'))
    check('feed adds new items over time', c0 > 3, c0)
    click(d, '#feedToggle')
    c1 = int(js_text(d, '#feedCount'))
    time.sleep(4.5)
    check('pause stops feed', int(js_text(d, '#feedCount')) == c1)
    click(d, '#feedToggle')
    time.sleep(4.5)
    check('resume restarts feed', int(js_text(d, '#feedCount')) > c1)
    check('feed capped at 6 items', len(d.find_elements(By.CSS_SELECTOR, '#liveFeed li')) <= 6)
    check('counter animated to its value', int(js_text(d, '#statRansom').replace(',', '')) >= 1287)
    d.execute_script('window.scrollTo(0,0)')
    time.sleep(1.5)  # page uses smooth scrolling
    check('back-to-top hidden at top', 'show' not in d.find_element(By.ID, 'cc-top').get_attribute('class'))
    d.execute_script('window.scrollTo(0,1500)')
    time.sleep(0.5)
    check('back-to-top shown after scrolling', 'show' in d.find_element(By.ID, 'cc-top').get_attribute('class'))
    check('progress bar grows', d.execute_script("return parseFloat(document.getElementById('cc-progress').style.width)") > 0)
    click(d, '#cc-top')
    time.sleep(1.5)
    check('back-to-top scrolls to top', d.execute_script('return window.scrollY') < 50)
    click(d, '#phishBtn')
    check('phishing quiz correct answer', 'Correct' in js_text(d, '#phishResult'))
    click(d, '#legitBtn')
    check('phishing quiz wrong answer', 'Incorrect' in js_text(d, '#phishResult'))
    click(d, '#checklistSubmit')
    check('security checklist gives feedback',
          d.execute_script("return document.querySelector('#checklistSubmit').parentNode.querySelectorAll('.alert').length") >= 1)

    # 3. Search routing (from root, subfolder, and fallback)
    for start, q, dest in [('index.html', 'ransomware', 'threats/ransomware.html'),
                           ('prevention/email_security.html', 'vpn', 'prevention/network_security.html'),
                           ('threats/malware.html', 'zzzz', 'threats/threats_view.html')]:
        d.get(BASE + start)
        time.sleep(0.4)
        box = d.find_element(By.CSS_SELECTOR, 'input[type=search]')
        d.execute_script('arguments[0].scrollIntoView()', box)
        box.send_keys(q + Keys.ENTER)
        try:
            wait(d, 5).until(EC.url_contains(dest))
        except TimeoutException:
            pass
        check('search %r from %s' % (q, start), d.current_url.endswith(dest), d.current_url)

    # 4. Signup -> login -> logout (same browser session = same localStorage)
    d.get(BASE + 'signup.html')
    d.execute_script('localStorage.clear()')
    d.get(BASE + 'signup.html')
    fill(d, '#registerEmail', 'tester@usindh.edu.pk')
    fill(d, '#registerPassword', 'weak')
    check('weak passphrase keeps button disabled', d.find_element(By.ID, 'registerBtn').get_attribute('disabled') is not None)
    pw = 'Str0ng!Passphrase#1'
    fill(d, '#registerPassword', pw)
    fill(d, '#confirmPassword', pw)
    check('strong passphrase enables button', d.find_element(By.ID, 'registerBtn').get_attribute('disabled') is None)
    click(d, '#agreeTerms')
    click(d, '#verifyStudent')
    fill(d, '#captchaInput', 'WRONG1')
    click(d, '#registerBtn')
    try:
        wait(d, 3).until(EC.alert_is_present())
        al = d.switch_to.alert
        check('wrong captcha rejected', 'CAPTCHA' in al.text)
        al.accept()
    except TimeoutException:
        check('wrong captcha rejected', False, 'no alert')
    fill(d, '#captchaInput', js_text(d, '#captchaText'))
    click(d, '#registerBtn')
    try:
        wait(d, 6).until(EC.url_contains('login.html'))
    except TimeoutException:
        pass
    check('signup succeeds and redirects to login', d.current_url.endswith('login.html'), d.current_url)
    stored = ls(d, 'cc_users') or ''
    check('passphrase stored hashed, not plaintext', 'hash' in stored and pw not in stored)

    d.get(BASE + 'signup.html')  # duplicate email
    fill(d, '#registerEmail', 'tester@usindh.edu.pk')
    fill(d, '#registerPassword', pw)
    fill(d, '#confirmPassword', pw)
    click(d, '#agreeTerms')
    click(d, '#verifyStudent')
    fill(d, '#captchaInput', js_text(d, '#captchaText'))
    click(d, '#registerBtn')
    try:
        wait(d, 4).until(EC.presence_of_element_located((By.CSS_SELECTOR, '.alert-danger')))
        check('duplicate email rejected', 'already exists' in js_text(d, '.alert-danger'))
    except TimeoutException:
        check('duplicate email rejected', False, 'no error shown')

    d.get(BASE + 'login.html')  # wrong password
    fill(d, '#loginEmail', 'tester@usindh.edu.pk')
    fill(d, '#loginPassword', 'WrongPassword!1')
    fill(d, '#login2FA', '123456')
    click(d, '#loginForm button[type=submit]')
    try:
        wait(d, 4).until(EC.presence_of_element_located((By.CSS_SELECTOR, '.card-body > .alert-danger')))
        check('wrong password rejected', 'Invalid' in js_text(d, '.card-body > .alert-danger'))
    except TimeoutException:
        check('wrong password rejected', False, 'no error shown')
    check('no session after failed login', ls(d, 'cc_session') is None)

    fill(d, '#loginPassword', pw)
    click(d, '#loginForm button[type=submit]')
    try:
        wait(d, 6).until(EC.url_contains('index.html'))
        wait(d, 4).until(EC.presence_of_element_located((By.ID, 'logoutBtn')))
    except TimeoutException:
        pass
    check('login redirects home and shows username', 'tester' in d.execute_script("return document.querySelector('nav').textContent"), d.current_url)
    d.get(BASE + 'threats/malware.html')
    time.sleep(0.5)
    check('session persists on subpage', len(d.find_elements(By.ID, 'logoutBtn')) == 1)
    click(d, '#logoutBtn')
    try:
        wait(d, 4).until(EC.url_contains('index.html'))
    except TimeoutException:
        pass
    time.sleep(0.5)
    check('logout restores login button', len(d.find_elements(By.CSS_SELECTOR, 'a.btn[href$="login.html"]')) == 1 and ls(d, 'cc_session') is None)

    # 5. Contact form
    d.get(BASE + 'contact.html')
    d.execute_script("localStorage.removeItem('cc_messages')")
    click(d, '#contactForm button[type=submit]')
    check('empty contact form is not stored', ls(d, 'cc_messages') is None)
    fill(d, '#name', 'Ali')
    fill(d, '#email', 'ali@example.com')
    Select(d.find_element(By.ID, 'subject')).select_by_index(1)
    fill(d, '#message', 'Hello team')
    a, b = map(int, re.findall(r'\d+', js_text(d, '#captchaQuestion')))
    fill(d, '#captchaAnswer', str(a + b + 1))
    click(d, '#contactForm button[type=submit]')
    check('wrong contact captcha is not stored', ls(d, 'cc_messages') is None)
    fill(d, '#captchaAnswer', str(a + b))
    click(d, '#contactForm button[type=submit]')
    time.sleep(0.5)
    msgs = json.loads(ls(d, 'cc_messages') or '[]')
    check('valid contact message stored', len(msgs) == 1 and msgs[0]['name'] == 'Ali', msgs)
    check('contact form resets after sending', d.find_element(By.ID, 'name').get_attribute('value') == '')
    check('success toast shown', len(d.find_elements(By.CSS_SELECTOR, '.cc-toast')) >= 1)

    # 6. Password reset
    d.get(BASE + 'password-reset.html')
    fill(d, '#resetEmail', 'x@usindh.edu.pk')
    click(d, '#resetForm button[type=submit]')
    check('password reset shows confirmation', 'reset instructions' in js_text(d, '#resetResult'))
finally:
    d.quit()
    srv.shutdown()

failed = [n for n, ok in results if not ok]
print('\n%d/%d checks passed' % (len(results) - len(failed), len(results)))
sys.exit(1 if failed else 0)
