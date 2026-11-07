// Shared site behaviour for Code & Conflict:
// navbar search, auth (client-side demo), toasts, scroll effects,
// animated counters and the live threat feed.
(function () {
    'use strict';

    var script = document.currentScript;
    var root = script ? script.src.replace(/assets\/js\/main\.js.*$/, '') : '';
    var CC = window.CC = window.CC || {};

    function $(sel, ctx) { return (ctx || document).querySelector(sel); }
    function $all(sel, ctx) { return Array.prototype.slice.call((ctx || document).querySelectorAll(sel)); }

    /* ---------------------------------------------------------- Toasts */
    CC.toast = function (message, type) {
        var box = $('#cc-toasts');
        if (!box) {
            box = document.createElement('div');
            box.id = 'cc-toasts';
            box.setAttribute('aria-live', 'polite');
            document.body.appendChild(box);
        }
        var el = document.createElement('div');
        el.className = 'cc-toast cc-toast-' + (type || 'info');
        el.textContent = message;
        box.appendChild(el);
        requestAnimationFrame(function () { el.classList.add('show'); });
        setTimeout(function () {
            el.classList.remove('show');
            setTimeout(function () { el.remove(); }, 300);
        }, 3500);
    };

    /* ------------------------------------------------------------ Auth */
    // NOTE: client-side only (localStorage). A demo, not real security.
    var USERS_KEY = 'cc_users', SESSION_KEY = 'cc_session';

    function loadUsers() {
        try { return JSON.parse(localStorage.getItem(USERS_KEY) || '{}'); } catch (e) { return {}; }
    }
    function hash(text) {
        if (window.crypto && crypto.subtle && window.TextEncoder) {
            return crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)).then(function (buf) {
                return Array.prototype.map.call(new Uint8Array(buf), function (b) {
                    return ('0' + b.toString(16)).slice(-2);
                }).join('');
            });
        }
        var h = 5381;
        for (var i = 0; i < text.length; i++) h = ((h << 5) + h + text.charCodeAt(i)) | 0;
        return Promise.resolve('d' + (h >>> 0).toString(16));
    }
    function randomSalt() {
        var a = new Uint8Array(8);
        (window.crypto || { getRandomValues: function (x) { for (var i = 0; i < x.length; i++) x[i] = Math.random() * 256; } }).getRandomValues(a);
        return Array.prototype.map.call(a, function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
    }

    CC.auth = {
        current: function () {
            try { return JSON.parse(localStorage.getItem(SESSION_KEY)); } catch (e) { return null; }
        },
        register: function (email, password, pgp) {
            email = String(email || '').trim().toLowerCase();
            if (!/^[^@\s]+@[^@\s]+\.edu\.pk$/.test(email)) {
                return Promise.resolve({ ok: false, error: 'Please use a valid .edu.pk university email.' });
            }
            var users = loadUsers();
            if (users[email]) {
                return Promise.resolve({ ok: false, error: 'An account with this email already exists.' });
            }
            var salt = randomSalt();
            return hash(salt + password).then(function (h) {
                users[email] = { name: email.split('@')[0], salt: salt, hash: h, pgp: pgp || '', created: new Date().toISOString() };
                localStorage.setItem(USERS_KEY, JSON.stringify(users));
                return { ok: true };
            });
        },
        login: function (email, password) {
            email = String(email || '').trim().toLowerCase();
            var user = loadUsers()[email];
            if (!user) return Promise.resolve({ ok: false, error: 'Invalid email or passphrase.' });
            return hash(user.salt + password).then(function (h) {
                if (h !== user.hash) return { ok: false, error: 'Invalid email or passphrase.' };
                localStorage.setItem(SESSION_KEY, JSON.stringify({ email: email, name: user.name }));
                return { ok: true };
            });
        },
        logout: function () { localStorage.removeItem(SESSION_KEY); }
    };

    function renderAuthState() {
        var loginBtn = $('a.btn[href$="login.html"]');
        if (!loginBtn) return;
        var holder = loginBtn.parentNode;
        var user = CC.auth.current();
        if (!user) return;
        holder.innerHTML = '';
        var hello = document.createElement('span');
        hello.className = 'text-light me-3';
        var icon = document.createElement('i');
        icon.className = 'bi bi-person-circle me-1';
        hello.appendChild(icon);
        hello.appendChild(document.createTextNode(user.name));
        var out = document.createElement('button');
        out.type = 'button';
        out.className = 'btn btn-outline-light';
        out.id = 'logoutBtn';
        out.innerHTML = '<i class="bi bi-box-arrow-right"></i> Logout';
        out.addEventListener('click', function () {
            CC.auth.logout();
            window.location.href = root + 'index.html';
        });
        holder.appendChild(hello);
        holder.appendChild(out);
    }

    /* ---------------------------------------------------------- Search */
    var routes = [
        ['malware|virus|trojan|worm|spyware', 'threats/malware.html'],
        ['phish|scam|spoof', 'threats/phishing.html'],
        ['password|brute|credential', 'threats/password_attacks.html'],
        ['ransom|lockbit|encrypt', 'threats/ransomware.html'],
        ['social|manipulat', 'threats/social_engineering.html'],
        ['email|mail', 'prevention/email_security.html'],
        ['privacy|data', 'prevention/data_privacy.html'],
        ['mobile|phone|android|ios', 'prevention/mobile_security.html'],
        ['network|firewall|vpn|wifi|router', 'prevention/network_security.html'],
        ['brows|chrome|firefox|cookie', 'prevention/secure_browsing.html'],
        ['patch|update|cve|vulnerab', 'news/security_patches.html'],
        ['event|conference|calendar|defcon|blackhat', 'news/event_calendar.html'],
        ['industry|news', 'news/industry_news.html'],
        ['latest|zero|attack', 'news/latest_threats.html']
    ];
    var suggestions = ['Malware', 'Phishing', 'Password attacks', 'Ransomware', 'Social engineering',
        'Email security', 'Data privacy', 'Mobile security', 'Network security', 'Secure browsing',
        'Security patches', 'Event calendar', 'Industry news', 'Latest threats'];

    function initSearch() {
        var list = document.createElement('datalist');
        list.id = 'cc-search-suggestions';
        suggestions.forEach(function (s) {
            var o = document.createElement('option');
            o.value = s;
            list.appendChild(o);
        });
        document.body.appendChild(list);

        $all('form[role="search"]').forEach(function (form) {
            var input = $('input[type="search"]', form);
            if (input) input.setAttribute('list', list.id);
            form.addEventListener('submit', function (e) {
                e.preventDefault();
                var q = input ? input.value.trim().toLowerCase() : '';
                if (!q) return;
                var target = 'threats/threats_view.html';
                for (var i = 0; i < routes.length; i++) {
                    if (new RegExp(routes[i][0]).test(q)) { target = routes[i][1]; break; }
                }
                window.location.href = root + target;
            });
        });
    }

    /* -------------------------------------------------- Scroll effects */
    function initScrollEffects() {
        var bar = document.createElement('div');
        bar.id = 'cc-progress';
        document.body.appendChild(bar);

        var top = document.createElement('button');
        top.id = 'cc-top';
        top.type = 'button';
        top.setAttribute('aria-label', 'Back to top');
        top.innerHTML = '<i class="bi bi-arrow-up"></i>';
        top.addEventListener('click', function () { window.scrollTo({ top: 0, behavior: 'smooth' }); });
        document.body.appendChild(top);

        function onScroll() {
            var h = document.documentElement;
            var max = h.scrollHeight - h.clientHeight;
            bar.style.width = (max > 0 ? (h.scrollTop / max) * 100 : 0) + '%';
            top.classList.toggle('show', h.scrollTop > 400);
        }
        window.addEventListener('scroll', onScroll, { passive: true });
        onScroll();

        // Reveal cards as they enter the viewport
        if ('IntersectionObserver' in window) {
            var io = new IntersectionObserver(function (entries) {
                entries.forEach(function (en) {
                    if (en.isIntersecting) {
                        en.target.classList.add('cc-visible');
                        io.unobserve(en.target);
                    }
                });
            }, { threshold: 0.1 });
            $all('.card, .timeline-item').forEach(function (el) {
                var r = el.getBoundingClientRect();
                if (r.top > window.innerHeight) {
                    el.classList.add('cc-reveal');
                    io.observe(el);
                }
            });
        }
    }

    /* -------------------------------------------------------- Counters */
    function format(n) { return n.toLocaleString('en-US'); }

    function animateCount(el, target) {
        var start = parseInt(el.textContent.replace(/\D/g, ''), 10) || 0;
        var t0 = performance.now(), dur = 900;
        function step(now) {
            var p = Math.min((now - t0) / dur, 1);
            el.textContent = format(Math.round(start + (target - start) * p));
            if (p < 1) requestAnimationFrame(step);
        }
        requestAnimationFrame(step);
    }
    CC.setCount = animateCount;

    function initCounters() {
        $all('[data-count]').forEach(function (el) {
            var target = parseInt(el.getAttribute('data-count'), 10);
            el.textContent = '0';
            animateCount(el, target);
        });
    }

    /* --------------------------------------------------- Live threat feed */
    var feedPool = [
        { sev: 'critical', type: 'ransom', title: 'LockBit variant encrypting hospital file servers', region: 'Europe' },
        { sev: 'critical', type: 'zero', title: 'Zero-day exploit in VPN gateway observed in the wild', region: 'Global' },
        { sev: 'high', type: 'phish', title: 'Fake Microsoft Teams alerts harvesting credentials', region: 'North America' },
        { sev: 'high', type: 'phish', title: 'Spear-phishing targeting university staff mailboxes', region: 'South Asia' },
        { sev: 'high', type: 'ransom', title: 'Ransomware gang leaks data from logistics firm', region: 'Asia-Pacific' },
        { sev: 'medium', type: 'malware', title: 'Info-stealer bundled with cracked software installers', region: 'Global' },
        { sev: 'medium', type: 'phish', title: 'SMS phishing impersonating a courier service', region: 'Middle East' },
        { sev: 'low', type: 'advisory', title: 'CISA advisory: update exposed router firmware', region: 'USA' },
        { sev: 'medium', type: 'zero', title: 'Browser zero-day patched in emergency update', region: 'Global' },
        { sev: 'low', type: 'advisory', title: 'New guidance on enforcing MFA for admin accounts', region: 'Global' }
    ];
    var sevClass = { critical: 'danger', high: 'warning', medium: 'info', low: 'success' };

    function initFeed() {
        var feed = $('#liveFeed');
        if (!feed) return;
        var statEls = { ransom: $('#statRansom'), phish: $('#statPhish'), zero: $('#statZero') };
        var counts = {};
        Object.keys(statEls).forEach(function (k) {
            counts[k] = statEls[k] ? parseInt(statEls[k].getAttribute('data-count'), 10) : 0;
        });
        var paused = false, MAX = 6, idx = 0;

        function addItem() {
            if (paused) return;
            var d = feedPool[Math.floor(Math.random() * feedPool.length)];
            var li = document.createElement('li');
            li.className = 'list-group-item bg-transparent d-flex align-items-start gap-3 cc-feed-item';
            li.setAttribute('data-sev', d.sev);

            var badge = document.createElement('span');
            badge.className = 'badge text-bg-' + sevClass[d.sev] + ' text-uppercase';
            badge.textContent = d.sev;

            var body = document.createElement('div');
            body.className = 'flex-grow-1';
            var title = document.createElement('div');
            title.className = 'fw-semibold';
            title.textContent = d.title;
            var meta = document.createElement('small');
            meta.className = 'text-muted';
            meta.textContent = d.region + ' \u00b7 ' + new Date().toLocaleTimeString();
            body.appendChild(title);
            body.appendChild(meta);

            li.appendChild(badge);
            li.appendChild(body);
            feed.insertBefore(li, feed.firstChild);
            requestAnimationFrame(function () { li.classList.add('in'); });
            while (feed.children.length > MAX) feed.removeChild(feed.lastChild);

            if (statEls[d.type]) {
                counts[d.type] += 1;
                animateCount(statEls[d.type], counts[d.type]);
            }
            var n = $('#feedCount');
            if (n) n.textContent = String(++idx);
        }

        for (var i = 0; i < 3; i++) addItem();
        setInterval(addItem, 4000);

        var btn = $('#feedToggle');
        if (btn) {
            btn.addEventListener('click', function () {
                paused = !paused;
                btn.innerHTML = paused
                    ? '<i class="bi bi-play-fill"></i> Resume'
                    : '<i class="bi bi-pause-fill"></i> Pause';
                btn.setAttribute('aria-pressed', String(paused));
            });
        }
    }

    /* ------------------------------------------------------------ Init */
    function init() {
        renderAuthState();
        initSearch();
        initScrollEffects();
        initCounters();
        initFeed();
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
