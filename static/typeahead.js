/**
 * typeahead.js — handle typeahead for AIP login forms.
 *
 * Community-run, unauthenticated, CORS-enabled actor search for atproto:
 *   GET https://typeahead.waow.tech/xrpc/tech.waow.typeahead.searchActors?q=<prefix>&limit=10
 * See https://typeahead.waow.tech/llms.txt
 *
 * Attaches to every <input data-typeahead> on the page (login + app-password
 * forms both use id="login_hint"). Vanilla JS, no dependencies. Degrades
 * gracefully to the plain text input if the service is unreachable.
 */
(function () {
  'use strict';

  var API = 'https://typeahead.waow.tech/xrpc/tech.waow.typeahead.searchActors';
  var DEBOUNCE_MS = 150;
  var MIN_CHARS = 2;
  var LIMIT = 10;

  function init() {
    var inputs = document.querySelectorAll('input[data-typeahead]');
    for (var i = 0; i < inputs.length; i++) {
      if (!inputs[i].dataset.typeaheadReady) {
        new Typeahead(inputs[i]);
      }
    }
  }

  function Typeahead(input) {
    this.input = input;
    this.results = [];
    this.active = -1;
    this.timer = null;
    this.abort = null;
    this.build();
    this.bind();
    input.dataset.typeaheadReady = '1';
  }

  Typeahead.prototype.build = function () {
    var box = document.createElement('div');
    box.className = 'typeahead-box';
    box.setAttribute('role', 'listbox');
    box.setAttribute('aria-label', 'Handle suggestions');
    box.hidden = true;

    var field = this.input.closest('label') || this.input.parentElement;
    field.appendChild(box);

    var style = document.createElement('style');
    if (!document.getElementById('typeahead-styles')) {
      style.id = 'typeahead-styles';
      style.textContent =
        '.typeahead-box{position:absolute;top:100%;left:0;right:0;z-index:50;margin-top:.25rem;' +
        'background:#fff;border:1px solid #d3d3d3;border-radius:6px;box-shadow:0 4px 12px rgba(0,0,0,.12);' +
        'max-height:280px;overflow-y:auto;text-align:left}' +
        '.typeahead-label label{position:relative}.typeahead-label>label{position:static}' +
        '.typeahead-item{display:flex;align-items:center;gap:.6rem;padding:.5rem .6rem;cursor:pointer;' +
        'border-bottom:1px solid #f0f0f0;color:#222}.typeahead-item:last-child{border-bottom:0}' +
        '.typeahead-item[aria-selected="true"],.typeahead-item:hover{background:#eaf2ff}' +
        '.typeahead-avatar{width:30px;height:30px;border-radius:50%;flex:0 0 30px;' +
        'background:linear-gradient(135deg,#9bb7ff,#7aa8ff);display:flex;align-items:center;' +
        'justify-content:center;color:#fff;font-weight:600;font-size:14px;overflow:hidden}' +
        '.typeahead-avatar img{width:100%;height:100%;object-fit:cover}' +
        '.typeahead-info{display:flex;flex-direction:column;min-width:0}' +
        '.typeahead-handle{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}' +
        '.typeahead-name{font-size:.8rem;color:#666;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}';
      document.head.appendChild(style);
    }

    var wrapCss = document.createElement('style');
    if (!document.getElementById('typeahead-wrap-styles')) {
      wrapCss.id = 'typeahead-wrap-styles';
      wrapCss.textContent = 'label:has(> .typeahead-box){position:relative;display:block}';
      document.head.appendChild(wrapCss);
    }

    this.reposition();
  };

  Typeahead.prototype.reposition = function () {
    var pos = getComputedStyle(this.input.closest('label') || this.input.parentElement);
    if (pos.position !== 'relative') {
      (this.input.closest('label') || this.input.parentElement).style.position = 'relative';
    }
  };

  Typeahead.prototype.bind = function () {
    var self = this;

    this.input.addEventListener('input', function () {
      clearTimeout(self.timer);
      self.timer = setTimeout(function () {
        var q = self.input.value.trim();
        if (q.length < MIN_CHARS) {
          self.close();
          return;
        }
        self.search(q);
      }, DEBOUNCE_MS);
    });

    this.input.addEventListener('keydown', function (e) {
      if (!self.box || self.box.hidden) return;
      var n = self.results.length;
      switch (e.key) {
        case 'ArrowDown':
          e.preventDefault();
          self.move(1);
          break;
        case 'ArrowUp':
          e.preventDefault();
          self.move(-1);
          break;
        case 'Enter':
          if (self.active >= 0 && self.active < n) {
            e.preventDefault();
            self.select(self.active);
          }
          break;
        case 'Tab':
          if (self.active >= 0 && self.active < n) {
            self.select(self.active);
          }
          break;
        case 'Escape':
          e.preventDefault();
          self.close();
          break;
      }
    });

    this.input.addEventListener('blur', function () {
      setTimeout(function () { self.close(); }, 150);
    });

    this.box.addEventListener('mousedown', function (e) { e.preventDefault(); });
  };

  Typeahead.prototype.search = function (q) {
    var self = this;
    if (this.abort) { this.abort.abort(); }

    var ctrl = new AbortController();
    this.abort = ctrl;
    // Escape helpers
    var url = API + '?q=' + encodeURIComponent(q) + '&limit=' + LIMIT;

    fetch(url, { signal: ctrl.signal })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (ctrl.signal.aborted) return;
        self.results = Array.isArray(data.actors) ? data.actors : [];
        self.active = -1;
        self.render();
      })
      .catch(function () {
        // network error / abort: close silently, plain input still works
        if (!ctrl.signal.aborted) self.close();
      });
  };

  Typeahead.prototype.render = function () {
    var self = this;
    if (!this.results.length) { this.close(); return; }

    this.box.innerHTML = '';
    this.results.forEach(function (actor, i) {
      var item = document.createElement('div');
      item.className = 'typeahead-item';
      item.setAttribute('role', 'option');
      item.setAttribute('aria-selected', 'false');
      item.dataset.index = i;

      var avatar = document.createElement('span');
      avatar.className = 'typeahead-avatar';
      if (actor.avatar) {
        var img = document.createElement('img');
        img.src = actor.avatar;
        img.alt = '';
        img.loading = 'lazy';
        avatar.appendChild(img);
      } else {
        avatar.textContent = (actor.handle || '?').charAt(0).toUpperCase();
      }

      var info = document.createElement('span');
      info.className = 'typeahead-info';
      var h = document.createElement('span');
      h.className = 'typeahead-handle';
      h.textContent = actor.handle || actor.did || '';
      info.appendChild(h);
      if (actor.displayName) {
        var n = document.createElement('span');
        n.className = 'typeahead-name';
        n.textContent = actor.displayName;
        info.appendChild(n);
      }

      item.appendChild(avatar);
      item.appendChild(info);

      item.addEventListener('mousedown', function (e) { e.preventDefault(); });
      item.addEventListener('click', function () { self.select(i); });

      self.box.appendChild(item);
    });

    this.box.hidden = false;
    this.input.setAttribute('aria-expanded', 'true');
  };

  Typeahead.prototype.move = function (delta) {
    var n = this.results.length;
    if (!n) return;
    this.active = (this.active + delta + n) % n;
    this.setActive();
  };

  Typeahead.prototype.setActive = function () {
    var items = this.box.querySelectorAll('.typeahead-item');
    for (var i = 0; i < items.length; i++) {
      var sel = i === this.active;
      items[i].setAttribute('aria-selected', sel ? 'true' : 'false');
      if (sel && items[i].scrollIntoView) {
        items[i].scrollIntoView({ block: 'nearest' });
      }
    }
  };

  Typeahead.prototype.select = function (idx) {
    var actor = this.results[idx];
    if (!actor) return;
    this.input.value = actor.handle || actor.did || this.input.value;
    this.input.focus();
    this.close();
  };

  Typeahead.prototype.close = function () {
    if (this.box) { this.box.hidden = true; this.box.innerHTML = ''; }
    if (this.abort) { this.abort.abort(); this.abort = null; }
    this.results = [];
    this.active = -1;
    this.input.removeAttribute('aria-expanded');
  };

  // kicks off on DOMContentLoaded (defer'd script may run before ready)
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();