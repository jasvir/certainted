"use strict";
(() => {
  // node_modules/preact/dist/preact.module.js
  var n;
  var l;
  var u;
  var t;
  var i;
  var r;
  var o;
  var e;
  var f;
  var c;
  var a;
  var s;
  var h;
  var p;
  var v;
  var y;
  var d = {};
  var w = [];
  var _ = /acit|ex(?:s|g|n|p|$)|rph|grid|ows|mnc|ntw|ine[ch]|zoo|^ord|itera/i;
  var g = Array.isArray;
  function m(n2, l3) {
    for (var u4 in l3) n2[u4] = l3[u4];
    return n2;
  }
  function b(n2) {
    n2 && n2.parentNode && n2.parentNode.removeChild(n2);
  }
  function k(l3, u4, t3) {
    var i3, r3, o3, e3 = {};
    for (o3 in u4) "key" == o3 ? i3 = u4[o3] : "ref" == o3 ? r3 = u4[o3] : e3[o3] = u4[o3];
    if (arguments.length > 2 && (e3.children = arguments.length > 3 ? n.call(arguments, 2) : t3), "function" == typeof l3 && null != l3.defaultProps) for (o3 in l3.defaultProps) void 0 === e3[o3] && (e3[o3] = l3.defaultProps[o3]);
    return x(l3, e3, i3, r3, null);
  }
  function x(n2, t3, i3, r3, o3) {
    var e3 = { type: n2, props: t3, key: i3, ref: r3, __k: null, __: null, __b: 0, __e: null, __c: null, constructor: void 0, __v: null == o3 ? ++u : o3, __i: -1, __u: 0 };
    return null == o3 && null != l.vnode && l.vnode(e3), e3;
  }
  function S(n2) {
    return n2.children;
  }
  function C(n2, l3) {
    this.props = n2, this.context = l3;
  }
  function $(n2, l3) {
    if (null == l3) return n2.__ ? $(n2.__, n2.__i + 1) : null;
    for (var u4; l3 < n2.__k.length; l3++) if (null != (u4 = n2.__k[l3]) && null != u4.__e) return u4.__e;
    return "function" == typeof n2.type ? $(n2) : null;
  }
  function I(n2) {
    if (n2.__P && n2.__d) {
      var u4 = n2.__v, t3 = u4.__e, i3 = [], r3 = [], o3 = m({}, u4);
      o3.__v = u4.__v + 1, l.vnode && l.vnode(o3), q(n2.__P, o3, u4, n2.__n, n2.__P.namespaceURI, 32 & u4.__u ? [t3] : null, i3, null == t3 ? $(u4) : t3, !!(32 & u4.__u), r3), o3.__v = u4.__v, o3.__.__k[o3.__i] = o3, D(i3, o3, r3), u4.__e = u4.__ = null, o3.__e != t3 && P(o3);
    }
  }
  function P(n2) {
    if (null != (n2 = n2.__) && null != n2.__c) return n2.__e = n2.__c.base = null, n2.__k.some(function(l3) {
      if (null != l3 && null != l3.__e) return n2.__e = n2.__c.base = l3.__e;
    }), P(n2);
  }
  function A(n2) {
    (!n2.__d && (n2.__d = true) && i.push(n2) && !H.__r++ || r != l.debounceRendering) && ((r = l.debounceRendering) || o)(H);
  }
  function H() {
    try {
      for (var n2, l3 = 1; i.length; ) i.length > l3 && i.sort(e), n2 = i.shift(), l3 = i.length, I(n2);
    } finally {
      i.length = H.__r = 0;
    }
  }
  function L(n2, l3, u4, t3, i3, r3, o3, e3, f4, c3, a3) {
    var s3, h4, p3, v3, y3, _2, g2 = t3 && t3.__k || w, m3 = l3.length;
    for (f4 = T(u4, l3, g2, f4, m3), s3 = 0; s3 < m3; s3++) null != (p3 = u4.__k[s3]) && (h4 = -1 != p3.__i && g2[p3.__i] || d, p3.__i = s3, _2 = q(n2, p3, h4, i3, r3, o3, e3, f4, c3, a3), v3 = p3.__e, p3.ref && h4.ref != p3.ref && (h4.ref && J(h4.ref, null, p3), a3.push(p3.ref, p3.__c || v3, p3)), null == y3 && null != v3 && (y3 = v3), 4 & p3.__u ? (f4 = j(p3, f4, n2), h4.__e && (h4.__e = null)) : "function" == typeof p3.type && void 0 !== _2 ? f4 = _2 : v3 && (f4 = v3.nextSibling), p3.__u &= -7);
    return u4.__e = y3, f4;
  }
  function T(n2, l3, u4, t3, i3) {
    var r3, o3, e3, f4, c3, a3 = u4.length, s3 = a3, h4 = 0;
    for (n2.__k = new Array(i3), r3 = 0; r3 < i3; r3++) null != (o3 = l3[r3]) && "boolean" != typeof o3 && "function" != typeof o3 ? ("string" == typeof o3 || "number" == typeof o3 || "bigint" == typeof o3 || o3.constructor == String ? o3 = n2.__k[r3] = x(null, o3, null, null, null) : g(o3) ? o3 = n2.__k[r3] = x(S, { children: o3 }, null, null, null) : void 0 === o3.constructor && o3.__b > 0 ? o3 = n2.__k[r3] = x(o3.type, o3.props, o3.key, o3.ref ? o3.ref : null, o3.__v) : n2.__k[r3] = o3, f4 = r3 + h4, o3.__ = n2, o3.__b = n2.__b + 1, e3 = null, -1 != (c3 = o3.__i = O(o3, u4, f4, s3)) && (s3--, (e3 = u4[c3]) && (e3.__u |= 2)), null == e3 || null == e3.__v ? (-1 == c3 && (i3 > a3 ? h4-- : i3 < a3 && h4++), "function" != typeof o3.type && (o3.__u |= 4)) : c3 != f4 && (c3 == f4 - 1 ? h4-- : c3 == f4 + 1 ? h4++ : (c3 > f4 ? h4-- : h4++, o3.__u |= 4))) : n2.__k[r3] = null;
    if (s3) for (r3 = 0; r3 < a3; r3++) null != (e3 = u4[r3]) && 0 == (2 & e3.__u) && (e3.__e == t3 && (t3 = $(e3)), K(e3, e3));
    return t3;
  }
  function j(n2, l3, u4) {
    var t3, i3;
    if ("function" == typeof n2.type) {
      for (t3 = n2.__k, i3 = 0; t3 && i3 < t3.length; i3++) t3[i3] && (t3[i3].__ = n2, l3 = j(t3[i3], l3, u4));
      return l3;
    }
    n2.__e != l3 && (l3 && n2.type && !l3.parentNode && (l3 = $(n2)), l3 = u4.insertBefore(n2.__e, l3 || null));
    do {
      l3 = l3 && l3.nextSibling;
    } while (null != l3 && 8 == l3.nodeType);
    return l3;
  }
  function O(n2, l3, u4, t3) {
    var i3, r3, o3, e3 = n2.key, f4 = n2.type, c3 = l3[u4], a3 = null != c3 && 0 == (2 & c3.__u);
    if (null === c3 && null == e3 || a3 && e3 == c3.key && f4 == c3.type) return u4;
    if (t3 > (a3 ? 1 : 0)) {
      for (i3 = u4 - 1, r3 = u4 + 1; i3 >= 0 || r3 < l3.length; ) if (null != (c3 = l3[o3 = i3 >= 0 ? i3-- : r3++]) && 0 == (2 & c3.__u) && e3 == c3.key && f4 == c3.type) return o3;
    }
    return -1;
  }
  function z(n2, l3, u4) {
    "-" == l3[0] ? n2.setProperty(l3, null == u4 ? "" : u4) : n2[l3] = null == u4 ? "" : "number" != typeof u4 || _.test(l3) ? u4 : u4 + "px";
  }
  function N(n2, l3, u4, t3, i3) {
    var r3, o3;
    n: if ("style" == l3) if ("string" == typeof u4) n2.style.cssText = u4;
    else {
      if ("string" == typeof t3 && (n2.style.cssText = t3 = ""), t3) for (l3 in t3) u4 && l3 in u4 || z(n2.style, l3, "");
      if (u4) for (l3 in u4) t3 && u4[l3] == t3[l3] || z(n2.style, l3, u4[l3]);
    }
    else if ("o" == l3[0] && "n" == l3[1]) r3 = l3 != (l3 = l3.replace(s, "$1")), o3 = l3.toLowerCase(), l3 = o3 in n2 || "onFocusOut" == l3 || "onFocusIn" == l3 ? o3.slice(2) : l3.slice(2), n2.l || (n2.l = {}), n2.l[l3 + r3] = u4, u4 ? t3 ? u4[a] = t3[a] : (u4[a] = h, n2.addEventListener(l3, r3 ? v : p, r3)) : n2.removeEventListener(l3, r3 ? v : p, r3);
    else {
      if ("http://www.w3.org/2000/svg" == i3) l3 = l3.replace(/xlink(H|:h)/, "h").replace(/sName$/, "s");
      else if ("width" != l3 && "height" != l3 && "href" != l3 && "list" != l3 && "form" != l3 && "tabIndex" != l3 && "download" != l3 && "rowSpan" != l3 && "colSpan" != l3 && "role" != l3 && "popover" != l3 && l3 in n2) try {
        n2[l3] = null == u4 ? "" : u4;
        break n;
      } catch (n3) {
      }
      "function" == typeof u4 || (null == u4 || false === u4 && "-" != l3[4] ? n2.removeAttribute(l3) : n2.setAttribute(l3, "popover" == l3 && 1 == u4 ? "" : u4));
    }
  }
  function V(n2) {
    return function(u4) {
      if (this.l) {
        var t3 = this.l[u4.type + n2];
        if (null == u4[c]) u4[c] = h++;
        else if (u4[c] < t3[a]) return;
        return t3(l.event ? l.event(u4) : u4);
      }
    };
  }
  function q(n2, u4, t3, i3, r3, o3, e3, f4, c3, a3) {
    var s3, h4, p3, v3, y3, d3, _2, k3, x2, M, I2, P2, A3, H2, T3, j3, F = u4.type;
    if (void 0 !== u4.constructor) return null;
    128 & t3.__u && (c3 = !!(32 & t3.__u), o3 = [f4 = u4.__e = t3.__e]), (s3 = l.__b) && s3(u4);
    n: if ("function" == typeof F) {
      h4 = e3.length;
      try {
        if (x2 = u4.props, M = F.prototype && F.prototype.render, I2 = (s3 = F.contextType) && i3[s3.__c], P2 = s3 ? I2 ? I2.props.value : s3.__ : i3, t3.__c ? k3 = (p3 = u4.__c = t3.__c).__ = p3.__E : (M ? u4.__c = p3 = new F(x2, P2) : (u4.__c = p3 = new C(x2, P2), p3.constructor = F, p3.render = Q), I2 && I2.sub(p3), p3.state || (p3.state = {}), p3.__n = i3, v3 = p3.__d = true, p3.__h = [], p3._sb = []), M && null == p3.__s && (p3.__s = p3.state), M && null != F.getDerivedStateFromProps && (p3.__s == p3.state && (p3.__s = m({}, p3.__s)), m(p3.__s, F.getDerivedStateFromProps(x2, p3.__s))), y3 = p3.props, d3 = p3.state, p3.__v = u4, v3) M && null == F.getDerivedStateFromProps && null != p3.componentWillMount && p3.componentWillMount(), M && null != p3.componentDidMount && p3.__h.push(p3.componentDidMount);
        else {
          if (M && null == F.getDerivedStateFromProps && x2 !== y3 && null != p3.componentWillReceiveProps && p3.componentWillReceiveProps(x2, P2), u4.__v == t3.__v || !p3.__e && null != p3.shouldComponentUpdate && false === p3.shouldComponentUpdate(x2, p3.__s, P2)) {
            u4.__v != t3.__v && (p3.props = x2, p3.state = p3.__s, p3.__d = false), u4.__e = t3.__e, u4.__k = t3.__k, u4.__k.some(function(n3) {
              n3 && (n3.__ = u4);
            }), w.push.apply(p3.__h, p3._sb), p3._sb = [], p3.__h.length && e3.push(p3), f4 = $(t3);
            break n;
          }
          null != p3.componentWillUpdate && p3.componentWillUpdate(x2, p3.__s, P2), M && null != p3.componentDidUpdate && p3.__h.push(function() {
            p3.componentDidUpdate(y3, d3, _2);
          });
        }
        if (p3.context = P2, p3.props = x2, p3.__P = n2, p3.__e = false, A3 = l.__r, H2 = 0, M) p3.state = p3.__s, p3.__d = false, A3 && A3(u4), s3 = p3.render(p3.props, p3.state, p3.context), w.push.apply(p3.__h, p3._sb), p3._sb = [];
        else do {
          p3.__d = false, A3 && A3(u4), s3 = p3.render(p3.props, p3.state, p3.context), p3.state = p3.__s;
        } while (p3.__d && ++H2 < 25);
        p3.state = p3.__s, null != p3.getChildContext && (i3 = m(m({}, i3), p3.getChildContext())), M && !v3 && null != p3.getSnapshotBeforeUpdate && (_2 = p3.getSnapshotBeforeUpdate(y3, d3)), T3 = null != s3 && s3.type === S && null == s3.key ? E(s3.props.children) : s3, f4 = L(n2, g(T3) ? T3 : [T3], u4, t3, i3, r3, o3, e3, f4, c3, a3), p3.base = u4.__e, u4.__u &= -161, p3.__h.length && e3.push(p3), k3 && (p3.__E = p3.__ = null);
      } catch (n3) {
        if (e3.length = h4, u4.__v = null, c3 || null != o3) {
          if (n3.then) {
            for (u4.__u |= c3 ? 160 : 128; f4 && 8 == f4.nodeType && f4.nextSibling; ) f4 = f4.nextSibling;
            null != o3 && (o3[o3.indexOf(f4)] = null), u4.__e = f4;
          } else if (null != o3) for (j3 = o3.length; j3--; ) b(o3[j3]);
        } else u4.__e = t3.__e;
        null == u4.__k && (u4.__k = t3.__k || []), n3.then || B(u4), l.__e(n3, u4, t3);
      }
    } else null == o3 && u4.__v == t3.__v ? (u4.__k = t3.__k, u4.__e = t3.__e) : f4 = u4.__e = G(t3.__e, u4, t3, i3, r3, o3, e3, c3, a3);
    return (s3 = l.diffed) && s3(u4), 128 & u4.__u ? void 0 : f4;
  }
  function B(n2) {
    n2 && (n2.__c && (n2.__c.__e = true), n2.__k && n2.__k.some(B));
  }
  function D(n2, u4, t3) {
    for (var i3 = 0; i3 < t3.length; i3++) J(t3[i3], t3[++i3], t3[++i3]);
    l.__c && l.__c(u4, n2), n2.some(function(u5) {
      try {
        n2 = u5.__h, u5.__h = [], n2.some(function(n3) {
          n3.call(u5);
        });
      } catch (n3) {
        l.__e(n3, u5.__v);
      }
    });
  }
  function E(n2) {
    return "object" != typeof n2 || null == n2 || n2.__b > 0 ? n2 : g(n2) ? n2.map(E) : void 0 !== n2.constructor ? null : m({}, n2);
  }
  function G(u4, t3, i3, r3, o3, e3, f4, c3, a3) {
    var s3, h4, p3, v3, y3, w3, _2, m3 = i3.props || d, k3 = t3.props, x2 = t3.type;
    if ("svg" == x2 ? o3 = "http://www.w3.org/2000/svg" : "math" == x2 ? o3 = "http://www.w3.org/1998/Math/MathML" : o3 || (o3 = "http://www.w3.org/1999/xhtml"), null != e3) {
      for (s3 = 0; s3 < e3.length; s3++) if ((y3 = e3[s3]) && "setAttribute" in y3 == !!x2 && (x2 ? y3.localName == x2 : 3 == y3.nodeType)) {
        u4 = y3, e3[s3] = null;
        break;
      }
    }
    if (null == u4) {
      if (null == x2) return document.createTextNode(k3);
      u4 = document.createElementNS(o3, x2, k3.is && k3), c3 && (l.__m && l.__m(t3, e3), c3 = false), e3 = null;
    }
    if (null == x2) m3 === k3 || c3 && u4.data == k3 || (u4.data = k3);
    else {
      if (e3 = "textarea" == x2 && null != k3.defaultValue ? null : e3 && n.call(u4.childNodes), !c3 && null != e3) for (m3 = {}, s3 = 0; s3 < u4.attributes.length; s3++) m3[(y3 = u4.attributes[s3]).name] = y3.value;
      for (s3 in m3) y3 = m3[s3], "dangerouslySetInnerHTML" == s3 ? p3 = y3 : "children" == s3 || s3 in k3 || "value" == s3 && "defaultValue" in k3 || "checked" == s3 && "defaultChecked" in k3 || N(u4, s3, null, y3, o3);
      for (s3 in k3) y3 = k3[s3], "children" == s3 ? v3 = y3 : "dangerouslySetInnerHTML" == s3 ? h4 = y3 : "value" == s3 ? w3 = y3 : "checked" == s3 ? _2 = y3 : c3 && "function" != typeof y3 || m3[s3] === y3 || N(u4, s3, y3, m3[s3], o3);
      if (h4) c3 || p3 && (h4.__html == p3.__html || h4.__html == u4.innerHTML) || (u4.innerHTML = h4.__html), t3.__k = [];
      else if (p3 && (u4.innerHTML = ""), L("template" == t3.type ? u4.content : u4, g(v3) ? v3 : [v3], t3, i3, r3, "foreignObject" == x2 ? "http://www.w3.org/1999/xhtml" : o3, e3, f4, e3 ? e3[0] : i3.__k && $(i3, 0), c3, a3), null != e3) for (s3 = e3.length; s3--; ) b(e3[s3]);
      c3 && "textarea" != x2 || (s3 = "value", "progress" == x2 && null == w3 ? u4.removeAttribute("value") : null != w3 && (w3 !== u4[s3] || "progress" == x2 && !w3 || "option" == x2 && w3 != m3[s3]) && N(u4, s3, w3, m3[s3], o3), s3 = "checked", null != _2 && _2 != u4[s3] && N(u4, s3, _2, m3[s3], o3));
    }
    return u4;
  }
  function J(n2, u4, t3) {
    try {
      if ("function" == typeof n2) {
        var i3 = "function" == typeof n2.__u;
        i3 && n2.__u(), i3 && null == u4 || (n2.__u = n2(u4));
      } else n2.current = u4;
    } catch (n3) {
      l.__e(n3, t3);
    }
  }
  function K(n2, u4, t3) {
    var i3, r3;
    if (l.unmount && l.unmount(n2), (i3 = n2.ref) && (i3.current && i3.current != n2.__e || J(i3, null, u4)), null != (i3 = n2.__c)) {
      if (i3.componentWillUnmount) try {
        i3.componentWillUnmount();
      } catch (n3) {
        l.__e(n3, u4);
      }
      i3.base = i3.__P = i3.__n = null;
    }
    if (i3 = n2.__k) for (r3 = 0; r3 < i3.length; r3++) i3[r3] && K(i3[r3], u4, t3 || "function" != typeof n2.type);
    t3 || b(n2.__e), n2.__c = n2.__ = n2.__e = void 0;
  }
  function Q(n2, l3, u4) {
    return this.constructor(n2, u4);
  }
  function R(u4, t3, i3) {
    var r3, o3, e3, f4;
    t3 == document && (t3 = document.documentElement), l.__ && l.__(u4, t3), o3 = (r3 = "function" == typeof i3) ? null : i3 && i3.__k || t3.__k, e3 = [], f4 = [], q(t3, u4 = (!r3 && i3 || t3).__k = k(S, null, [u4]), o3 || d, d, t3.namespaceURI, !r3 && i3 ? [i3] : o3 ? null : t3.firstChild ? n.call(t3.childNodes) : null, e3, !r3 && i3 ? i3 : o3 ? o3.__e : t3.firstChild, r3, f4), D(e3, u4, f4), u4.props.children = null;
  }
  n = w.slice, l = { __e: function(n2, l3, u4, t3) {
    for (var i3, r3, o3; l3 = l3.__; ) if ((i3 = l3.__c) && !i3.__) try {
      if ((r3 = i3.constructor) && null != r3.getDerivedStateFromError && (i3.setState(r3.getDerivedStateFromError(n2)), o3 = i3.__d), null != i3.componentDidCatch && (i3.componentDidCatch(n2, t3 || {}), o3 = i3.__d), o3) return i3.__E = i3;
    } catch (l4) {
      n2 = l4;
    }
    throw n2;
  } }, u = 0, t = function(n2) {
    return null != n2 && void 0 === n2.constructor;
  }, C.prototype.setState = function(n2, l3) {
    var u4;
    u4 = null != this.__s && this.__s != this.state ? this.__s : this.__s = m({}, this.state), "function" == typeof n2 && (n2 = n2(m({}, u4), this.props)), n2 && m(u4, n2), null != n2 && this.__v && (l3 && this._sb.push(l3), A(this));
  }, C.prototype.forceUpdate = function(n2) {
    this.__v && (this.__e = true, n2 && this.__h.push(n2), A(this));
  }, C.prototype.render = S, i = [], o = "function" == typeof Promise ? Promise.prototype.then.bind(Promise.resolve()) : setTimeout, e = function(n2, l3) {
    return n2.__v.__b - l3.__v.__b;
  }, H.__r = 0, f = Math.random().toString(8), c = "__d" + f, a = "__a" + f, s = /(PointerCapture)$|Capture$/i, h = 0, p = V(false), v = V(true), y = 0;

  // node_modules/preact/hooks/dist/hooks.module.js
  var t2;
  var r2;
  var u2;
  var i2;
  var o2 = 0;
  var f2 = [];
  var c2 = l;
  var e2 = c2.__b;
  var a2 = c2.__r;
  var v2 = c2.diffed;
  var l2 = c2.__c;
  var m2 = c2.unmount;
  var p2 = c2.__;
  function s2(n2, t3) {
    c2.__h && c2.__h(r2, n2, o2 || t3), o2 = 0;
    var u4 = r2.__H || (r2.__H = { __: [], __h: [] });
    return n2 >= u4.__.length && u4.__.push({}), u4.__[n2];
  }
  function d2(n2) {
    return o2 = 1, y2(D2, n2);
  }
  function y2(n2, u4, i3) {
    var o3 = s2(t2++, 2);
    if (o3.t = n2, !o3.__c && (o3.__ = [i3 ? i3(u4) : D2(void 0, u4), function(n3) {
      var t3 = o3.__N ? o3.__N[0] : o3.__[0], r3 = o3.t(t3, n3);
      t3 !== r3 && (o3.__N = [r3, o3.__[1]], o3.__c.setState({}));
    }], o3.__c = r2, !r2.__f)) {
      var f4 = function(n3, t3, r3) {
        if (!o3.__c.__H) return true;
        var u5 = false, i4 = o3.__c.props !== n3;
        if (o3.__c.__H.__.some(function(n4) {
          if (n4.__N) {
            u5 = true;
            var t4 = n4.__[0];
            n4.__ = n4.__N, n4.__N = void 0, t4 !== n4.__[0] && (i4 = true);
          }
        }), c3) {
          var f5 = c3.call(this, n3, t3, r3);
          return u5 ? f5 || i4 : f5;
        }
        return !u5 || i4;
      };
      r2.__f = true;
      var c3 = r2.shouldComponentUpdate, e3 = r2.componentWillUpdate;
      r2.componentWillUpdate = function(n3, t3, r3) {
        if (this.__e) {
          var u5 = c3;
          c3 = void 0, f4(n3, t3, r3), c3 = u5;
        }
        e3 && e3.call(this, n3, t3, r3);
      }, r2.shouldComponentUpdate = f4;
    }
    return o3.__N || o3.__;
  }
  function h2(n2, u4) {
    var i3 = s2(t2++, 3);
    !c2.__s && C2(i3.__H, u4) && (i3.__ = n2, i3.u = u4, r2.__H.__h.push(i3));
  }
  function A2(n2) {
    return o2 = 5, T2(function() {
      return { current: n2 };
    }, []);
  }
  function T2(n2, r3) {
    var u4 = s2(t2++, 7);
    return C2(u4.__H, r3) && (u4.__ = n2(), u4.__H = r3, u4.__h = n2), u4.__;
  }
  function q2(n2, t3) {
    return o2 = 8, T2(function() {
      return n2;
    }, t3);
  }
  function j2() {
    for (var n2; n2 = f2.shift(); ) {
      var t3 = n2.__H;
      if (n2.__P && t3) try {
        t3.__h.some(z2), t3.__h.some(B2), t3.__h = [];
      } catch (r3) {
        t3.__h = [], c2.__e(r3, n2.__v);
      }
    }
  }
  c2.__b = function(n2) {
    r2 = null, e2 && e2(n2);
  }, c2.__ = function(n2, t3) {
    n2 && t3.__k && t3.__k.__m && (n2.__m = t3.__k.__m), p2 && p2(n2, t3);
  }, c2.__r = function(n2) {
    a2 && a2(n2), t2 = 0;
    var i3 = (r2 = n2.__c).__H;
    i3 && (u2 === r2 ? (i3.__h = [], r2.__h = [], i3.__.some(function(n3) {
      n3.__N && (n3.__ = n3.__N), n3.u = n3.__N = void 0;
    })) : (i3.__h.some(z2), i3.__h.some(B2), i3.__h = [], t2 = 0)), u2 = r2;
  }, c2.diffed = function(n2) {
    v2 && v2(n2);
    var t3 = n2.__c;
    t3 && t3.__H && (t3.__H.__h.length && (1 !== f2.push(t3) && i2 === c2.requestAnimationFrame || ((i2 = c2.requestAnimationFrame) || w2)(j2)), t3.__H.__.some(function(n3) {
      n3.u && (n3.__H = n3.u, n3.u = void 0);
    })), u2 = r2 = null;
  }, c2.__c = function(n2, t3) {
    t3.some(function(n3) {
      try {
        n3.__h.some(z2), n3.__h = n3.__h.filter(function(n4) {
          return !n4.__ || B2(n4);
        });
      } catch (r3) {
        t3.some(function(n4) {
          n4.__h && (n4.__h = []);
        }), t3 = [], c2.__e(r3, n3.__v);
      }
    }), l2 && l2(n2, t3);
  }, c2.unmount = function(n2) {
    m2 && m2(n2);
    var t3, r3 = n2.__c;
    r3 && r3.__H && (r3.__H.__.some(function(n3) {
      try {
        z2(n3);
      } catch (n4) {
        t3 = n4;
      }
    }), r3.__H = void 0, t3 && c2.__e(t3, r3.__v));
  };
  var k2 = "function" == typeof requestAnimationFrame;
  function w2(n2) {
    var t3, r3 = function() {
      clearTimeout(u4), k2 && cancelAnimationFrame(t3), setTimeout(n2);
    }, u4 = setTimeout(r3, 35);
    k2 && (t3 = requestAnimationFrame(r3));
  }
  function z2(n2) {
    var t3 = r2, u4 = n2.__c;
    "function" == typeof u4 && (n2.__c = void 0, u4()), r2 = t3;
  }
  function B2(n2) {
    var t3 = r2;
    n2.__c = n2.__(), r2 = t3;
  }
  function C2(n2, t3) {
    return !n2 || n2.length !== t3.length || t3.some(function(t4, r3) {
      return t4 !== n2[r3];
    });
  }
  function D2(n2, t3) {
    return "function" == typeof t3 ? t3(n2) : t3;
  }

  // notification_tracker.ts
  var REPEAT_COOLDOWN_MS = 30 * 60 * 1e3;
  function emptyState() {
    return /* @__PURE__ */ Object.create(null);
  }
  function validProbeId(value) {
    return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
  }
  function validTime(value) {
    return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
  }
  function latestCandidates(candidates) {
    const latest = /* @__PURE__ */ new Map();
    for (const candidate of candidates) {
      if (typeof candidate?.key !== "string" || !candidate.key || !validProbeId(candidate.probeId)) continue;
      const previous = latest.get(candidate.key);
      if (!previous || candidate.probeId > previous.probeId) latest.set(candidate.key, candidate);
    }
    return [...latest.values()];
  }
  function dueNoticeCandidates(candidates, state, now, cooldownMs = REPEAT_COOLDOWN_MS) {
    if (!validTime(now)) return [];
    const cooldown = Number.isFinite(cooldownMs) ? Math.max(0, cooldownMs) : REPEAT_COOLDOWN_MS;
    return latestCandidates(candidates).filter((candidate) => {
      const receipt = Object.prototype.hasOwnProperty.call(state, candidate.key) ? state[candidate.key] : void 0;
      if (!receipt) return true;
      if (candidate.probeId <= receipt.probeId) return false;
      return now - receipt.notifiedAt >= cooldown;
    });
  }
  function markNotified(state, candidates, now) {
    const updated = Object.assign(emptyState(), state);
    if (!validTime(now)) return updated;
    for (const candidate of latestCandidates(candidates)) {
      updated[candidate.key] = { probeId: candidate.probeId, notifiedAt: now };
    }
    return updated;
  }
  function parseNoticeState(raw) {
    const state = emptyState();
    if (!raw) return state;
    try {
      const parsed = JSON.parse(raw);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return state;
      for (const [key, value] of Object.entries(parsed)) {
        if (!key || typeof value !== "object" || value === null || Array.isArray(value)) continue;
        const receipt = value;
        if (validProbeId(receipt.probeId) && validTime(receipt.notifiedAt)) {
          state[key] = { probeId: receipt.probeId, notifiedAt: receipt.notifiedAt };
        }
      }
    } catch {
    }
    return state;
  }
  function mergeNoticeStates(a3, b2) {
    const merged = emptyState();
    for (const source of [a3, b2]) {
      for (const [key, receipt] of Object.entries(source)) {
        if (!key || !receipt || !validProbeId(receipt.probeId) || !validTime(receipt.notifiedAt)) continue;
        const current = merged[key];
        if (!current || receipt.notifiedAt > current.notifiedAt || receipt.notifiedAt === current.notifiedAt && receipt.probeId > current.probeId) {
          merged[key] = { probeId: receipt.probeId, notifiedAt: receipt.notifiedAt };
        }
      }
    }
    return merged;
  }
  function compactNoticeState(state, maxEntries) {
    const compacted = emptyState();
    if (!Number.isSafeInteger(maxEntries) || maxEntries <= 0) return compacted;
    const entries = Object.entries(state).filter(([key, receipt]) => key && receipt && validProbeId(receipt.probeId) && validTime(receipt.notifiedAt)).sort(([keyA, a3], [keyB, b2]) => b2.notifiedAt - a3.notifiedAt || keyA.localeCompare(keyB));
    for (const [key, receipt] of entries.slice(0, maxEntries)) compacted[key] = receipt;
    return compacted;
  }

  // node_modules/preact/jsx-runtime/dist/jsxRuntime.module.js
  var f3 = 0;
  function u3(e3, t3, n2, o3, i3, u4) {
    t3 || (t3 = {});
    var a3, c3, p3 = t3;
    if ("ref" in p3) for (c3 in p3 = {}, t3) "ref" == c3 ? a3 = t3[c3] : p3[c3] = t3[c3];
    var l3 = { type: e3, props: p3, key: n2, ref: a3, __k: null, __: null, __b: 0, __e: null, __c: null, constructor: void 0, __v: --f3, __i: -1, __u: 0, __source: i3, __self: u4 };
    if ("function" == typeof e3 && (a3 = e3.defaultProps)) for (c3 in a3) void 0 === p3[c3] && (p3[c3] = a3[c3]);
    return l.vnode && l.vnode(l3), l3;
  }

  // app.tsx
  function syncCRLFieldValidity(event) {
    const input = event.currentTarget;
    if (input.matches(":user-invalid")) input.setAttribute("aria-invalid", "true");
    else input.removeAttribute("aria-invalid");
  }
  function markCRLFieldInvalid(event) {
    event.currentTarget.setAttribute("aria-invalid", "true");
  }
  function dateText(value) {
    if (!value) return "\u2014";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
  }
  function timestamp(value) {
    const time = value ? Date.parse(value) : NaN;
    return Number.isFinite(time) ? time : 0;
  }
  function shortHash(value) {
    return value ? value.length > 20 ? `${value.slice(0, 16)}\u2026` : value : "\u2014";
  }
  function destinationKey(destination) {
    return [destination.hostname || "", destination.ip || "", destination.port, destination.vantage].join("|");
  }
  function destinationText(destination) {
    if (!destination) return "Unknown destination";
    const host = destination.hostname || destination.ip || "Unknown host";
    return `${host}${destination.hostname && destination.ip ? ` (${destination.ip})` : ""}:${destination.port}`;
  }
  function destinationTextOrID(destination, id) {
    return destination ? destinationText(destination) : `Destination event #${id} (outside recent list)`;
  }
  function evidenceText(value) {
    return value === "direct" ? "Directly presented" : value === "candidate" ? "Candidate path" : value === "name_only" ? "Name only" : value || "Unknown";
  }
  function keyUsageText(mask) {
    const names = [[1, "digital signature"], [2, "content commitment"], [4, "key encipherment"], [8, "data encipherment"], [16, "key agreement"], [32, "certificate signing"], [64, "CRL signing"], [128, "encipher only"], [256, "decipher only"]];
    const active = names.filter(([bit]) => (mask & bit) !== 0).map(([, name]) => name);
    return active.length ? active.join(", ") : "not specified";
  }
  function timeQuery(filter, limit = 1e4) {
    const query = new URLSearchParams({ limit: String(limit) });
    if (filter.watchID) query.set("watch_id", filter.watchID);
    if (filter.from) query.set("from", new Date(filter.from).toISOString());
    if (filter.to) query.set("to", new Date(new Date(filter.to).getTime() + 6e4).toISOString());
    return query;
  }
  function revocationQuery(filter, limit = 1e4) {
    const query = new URLSearchParams({ limit: String(limit) });
    if (filter.from) query.set("from", new Date(filter.from).toISOString());
    if (filter.to) query.set("to", new Date(new Date(filter.to).getTime() + 6e4).toISOString());
    if (filter.evidence) query.set("evidence", filter.evidence);
    return query;
  }
  async function getJSON(path) {
    const response = await fetch(path, { credentials: "same-origin", headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
    return response.json();
  }
  function asList(value) {
    return Array.isArray(value) ? value : value?.items || [];
  }
  function Badge({ evidence, children }) {
    return /* @__PURE__ */ u3("span", { class: `badge ${evidence || ""}`.trim(), children });
  }
  function Stacked({ primary, secondary }) {
    return /* @__PURE__ */ u3("div", { children: [
      /* @__PURE__ */ u3("div", { class: "primary", children: primary }),
      secondary && /* @__PURE__ */ u3("div", { class: "secondary", children: secondary })
    ] });
  }
  function DataTable({ caption, headers, rows, empty }) {
    if (!rows.length) return /* @__PURE__ */ u3("p", { class: "empty", children: empty });
    return /* @__PURE__ */ u3("table", { children: [
      /* @__PURE__ */ u3("caption", { children: caption }),
      /* @__PURE__ */ u3("thead", { children: /* @__PURE__ */ u3("tr", { children: headers.map((header) => /* @__PURE__ */ u3("th", { scope: "col", children: header }, header)) }) }),
      /* @__PURE__ */ u3("tbody", { children: rows.map((row) => /* @__PURE__ */ u3("tr", { children: row.cells.map((content, index) => /* @__PURE__ */ u3("td", { children: content }, index)) }, row.key)) })
    ] });
  }
  function ExportLinks({ resource, filter, query }) {
    return /* @__PURE__ */ u3("div", { class: "export-links", children: ["json", "csv"].map((format) => {
      const params = query ? new URLSearchParams(query) : filter ? timeQuery(filter, 1e5) : new URLSearchParams();
      params.delete("limit");
      params.set("format", format);
      return /* @__PURE__ */ u3("a", { href: `/api/export/${encodeURIComponent(resource)}?${params.toString()}`, download: `certainted-${resource}.${format}`, children: [
        "Export ",
        format.toUpperCase()
      ] }, format);
    }) });
  }
  function SectionHeader({ number, eyebrow, title, titleID, exportResource, filter, exportQuery }) {
    return /* @__PURE__ */ u3("div", { class: "section-heading", children: [
      /* @__PURE__ */ u3("div", { children: [
        /* @__PURE__ */ u3("p", { class: "eyebrow", children: [
          number,
          " / ",
          eyebrow
        ] }),
        /* @__PURE__ */ u3("h2", { id: titleID, children: title })
      ] }),
      exportResource && /* @__PURE__ */ u3(ExportLinks, { resource: exportResource, filter, query: exportQuery })
    ] });
  }
  function CertificateList({ certificates, context }) {
    if (!certificates.length) return /* @__PURE__ */ u3("p", { children: "No certificates recorded." });
    return /* @__PURE__ */ u3("ol", { children: certificates.map((certificate, index) => /* @__PURE__ */ u3("li", { children: [
      /* @__PURE__ */ u3("div", { class: "primary", children: [
        certificate.subject || "Unknown subject",
        " \xB7 ",
        certificate.is_ca ? "CA" : "leaf",
        " \xB7 ",
        /* @__PURE__ */ u3(Badge, { evidence: certificate.source === "trust_store" ? "candidate" : certificate.source === "presented" ? "direct" : "", children: certificate.source === "trust_store" ? "Trust-store candidate (inferred)" : certificate.source === "presented" ? "Presented by endpoint" : context })
      ] }),
      /* @__PURE__ */ u3("div", { class: "secondary", children: [
        "Issuer: ",
        certificate.issuer || "unknown",
        "; serial: ",
        certificate.serial || "unknown"
      ] }),
      /* @__PURE__ */ u3("div", { class: "mono", children: [
        "Certificate SHA-256: ",
        certificate.fingerprint_sha256 || "unknown"
      ] }),
      /* @__PURE__ */ u3("div", { class: "mono", children: [
        "Public-key SHA-256: ",
        certificate.spki_sha256 || "unknown"
      ] }),
      /* @__PURE__ */ u3("div", { class: "secondary", children: [
        dateText(certificate.not_before),
        " to ",
        dateText(certificate.not_after),
        " \xB7 ",
        certificate.public_key_algorithm || "key algorithm unknown",
        certificate.key_bits ? ` \xB7 ${certificate.key_bits} bits` : "",
        certificate.self_signed ? " \xB7 self-signed (not automatically trusted)" : ""
      ] }),
      /* @__PURE__ */ u3("div", { class: "secondary", children: [
        "Basic constraints: ",
        certificate.basic_constraints_valid ? certificate.is_ca ? "CA" : "not CA" : "not marked valid",
        certificate.max_path_len_zero ? "; max path length 0" : certificate.max_path_len > 0 ? `; max path length ${certificate.max_path_len}` : "",
        "; key usage: ",
        keyUsageText(certificate.key_usage || 0)
      ] }),
      Boolean(certificate.dns_names?.length || certificate.ip_addresses?.length || certificate.email_addresses?.length || certificate.uris?.length) && /* @__PURE__ */ u3("div", { class: "secondary", children: [
        "SANs: ",
        [...certificate.dns_names || [], ...certificate.ip_addresses || [], ...certificate.email_addresses || [], ...certificate.uris || []].join(", ")
      ] })
    ] }, `${certificate.fingerprint_sha256}-${index}`)) });
  }
  function ProbeDetails({ probe }) {
    return /* @__PURE__ */ u3("details", { children: [
      /* @__PURE__ */ u3("summary", { children: "View probe evidence" }),
      /* @__PURE__ */ u3("div", { class: "detail-content", children: [
        /* @__PURE__ */ u3("p", { children: [
          "Target: ",
          probe.target_ip || probe.hostname || "unknown",
          ":",
          probe.port,
          "; SNI: ",
          probe.sni || "none",
          "; vantage: ",
          probe.vantage || "unknown"
        ] }),
        /* @__PURE__ */ u3("p", { children: [
          "TLS: ",
          probe.tls_version || "unknown",
          "; cipher: ",
          probe.cipher_suite || "unknown"
        ] }),
        /* @__PURE__ */ u3("p", { children: [
          "Trust store: ",
          probe.trust_store || "not configured",
          "; validation: ",
          probe.validation_error || "no validation error recorded"
        ] }),
        probe.failure && /* @__PURE__ */ u3("p", { children: [
          "Probe failure: ",
          probe.failure
        ] }),
        probe.incomplete_chain && /* @__PURE__ */ u3("p", { children: "The presented chain was incomplete." }),
        /* @__PURE__ */ u3("h4", { children: "Presented by endpoint" }),
        /* @__PURE__ */ u3(CertificateList, { certificates: probe.presented || [], context: "presented" }),
        /* @__PURE__ */ u3("h4", { children: [
          "Candidate paths (",
          probe.candidate_paths?.length || 0,
          ")"
        ] }),
        !probe.candidate_paths?.length && /* @__PURE__ */ u3("p", { children: "No validated candidate path recorded." }),
        (probe.candidate_paths || []).map((path, index) => /* @__PURE__ */ u3("div", { children: [
          /* @__PURE__ */ u3("p", { children: [
            "Path ",
            index + 1,
            ": ",
            path.validation || "validation unavailable"
          ] }),
          /* @__PURE__ */ u3(CertificateList, { certificates: path.certificates || [], context: "candidate path" })
        ] }, index))
      ] })
    ] });
  }
  function WatchForm({ onSaved }) {
    const [message, setMessage] = d2("");
    const [saving, setSaving] = d2(false);
    async function submit(event) {
      event.preventDefault();
      const form = event.currentTarget;
      if (!form.reportValidity()) return;
      const values = new FormData(form);
      const matchType = String(values.get("match_type") || "");
      let value = String(values.get("value") || "").trim();
      if (matchType !== "name") {
        value = value.replace(/[:\s]/g, "").toLowerCase();
        if (!/^[0-9a-f]{64}$/.test(value)) {
          setMessage("Certificate and public-key fingerprints must be 64 hexadecimal characters.");
          return;
        }
      }
      const from = String(values.get("effective_from") || "");
      const to = String(values.get("effective_to") || "");
      if (from && to && timestamp(from) >= timestamp(to)) {
        setMessage("The effective-until date must follow the effective-from date.");
        return;
      }
      const payload = {
        name: String(values.get("name") || "").trim(),
        group: String(values.get("group") || "").trim(),
        match_type: matchType,
        value,
        status: String(values.get("status") || "monitored"),
        severity: String(values.get("severity") || "info"),
        reason: String(values.get("reason") || "").trim(),
        source: String(values.get("source") || "").trim() || "Manual dashboard entry",
        ...from ? { effective_from: new Date(from).toISOString() } : {},
        ...to ? { effective_to: new Date(to).toISOString() } : {}
      };
      setSaving(true);
      setMessage("Saving entry and reevaluating stored observations\u2026");
      try {
        const response = await fetch("/api/watches", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json", Accept: "application/json", "X-Certainted-Intent": "1" },
          body: JSON.stringify(payload)
        });
        if (!response.ok) throw new Error((await response.text()).slice(0, 300) || `HTTP ${response.status}`);
        form.reset();
        await onSaved();
        setMessage("Watchlist entry saved. Historical probe observations were reevaluated.");
      } catch (error) {
        setMessage(`Could not save watchlist entry: ${error instanceof Error ? error.message : String(error)}`);
      } finally {
        setSaving(false);
      }
    }
    return /* @__PURE__ */ u3("details", { class: "watch-form-wrap", children: [
      /* @__PURE__ */ u3("summary", { children: "Add a watchlist entry" }),
      /* @__PURE__ */ u3("form", { id: "watch-form", action: "/api/watches", method: "post", onSubmit: (event) => void submit(event), children: [
        /* @__PURE__ */ u3("div", { class: "form-grid", children: [
          /* @__PURE__ */ u3("div", { children: [
            /* @__PURE__ */ u3("label", { htmlFor: "watch-name", children: "Name" }),
            /* @__PURE__ */ u3("input", { id: "watch-name", name: "name", required: true, maxLength: 200 })
          ] }),
          /* @__PURE__ */ u3("div", { children: [
            /* @__PURE__ */ u3("label", { htmlFor: "watch-group", children: "Organization / group" }),
            /* @__PURE__ */ u3("input", { id: "watch-group", name: "group", maxLength: 200 })
          ] }),
          /* @__PURE__ */ u3("div", { children: [
            /* @__PURE__ */ u3("label", { htmlFor: "watch-match-type", children: "Match by" }),
            /* @__PURE__ */ u3("select", { id: "watch-match-type", name: "match_type", children: [
              /* @__PURE__ */ u3("option", { value: "cert_sha256", children: "Certificate SHA-256" }),
              /* @__PURE__ */ u3("option", { value: "spki_sha256", children: "Public key SHA-256" }),
              /* @__PURE__ */ u3("option", { value: "name", children: "Name only" })
            ] })
          ] }),
          /* @__PURE__ */ u3("div", { children: [
            /* @__PURE__ */ u3("label", { htmlFor: "watch-value", children: "Match value" }),
            /* @__PURE__ */ u3("input", { id: "watch-value", name: "value", required: true, maxLength: 500, "aria-describedby": "watch-value-help", autoCorrect: "off", autoCapitalize: "off", spellcheck: false }),
            /* @__PURE__ */ u3("small", { id: "watch-value-help", children: "Use a hex SHA-256 fingerprint for exact certificate or public-key matches." })
          ] }),
          /* @__PURE__ */ u3("div", { children: [
            /* @__PURE__ */ u3("label", { htmlFor: "watch-status", children: "Status" }),
            /* @__PURE__ */ u3("select", { id: "watch-status", name: "status", children: [
              /* @__PURE__ */ u3("option", { value: "monitored", children: "Monitored" }),
              /* @__PURE__ */ u3("option", { value: "under investigation", children: "Under investigation" }),
              /* @__PURE__ */ u3("option", { value: "distrusted", children: "Distrusted" }),
              /* @__PURE__ */ u3("option", { value: "compromised", children: "Compromised" })
            ] })
          ] }),
          /* @__PURE__ */ u3("div", { children: [
            /* @__PURE__ */ u3("label", { htmlFor: "watch-severity", children: "Severity" }),
            /* @__PURE__ */ u3("select", { id: "watch-severity", name: "severity", children: [
              /* @__PURE__ */ u3("option", { value: "info", children: "Info" }),
              /* @__PURE__ */ u3("option", { value: "low", children: "Low" }),
              /* @__PURE__ */ u3("option", { value: "medium", children: "Medium" }),
              /* @__PURE__ */ u3("option", { value: "high", children: "High" }),
              /* @__PURE__ */ u3("option", { value: "critical", children: "Critical" })
            ] })
          ] }),
          /* @__PURE__ */ u3("div", { children: [
            /* @__PURE__ */ u3("label", { htmlFor: "watch-effective-from", children: "Effective from" }),
            /* @__PURE__ */ u3("input", { id: "watch-effective-from", name: "effective_from", type: "datetime-local" })
          ] }),
          /* @__PURE__ */ u3("div", { children: [
            /* @__PURE__ */ u3("label", { htmlFor: "watch-effective-to", children: "Effective until (exclusive)" }),
            /* @__PURE__ */ u3("input", { id: "watch-effective-to", name: "effective_to", type: "datetime-local" })
          ] }),
          /* @__PURE__ */ u3("div", { class: "wide", children: [
            /* @__PURE__ */ u3("label", { htmlFor: "watch-reason", children: "Reason" }),
            /* @__PURE__ */ u3("textarea", { id: "watch-reason", name: "reason", rows: 2, maxLength: 2e3 })
          ] }),
          /* @__PURE__ */ u3("div", { class: "wide", children: [
            /* @__PURE__ */ u3("label", { htmlFor: "watch-source", children: "Source / reference" }),
            /* @__PURE__ */ u3("input", { id: "watch-source", name: "source", maxLength: 500 })
          ] })
        ] }),
        /* @__PURE__ */ u3("button", { type: "submit", disabled: saving, children: "Save and reevaluate history" }),
        /* @__PURE__ */ u3("p", { id: "watch-result", role: "status", "aria-live": "polite", children: message })
      ] })
    ] });
  }
  function MonitoringImports({ onImported }) {
    const dialog = A2(null);
    const [kind, setKind] = d2(null);
    const [saving, setSaving] = d2(false);
    const [message, setMessage] = d2("");
    const [error, setError] = d2(false);
    h2(() => {
      if (kind && !dialog.current?.open) dialog.current?.showModal();
    }, [kind]);
    function open(kindToOpen) {
      if (saving) return;
      setMessage("");
      setError(false);
      setKind(kindToOpen);
    }
    const isCRL = kind === "crl-file" || kind === "crl-url";
    const title = kind === "json" ? "Import JSON watchlist" : kind === "csv" ? "Import CSV watchlist" : kind === "crl-file" ? "Import CRL file" : "Import CRL URL";
    async function submit(event) {
      event.preventDefault();
      if (!kind) return;
      const form = event.currentTarget;
      if (!form.reportValidity()) return;
      const payload = new FormData(form);
      if (kind === "crl-url") {
        const value = String(payload.get("crl_url") || "").trim();
        let url;
        try {
          url = new URL(value);
        } catch {
          setError(true);
          setMessage("Enter a complete HTTP or HTTPS CRL URL.");
          return;
        }
        if (url.protocol !== "https:" && url.protocol !== "http:") {
          setError(true);
          setMessage("The CRL URL must start with https:// or http://.");
          return;
        }
        payload.set("crl_url", url.href);
      }
      if (isCRL) payload.set("method", kind === "crl-url" ? "url" : "file");
      else payload.set("format", kind);
      setSaving(true);
      setError(false);
      setMessage(isCRL ? kind === "crl-url" ? "Fetching and verifying this CRL\u2026" : "Verifying and importing this CRL\u2026" : "Importing watches and reevaluating stored probes\u2026");
      try {
        const response = await fetch(isCRL ? "/api/revocations/import" : "/api/watches/import", {
          method: "POST",
          credentials: "same-origin",
          headers: { Accept: "application/json", "X-Certainted-Intent": "1" },
          body: payload
        });
        const raw = await response.text();
        let result;
        try {
          result = JSON.parse(raw);
        } catch {
          throw new Error(response.ok ? "The server returned an invalid response." : `HTTP ${response.status}: ${raw.slice(0, 200)}`);
        }
        if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
        form.reset();
        onImported();
        dialog.current?.close();
        setMessage(isCRL ? `CRL #${result.id} imported with ${result.entry_count} revoked serial${result.entry_count === 1 ? "" : "s"}. Stored probes were reevaluated.` : result.imported ? `${result.imported} watchlist entr${result.imported === 1 ? "y" : "ies"} imported${result.skipped ? `; ${result.skipped} duplicate${result.skipped === 1 ? "" : "s"} skipped` : ""}. Stored probes were reevaluated.` : `No new watches imported; ${result.skipped || 0} duplicate${result.skipped === 1 ? "" : "s"} skipped.`);
      } catch (cause) {
        setError(true);
        setMessage(`Could not import ${isCRL ? "CRL" : "watchlist"}: ${cause instanceof Error ? cause.message : String(cause)}`);
      } finally {
        setSaving(false);
      }
    }
    return /* @__PURE__ */ u3("div", { class: "monitoring-imports", "aria-label": "Import monitoring sources", children: [
      /* @__PURE__ */ u3("div", { class: "import-actions", children: [
        /* @__PURE__ */ u3("span", { class: "import-actions-label", children: "Load from" }),
        /* @__PURE__ */ u3("button", { type: "button", onClick: () => open("json"), disabled: saving, children: "JSON file" }),
        /* @__PURE__ */ u3("button", { type: "button", onClick: () => open("csv"), disabled: saving, children: "CSV file" }),
        /* @__PURE__ */ u3("button", { type: "button", onClick: () => open("crl-file"), disabled: saving, children: "CRL file" }),
        /* @__PURE__ */ u3("button", { type: "button", onClick: () => open("crl-url"), disabled: saving, children: "CRL URL" })
      ] }),
      !kind && message && /* @__PURE__ */ u3("p", { class: error ? "import-result error" : "import-result", role: "status", "aria-live": "polite", children: message }),
      /* @__PURE__ */ u3("dialog", { ref: dialog, class: "import-dialog", "aria-labelledby": "import-dialog-title", onCancel: (event) => {
        if (saving) event.preventDefault();
      }, onClose: () => setKind(null), children: kind && /* @__PURE__ */ u3(S, { children: [
        /* @__PURE__ */ u3("div", { class: "import-dialog-heading", children: [
          /* @__PURE__ */ u3("h3", { id: "import-dialog-title", children: title }),
          /* @__PURE__ */ u3("button", { type: "button", class: "dialog-close", onClick: () => dialog.current?.close(), "aria-label": "Close import dialog", disabled: saving, children: "\xD7" })
        ] }),
        /* @__PURE__ */ u3("p", { class: "import-dialog-description", children: isCRL ? "Choose a certificate revocation list and its issuer certificate. Certainted verifies the CRL signature and checks stored and future independent probes. The issuer certificate does not become a trusted root." : "Load up to 256 CA watch entries from a file up to 2 MiB. Certificate, public-key, and name matching rules are supported. Imported entries are checked against stored probe history." }),
        kind === "crl-url" && /* @__PURE__ */ u3("p", { class: "import-dialog-note", children: "Certainted fetches this URL once when you import it. The request reveals your network address and request metadata to that host. Lists are not refreshed automatically." }),
        /* @__PURE__ */ u3("form", { method: "post", encType: "multipart/form-data", onSubmit: (event) => void submit(event), children: [
          /* @__PURE__ */ u3("div", { class: "import-fields", children: [
            (kind === "json" || kind === "csv") && /* @__PURE__ */ u3("div", { children: [
              /* @__PURE__ */ u3("label", { htmlFor: "watch-import-file", children: [
                kind.toUpperCase(),
                " watchlist file"
              ] }),
              /* @__PURE__ */ u3("input", { id: "watch-import-file", name: "file", type: "file", accept: kind === "json" ? ".json,application/json" : ".csv,text/csv", required: true })
            ] }),
            kind === "crl-file" && /* @__PURE__ */ u3("div", { children: [
              /* @__PURE__ */ u3("label", { htmlFor: "crl-import-file", children: "CRL file (PEM or DER)" }),
              /* @__PURE__ */ u3("input", { id: "crl-import-file", name: "crl_file", type: "file", accept: ".crl,.pem,.der,application/pkix-crl", required: true, onBlur: syncCRLFieldValidity, onChange: syncCRLFieldValidity, onInvalid: markCRLFieldInvalid })
            ] }),
            kind === "crl-url" && /* @__PURE__ */ u3("div", { children: [
              /* @__PURE__ */ u3("label", { htmlFor: "crl-import-url", children: "CRL URL (HTTP or HTTPS)" }),
              /* @__PURE__ */ u3("input", { id: "crl-import-url", name: "crl_url", type: "url", placeholder: "https://ca.example/revocations.crl", autoCorrect: "off", autoCapitalize: "off", spellcheck: false, required: true, "aria-describedby": "crl-url-help", onBlur: syncCRLFieldValidity, onInput: syncCRLFieldValidity, onInvalid: markCRLFieldInvalid }),
              /* @__PURE__ */ u3("small", { id: "crl-url-help", children: "Public addresses on standard HTTP or HTTPS ports only; redirects are not followed." })
            ] }),
            isCRL && /* @__PURE__ */ u3(S, { children: [
              /* @__PURE__ */ u3("div", { children: [
                /* @__PURE__ */ u3("label", { htmlFor: "crl-import-issuer", children: "Issuer certificate (PEM or DER)" }),
                /* @__PURE__ */ u3("input", { id: "crl-import-issuer", name: "issuer_file", type: "file", accept: ".crt,.cer,.pem,.der,application/pkix-cert", required: true, onBlur: syncCRLFieldValidity, onChange: syncCRLFieldValidity, onInvalid: markCRLFieldInvalid })
              ] }),
              /* @__PURE__ */ u3("div", { children: [
                /* @__PURE__ */ u3("label", { htmlFor: "crl-import-source", children: "Source note (optional)" }),
                /* @__PURE__ */ u3("input", { id: "crl-import-source", name: "source", type: "text", maxLength: 500, placeholder: "CA bulletin or internal reference" })
              ] })
            ] })
          ] }),
          /* @__PURE__ */ u3("div", { class: "dialog-actions", children: [
            /* @__PURE__ */ u3("button", { type: "button", class: "secondary-button", onClick: () => dialog.current?.close(), disabled: saving, children: "Cancel" }),
            /* @__PURE__ */ u3("button", { type: "submit", disabled: saving, children: saving ? "Importing\u2026" : "Import" })
          ] }),
          /* @__PURE__ */ u3("p", { class: error ? "import-result error" : "import-result", role: "status", "aria-live": "polite", children: message })
        ] })
      ] }) })
    ] });
  }
  var alertPreferenceKey = "certainted.desktop-alerts.enabled";
  var alertCollapsedKey = "certainted.desktop-alerts.collapsed.v2";
  var alertReceiptKey = "certainted.desktop-alerts.receipts.v1";
  var legacyAlertPreferenceKey = "certained.desktop-alerts.enabled";
  var maxAlertReceipts = 12e3;
  function alertPermission() {
    if (!window.isSecureContext || typeof Notification === "undefined") return "unsupported";
    return Notification.permission;
  }
  function savedAlertFlag(key, legacyKey) {
    try {
      const current = window.localStorage.getItem(key);
      if (current !== null) return current === "1";
      const legacy = window.localStorage.getItem(legacyKey);
      if (legacy !== null) {
        window.localStorage.setItem(key, legacy);
        window.localStorage.removeItem(legacyKey);
      }
      return legacy === "1";
    } catch {
      return false;
    }
  }
  function savedAlertPreference() {
    return savedAlertFlag(alertPreferenceKey, legacyAlertPreferenceKey);
  }
  function saveAlertPreference(enabled) {
    try {
      if (enabled) window.localStorage.setItem(alertPreferenceKey, "1");
      else window.localStorage.removeItem(alertPreferenceKey);
    } catch {
    }
  }
  function savedAlertCollapse() {
    try {
      return window.localStorage.getItem(alertCollapsedKey) === "1";
    } catch {
      return false;
    }
  }
  function alertIdentity(alert) {
    return JSON.stringify([alert.watch_id, alert.evidence, alert.destination_key]);
  }
  function revocationIdentity(finding) {
    return JSON.stringify([finding.destination_key || finding.destination_id, finding.certificate_fingerprint, finding.evidence, finding.issuer_match]);
  }
  function loadAlertReceipts() {
    try {
      return parseNoticeState(window.localStorage.getItem(alertReceiptKey));
    } catch {
      return {};
    }
  }
  function saveAlertReceipts(receipts) {
    try {
      const merged = compactNoticeState(mergeNoticeStates(loadAlertReceipts(), receipts), maxAlertReceipts);
      window.localStorage.setItem(alertReceiptKey, JSON.stringify(merged));
      return merged;
    } catch {
      return receipts;
    }
  }
  function showDesktopNotification(title, body, onOpen) {
    try {
      const notification = new Notification(title, { body });
      if (onOpen) notification.onclick = () => {
        window.focus();
        onOpen();
        notification.close();
      };
      return notification;
    } catch {
      return null;
    }
  }
  function DesktopAlerts({ onNewAlert, onOpenAlert, onOpenRevocation }) {
    const [permission, setPermission] = d2(alertPermission);
    const [enabled, setEnabled] = d2(savedAlertPreference);
    const [collapsed, setCollapsed] = d2(savedAlertCollapse);
    const [message, setMessage] = d2("");
    const [showPermissionHelp, setShowPermissionHelp] = d2(false);
    const active = enabled && permission === "granted";
    async function enable() {
      if (permission === "unsupported") return;
      try {
        const result = Notification.permission === "default" ? await Notification.requestPermission() : Notification.permission;
        setPermission(result);
        if (result === "granted") {
          saveAlertPreference(true);
          setEnabled(true);
          setShowPermissionHelp(false);
          setMessage("Alerts enabled. Certainted will check stored and new findings while this page is open.");
        } else {
          setShowPermissionHelp(true);
          setMessage(result === "denied" ? "Notifications are blocked for this address in your browser settings." : "The browser did not grant permission. It may have dismissed or suppressed the prompt.");
        }
      } catch {
        setShowPermissionHelp(true);
        setMessage("The browser could not request notification permission.");
      }
    }
    function pause() {
      saveAlertPreference(false);
      setEnabled(false);
      setMessage("Desktop alerts paused for Certainted.");
    }
    function sendTest() {
      if (Notification.permission !== "granted") {
        setPermission(Notification.permission);
        setMessage("Browser notification permission is no longer granted. Check this site's notification setting.");
        return;
      }
      const notification = showDesktopNotification(
        "Certainted test notification",
        "Your local dashboard requested this test notification."
      );
      if (!notification) {
        setMessage("This browser could not create a test notification. Check its notification settings.");
        return;
      }
      let completed = false;
      const timer = window.setTimeout(() => {
        if (!completed) setMessage("The browser gave no display confirmation. Check system notification settings and Focus mode.");
      }, 5e3);
      notification.addEventListener("show", () => {
        completed = true;
        window.clearTimeout(timer);
        setMessage("The browser reported showing the test notification. Your operating system can still hide its banner.");
      }, { once: true });
      notification.addEventListener("error", () => {
        completed = true;
        window.clearTimeout(timer);
        setMessage("The browser reported a notification delivery error. Check browser and system notification settings.");
      }, { once: true });
      setMessage("Waiting for the browser to report whether it showed the test notification\u2026");
    }
    function toggleCollapsed() {
      const next = !collapsed;
      setCollapsed(next);
      if (!next) setPermission(alertPermission());
      try {
        if (next) window.localStorage.setItem(alertCollapsedKey, "1");
        else window.localStorage.removeItem(alertCollapsedKey);
      } catch {
      }
    }
    h2(() => {
      if (!active) return;
      let current = true;
      let checking = false;
      let receipts = loadAlertReceipts();
      let previousAlertVersion = null;
      let previousRevocationVersion = null;
      async function check() {
        if (!current || checking) return;
        checking = true;
        try {
          if (Notification.permission !== "granted") {
            setPermission(Notification.permission);
            setEnabled(false);
            saveAlertPreference(false);
            return;
          }
          const [alertResult, revocationResult] = await Promise.allSettled([
            getJSON("/api/alerts?limit=10000"),
            getJSON("/api/revocations/findings?limit=1000")
          ]);
          if (!current) return;
          receipts = mergeNoticeStates(receipts, loadAlertReceipts());
          let inventoryChanged = false;
          let notificationFailed = false;
          let notificationRequested = false;
          const failedChecks = [];
          const now = Date.now();
          if (alertResult.status === "fulfilled") {
            const alerts = asList(alertResult.value);
            const version = JSON.stringify(alerts.map((alert) => [alertIdentity(alert), alert.latest_probe_id]));
            if (previousAlertVersion !== null && version !== previousAlertVersion) inventoryChanged = true;
            previousAlertVersion = version;
            const candidates = alerts.filter((alert) => alert.evidence === "direct" || alert.evidence === "candidate").map((alert) => ({ key: `ca:${alertIdentity(alert)}`, probeId: alert.latest_probe_id }));
            const due = dueNoticeCandidates(candidates, receipts, now);
            if (due.length) {
              const requested = showDesktopNotification(
                "Certainted: potential CA exposure",
                `${due.length} destination match${due.length === 1 ? "" : "es"} in independent probes. Review the CA watch and probe evidence.`,
                onOpenAlert
              );
              if (requested) {
                receipts = saveAlertReceipts(markNotified(receipts, due, now));
                notificationRequested = true;
              } else notificationFailed = true;
            }
          } else failedChecks.push("CA watches");
          if (revocationResult.status === "fulfilled") {
            const revocations = asList(revocationResult.value);
            const version = JSON.stringify(revocations.map((finding) => [finding.id, finding.probe_id]));
            if (previousRevocationVersion !== null && version !== previousRevocationVersion) inventoryChanged = true;
            previousRevocationVersion = version;
            const candidatesByKey = /* @__PURE__ */ new Map();
            for (const finding of revocations) {
              if (finding.evidence !== "direct" || finding.issuer_match !== "verified_path" || finding.crl_stale_at_probe) continue;
              const key = `crl:${revocationIdentity(finding)}`;
              const prior = candidatesByKey.get(key);
              if (!prior || finding.probe_id > prior.probeId) candidatesByKey.set(key, { key, probeId: finding.probe_id });
            }
            const due = dueNoticeCandidates([...candidatesByKey.values()], receipts, now);
            if (due.length) {
              const requested = showDesktopNotification(
                "Certainted: revoked certificate in probe",
                `${due.length} destination match${due.length === 1 ? "" : "es"} with direct independent-probe evidence. Review the CRL and probe details.`,
                onOpenRevocation
              );
              if (requested) {
                receipts = saveAlertReceipts(markNotified(receipts, due, now));
                notificationRequested = true;
              } else notificationFailed = true;
            }
          } else failedChecks.push("revocation findings");
          if (inventoryChanged) onNewAlert();
          if (notificationFailed) {
            saveAlertPreference(false);
            setEnabled(false);
            setMessage("This browser could not create a desktop notification. Findings remain available in the dashboard.");
          } else if (failedChecks.length) {
            setMessage(`Could not check ${failedChecks.join(" and ")}; Certainted will retry while this page is open.`);
          } else if (notificationRequested) {
            setMessage("Browser notification requested. If no banner appears, use Send test notification and check browser and system settings.");
          }
        } catch {
          if (current) setMessage("Could not check for new alerts; Certainted will retry while this page is open.");
        } finally {
          checking = false;
        }
      }
      void check();
      const timer = window.setInterval(() => void check(), 3e4);
      return () => {
        current = false;
        window.clearInterval(timer);
      };
    }, [active, onNewAlert, onOpenAlert, onOpenRevocation]);
    const description = permission === "unsupported" ? "This browser cannot show desktop notifications here. Findings remain available in Revoked certificates and CA exposure." : permission === "denied" ? "Notifications are blocked for this local address. Change the browser site setting to enable them." : active ? "On while this dashboard is open. Certainted checks for direct revocation findings and CA watch matches." : "Get a local browser alert for direct revocation findings and CA watch matches while this dashboard is open.";
    const compactStatus = active ? "On" : permission === "denied" ? "Blocked" : permission === "unsupported" ? "Unavailable" : "Off";
    const permissionHelp = permission !== "granted" && (permission === "unsupported" || permission === "denied" || showPermissionHelp);
    return /* @__PURE__ */ u3("aside", { class: `desktop-alerts${collapsed ? " is-collapsed" : ""}`, "aria-label": "Desktop alerts", children: [
      collapsed && /* @__PURE__ */ u3("div", { class: "desktop-alerts-compact-label", children: [
        /* @__PURE__ */ u3("strong", { children: "Desktop alerts" }),
        /* @__PURE__ */ u3("span", { children: compactStatus })
      ] }),
      /* @__PURE__ */ u3("div", { id: "desktop-alerts-details", hidden: collapsed, children: [
        /* @__PURE__ */ u3("h3", { children: "Desktop alerts" }),
        /* @__PURE__ */ u3("p", { children: description }),
        /* @__PURE__ */ u3("p", { class: "alert-message", role: "status", children: message }),
        permissionHelp && /* @__PURE__ */ u3("p", { class: "alert-permission-help", children: [
          "Open this local dashboard at ",
          /* @__PURE__ */ u3("code", { children: window.location.origin }),
          " directly in Chrome. In Chrome's site settings for this address, set Notifications to Allow, then reload. If you dismissed the prompt, you can also click Enable alerts again."
        ] })
      ] }),
      /* @__PURE__ */ u3("div", { class: "desktop-alerts-actions", children: [
        !collapsed && active && /* @__PURE__ */ u3("button", { type: "button", class: "test-alerts", onClick: sendTest, children: "Send test notification" }),
        !collapsed && (active ? /* @__PURE__ */ u3("button", { type: "button", onClick: pause, children: "Pause alerts" }) : permission !== "unsupported" && permission !== "denied" ? /* @__PURE__ */ u3("button", { type: "button", onClick: () => void enable(), children: "Enable alerts" }) : null),
        /* @__PURE__ */ u3("button", { type: "button", class: collapsed ? "expand-alerts" : "dismiss-alerts", onClick: toggleCollapsed, "aria-controls": "desktop-alerts-details", "aria-expanded": !collapsed, "aria-label": collapsed ? "Show desktop alert options" : "Collapse desktop alert options", title: collapsed ? "Show desktop alert options" : "Collapse desktop alert options", children: collapsed ? "Show options" : "\xD7" })
      ] })
    ] });
  }
  function Overview({ stats, destinations, probes, findings, revocationFindings, crlCount, watchCount, onNewAlert, onOpenAlert, onOpenRevocation, onProbeFilter }) {
    const unique = stats.unique_destinations ?? new Set(destinations.map(destinationKey)).size;
    const probed = stats.probed_destinations ?? new Set(probes.map((probe) => probe.destination_id)).size;
    const failed = stats.failed_probes ?? probes.filter((probe) => Boolean(probe.failure)).length;
    const affected = stats.affected_destinations ?? new Set(findings.map((finding) => finding.destination_id)).size;
    const matches = stats.watchlist_matches ?? findings.length;
    const events = stats.destination_events ?? destinations.length;
    const directRevocations = revocationFindings.filter((finding) => finding.evidence === "direct" && finding.issuer_match === "verified_path");
    const candidateRevocations = revocationFindings.filter((finding) => finding.evidence !== "direct" || finding.issuer_match !== "verified_path");
    const verifiedDestinations = new Set(directRevocations.map((finding) => finding.destination_key || finding.destination_id)).size;
    const cards = [
      { label: "Verified direct probe matches", value: crlCount ? stats.verified_direct_revocations ?? directRevocations.length : "\u2014", detail: crlCount ? `${verifiedDestinations} destination${verifiedDestinations === 1 ? "" : "s"} in loaded history; ${candidateRevocations.length} other potential match${candidateRevocations.length === 1 ? "" : "es"}` : "Import a CRL to check stored probes", href: crlCount ? "#revocations" : "#watchlist", action: crlCount ? "Review revocation evidence" : "Load a CRL", attention: (stats.verified_direct_revocations ?? directRevocations.length) > 0 },
      { label: "Potential exposure", value: watchCount ? affected : "\u2014", detail: watchCount ? `${matches} watchlist finding${matches === 1 ? "" : "s"} in stored history` : "Add a CA watch to start matching", href: watchCount ? "#exposure" : "#watchlist", action: watchCount ? "Investigate exposure" : "Set up watchlist", attention: affected > 0 },
      { label: "Destinations observed", value: unique, detail: `${events} collector event${events === 1 ? "" : "s"} received`, href: "#destinations", action: "Browse destinations" },
      { label: "Probe failures", value: failed, detail: `${probed} of ${unique} destinations ever probed`, href: "#probes", action: "Inspect failed probes", onClick: () => onProbeFilter("failed") }
    ];
    const latest = stats.latest_probe || probes.reduce((max, probe) => timestamp(probe.time) > timestamp(max) ? probe.time : max, "");
    return /* @__PURE__ */ u3("section", { id: "overview", "aria-labelledby": "overview-title", children: [
      /* @__PURE__ */ u3(SectionHeader, { number: "01", eyebrow: "Summary", title: "Overview", titleID: "overview-title" }),
      /* @__PURE__ */ u3("div", { class: "stat-grid", children: cards.map((card) => /* @__PURE__ */ u3("a", { class: `stat${card.attention ? " attention" : ""}`, href: card.href, onClick: card.onClick, children: [
        /* @__PURE__ */ u3("span", { class: "stat-label", children: card.label }),
        /* @__PURE__ */ u3("strong", { class: "stat-value", children: typeof card.value === "number" ? new Intl.NumberFormat().format(card.value) : card.value }),
        /* @__PURE__ */ u3("span", { class: "stat-detail", children: card.detail }),
        /* @__PURE__ */ u3("span", { class: "stat-action", children: [
          card.action,
          " ",
          /* @__PURE__ */ u3("span", { "aria-hidden": "true", children: "\u2197" })
        ] })
      ] }, card.label)) }),
      /* @__PURE__ */ u3(DesktopAlerts, { onNewAlert, onOpenAlert, onOpenRevocation }),
      /* @__PURE__ */ u3("div", { class: "note-row", children: [
        /* @__PURE__ */ u3("p", { children: "Collector events and independent probes are separate; neither counts application requests. Revocation matches are from Certainted probes." }),
        /* @__PURE__ */ u3("p", { children: /* @__PURE__ */ u3("a", { href: "#probes", children: [
          "Latest probe: ",
          dateText(latest)
        ] }) })
      ] })
    ] });
  }
  function RevocationsView({ crls, findings, destinations, filter, setFilter, search, setSearch }) {
    const destinationsByID = new Map(destinations.map((destination) => [destination.id, destination]));
    const needle = search.trim().toLowerCase();
    const rows = findings.filter((finding) => {
      const destination = destinationsByID.get(finding.destination_id);
      const haystack = `${destinationTextOrID(destination, finding.destination_id)} ${finding.certificate_fingerprint} ${finding.certificate_serial} ${finding.issuer} ${finding.reason} ${finding.source}`.toLowerCase();
      return !needle || haystack.includes(needle);
    }).sort((a3, b2) => timestamp(b2.time) - timestamp(a3.time)).map((finding) => {
      const destination = destinationsByID.get(finding.destination_id);
      const source = finding.source || `Imported CRL #${finding.crl_id}`;
      return { key: `${finding.crl_id}-${finding.probe_id}-${finding.certificate_fingerprint}`, cells: [
        /* @__PURE__ */ u3(Stacked, { primary: destinationTextOrID(destination, finding.destination_id), secondary: destination?.vantage ? `Vantage: ${destination.vantage}` : void 0 }),
        /* @__PURE__ */ u3("div", { children: [
          /* @__PURE__ */ u3("div", { class: "mono", children: [
            "SHA-256: ",
            finding.certificate_fingerprint || "\u2014"
          ] }),
          /* @__PURE__ */ u3("div", { class: "mono", children: [
            "Serial: ",
            finding.certificate_serial || "\u2014"
          ] })
        ] }),
        /* @__PURE__ */ u3("div", { children: [
          /* @__PURE__ */ u3(Badge, { evidence: finding.evidence, children: finding.evidence === "direct" ? "Presented to probe" : "Candidate path (inferred)" }),
          /* @__PURE__ */ u3("div", { class: "issuer-match", children: /* @__PURE__ */ u3(Badge, { evidence: finding.issuer_match === "verified_path" ? "success" : "candidate", children: finding.issuer_match === "verified_path" ? "Issuer path verified" : "Issuer link requires review" }) })
        ] }),
        /* @__PURE__ */ u3(Stacked, { primary: dateText(finding.revoked_at), secondary: finding.reason || `Reason code ${finding.reason_code}` }),
        /* @__PURE__ */ u3(Stacked, { primary: dateText(finding.time), secondary: `Probe #${finding.probe_id}` }),
        /* @__PURE__ */ u3("div", { children: [
          /* @__PURE__ */ u3("div", { class: "primary", children: finding.issuer || "Unknown issuer" }),
          /* @__PURE__ */ u3("div", { class: "secondary", children: [
            "Source: ",
            source
          ] }),
          /* @__PURE__ */ u3("div", { class: "secondary", children: [
            "Valid ",
            dateText(finding.crl_this_update),
            " to ",
            dateText(finding.crl_next_update)
          ] }),
          finding.crl_this_update_after_probe && /* @__PURE__ */ u3(Badge, { evidence: "candidate", children: "CRL update dated after probe" }),
          finding.crl_stale_at_probe && /* @__PURE__ */ u3(Badge, { evidence: "failed", children: "Stale at probe time" })
        ] })
      ] };
    });
    const now = Date.now();
    const crlRows = [...crls].sort((a3, b2) => timestamp(b2.imported_at) - timestamp(a3.imported_at)).map((crl) => {
      const expired = timestamp(crl.next_update) <= now;
      return { key: String(crl.id), cells: [
        /* @__PURE__ */ u3(Stacked, { primary: crl.issuer || "Unknown issuer", secondary: /* @__PURE__ */ u3("code", { class: "mono", children: crl.issuer_fingerprint_sha256 || "Issuer certificate unknown" }) }),
        /* @__PURE__ */ u3("span", { class: "mono", children: crl.source || "Local import" }),
        /* @__PURE__ */ u3(Stacked, { primary: /* @__PURE__ */ u3(Badge, { evidence: expired ? "failed" : "success", children: expired ? "Expired" : "Current" }), secondary: `${dateText(crl.this_update)} to ${dateText(crl.next_update)}` }),
        crl.entry_count ?? "\u2014",
        dateText(crl.imported_at)
      ] };
    });
    return /* @__PURE__ */ u3("section", { id: "revocations", "aria-labelledby": "revocations-title", children: [
      /* @__PURE__ */ u3(SectionHeader, { number: "03", eyebrow: "Revocation", title: "Revoked certificates", titleID: "revocations-title", exportResource: "revocations", exportQuery: revocationQuery(filter, 1e5) }),
      /* @__PURE__ */ u3("p", { class: "section-description", children: [
        "This section uses imported, signature-verified CRLs. The built-in eMudhra incident keys are separate ",
        /* @__PURE__ */ u3("a", { href: "#watchlist", children: "CA watchlist" }),
        " entries; their matches appear under ",
        /* @__PURE__ */ u3("a", { href: "#exposure", children: "CA exposure" }),
        ". For CRL findings, \u201Cpresented\u201D is direct probe evidence and \u201Ccandidate path\u201D is inferred. Neither establishes which certificate the original application received or trusted."
      ] }),
      /* @__PURE__ */ u3("div", { class: "filters", children: [
        /* @__PURE__ */ u3("div", { children: [
          /* @__PURE__ */ u3("label", { htmlFor: "revocation-from", children: "Probed from" }),
          /* @__PURE__ */ u3("input", { id: "revocation-from", type: "datetime-local", value: filter.from, onChange: (event) => setFilter({ ...filter, from: event.currentTarget.value }) })
        ] }),
        /* @__PURE__ */ u3("div", { children: [
          /* @__PURE__ */ u3("label", { htmlFor: "revocation-to", children: "Probed through" }),
          /* @__PURE__ */ u3("input", { id: "revocation-to", type: "datetime-local", value: filter.to, onChange: (event) => setFilter({ ...filter, to: event.currentTarget.value }) })
        ] }),
        /* @__PURE__ */ u3("div", { children: [
          /* @__PURE__ */ u3("label", { htmlFor: "revocation-evidence", children: "Evidence" }),
          /* @__PURE__ */ u3("select", { id: "revocation-evidence", value: filter.evidence, onChange: (event) => setFilter({ ...filter, evidence: event.currentTarget.value }), children: [
            /* @__PURE__ */ u3("option", { value: "", children: "All matches" }),
            /* @__PURE__ */ u3("option", { value: "direct", children: "Presented to probe" }),
            /* @__PURE__ */ u3("option", { value: "candidate", children: "Candidate path (inferred)" })
          ] })
        ] }),
        /* @__PURE__ */ u3("div", { children: [
          /* @__PURE__ */ u3("label", { htmlFor: "revocation-search", children: "Search findings" }),
          /* @__PURE__ */ u3("input", { id: "revocation-search", type: "search", placeholder: "Destination, serial, issuer, or reason", value: search, onInput: (event) => setSearch(event.currentTarget.value) })
        ] })
      ] }),
      /* @__PURE__ */ u3("div", { class: "table-wrap", children: /* @__PURE__ */ u3(DataTable, { caption: `${rows.length} post-revocation finding record${rows.length === 1 ? "" : "s"}${findings.length >= 1e4 ? " (API limit reached; use export for more)" : ""}`, headers: ["Destination", "Certificate", "Evidence", "Revoked / reason", "Probe observed", "CRL provenance"], rows, empty: crls.length ? "No post-revocation findings for these filters." : "No CRLs imported yet. Load a signed CRL in CA watchlist & CRLs to compare it with stored probes." }) }),
      /* @__PURE__ */ u3("div", { class: "section-heading subsection-heading", children: [
        /* @__PURE__ */ u3("h3", { id: "imported-crls", children: "Imported CRLs" }),
        /* @__PURE__ */ u3(ExportLinks, { resource: "crls" })
      ] }),
      /* @__PURE__ */ u3("p", { class: "section-description", children: "Certainted uses locally imported, signature-verified CRLs. Expired lists remain historical evidence; import a newer CRL for current status." }),
      /* @__PURE__ */ u3("div", { class: "table-wrap", children: /* @__PURE__ */ u3(DataTable, { caption: `${crlRows.length} imported CRL${crlRows.length === 1 ? "" : "s"}`, headers: ["Issuer", "Source", "Freshness", "Revoked serials", "Imported"], rows: crlRows, empty: "No CRLs imported yet." }) })
    ] });
  }
  function CommunityShare() {
    const dialog = A2(null);
    const [mode, setMode] = d2(null);
    const [preview, setPreview] = d2([]);
    const [selected, setSelected] = d2([]);
    const [pendingAuto, setPendingAuto] = d2(false);
    const [loading, setLoading] = d2(false);
    const [saving, setSaving] = d2(false);
    const [message, setMessage] = d2("");
    const [dialogMessage, setDialogMessage] = d2("");
    async function loadPreview() {
      const result = await getJSON("/api/community/preview");
      if (result.mode !== "manual" && result.mode !== "auto") throw new Error("Invalid sharing mode returned by the local server.");
      if (!Array.isArray(result.reports) || result.reports.some((item) => typeof item.id !== "string" || typeof item.report_id !== "string" || typeof item.report !== "object" || item.report === null)) throw new Error("Invalid sharing preview returned by the local server.");
      setMode(result.mode);
      setPreview(result.reports);
      return result;
    }
    h2(() => {
      let active = true;
      void getJSON("/api/community/preview").then((result) => {
        if (!active) return;
        if ((result.mode === "manual" || result.mode === "auto") && Array.isArray(result.reports) && result.reports.every((item) => typeof item.id === "string" && typeof item.report_id === "string" && typeof item.report === "object" && item.report !== null)) {
          setMode(result.mode);
          setPreview(result.reports);
        } else setMessage("The local sharing service returned an invalid response.");
      }).catch((error) => {
        if (active) setMessage(`Sharing is unavailable: ${error instanceof Error ? error.message : String(error)}`);
      });
      return () => {
        active = false;
      };
    }, []);
    async function postJSON(path, payload) {
      const response = await fetch(path, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", Accept: "application/json", "X-Certainted-Intent": "1" },
        body: JSON.stringify(payload)
      });
      if (!response.ok) throw new Error((await response.text()).slice(0, 250) || `HTTP ${response.status}`);
    }
    async function openPreview(forAuto) {
      setMessage("");
      setDialogMessage("");
      setLoading(true);
      try {
        await loadPreview();
        setSelected([]);
        setPendingAuto(forAuto);
        dialog.current?.showModal();
      } catch (error) {
        setMessage(`Could not load the exact sharing preview: ${error instanceof Error ? error.message : String(error)}`);
      } finally {
        setLoading(false);
      }
    }
    async function turnOffAuto() {
      setSaving(true);
      try {
        await postJSON("/api/community/mode", { mode: "manual" });
        setMode("manual");
        setMessage("Auto share is off. Reports remain local until you choose Share.");
      } catch (error) {
        setMessage(`Could not change sharing mode: ${error instanceof Error ? error.message : String(error)}`);
      } finally {
        setSaving(false);
      }
    }
    async function confirm() {
      setSaving(true);
      setMessage("");
      setDialogMessage("");
      let sharedCount = 0;
      try {
        if (pendingAuto) {
          await postJSON("/api/community/mode", { mode: "auto" });
          setMode("auto");
          setMessage("Auto share is on for future eligible reports. You can turn it off here at any time.");
        } else {
          for (const id of selected) {
            const item = preview.find((report) => report.id === id);
            if (!item) throw new Error("A selected report is no longer in the preview. Review the reports again before sharing.");
            await postJSON("/api/community/share", { id, report_id: item.report_id });
            sharedCount++;
            setPreview((current) => current.map((report) => report.id === id ? { ...report, shared: true } : report));
            setSelected((current) => current.filter((selectedID) => selectedID !== id));
          }
          setMessage(`${sharedCount} report${sharedCount === 1 ? "" : "s"} submitted to certainted.com. Public submissions are unverified claims.`);
        }
        dialog.current?.close();
        setSelected([]);
      } catch (error) {
        const failure = `Could not complete sharing${sharedCount ? ` after ${sharedCount} report${sharedCount === 1 ? "" : "s"} was submitted` : ""}: ${error instanceof Error ? error.message : String(error)}`;
        setMessage(failure);
        setDialogMessage(failure);
      } finally {
        setSaving(false);
      }
    }
    function toggleSelection(id, checked) {
      setSelected((current) => checked ? [...current, id] : current.filter((item) => item !== id));
    }
    const unshared = preview.filter((item) => !item.shared);
    return /* @__PURE__ */ u3("aside", { class: "community-share", "aria-labelledby": "community-share-title", children: [
      /* @__PURE__ */ u3("div", { class: "community-share-head", children: [
        /* @__PURE__ */ u3("div", { children: [
          /* @__PURE__ */ u3("h3", { id: "community-share-title", children: "Share a finding" }),
          /* @__PURE__ */ u3("p", { children: [
            "Send eligible independent-probe reports to ",
            /* @__PURE__ */ u3("strong", { children: "certainted.com" }),
            ". Shared reports include public hostnames and certificate evidence. They do not include private destinations, workload identity, collector metadata, or local probe IDs."
          ] })
        ] }),
        /* @__PURE__ */ u3("div", { class: "community-share-actions", children: [
          /* @__PURE__ */ u3("label", { class: "community-share-switch", htmlFor: "community-auto-share", children: [
            /* @__PURE__ */ u3("input", { id: "community-auto-share", type: "checkbox", role: "switch", checked: mode === "auto", disabled: mode === null || loading || saving, onChange: (event) => {
              const requestedAuto = event.currentTarget.checked;
              event.currentTarget.checked = mode === "auto";
              if (requestedAuto) void openPreview(true);
              else void turnOffAuto();
            } }),
            " Auto share"
          ] }),
          mode === "manual" && /* @__PURE__ */ u3("button", { type: "button", disabled: loading || saving, onClick: () => void openPreview(false), children: loading ? "Loading preview\u2026" : "Share\u2026" })
        ] })
      ] }),
      /* @__PURE__ */ u3("p", { class: "community-share-help", children: "Manual is the default. Auto share is opt-in and sends future eligible reports; turning it on does not submit earlier findings. A public hostname and certificate fingerprint can reveal your interest in that destination. The public dashboard has no account verification, so every report is labeled unverified." }),
      /* @__PURE__ */ u3("p", { class: "community-share-message", role: "status", "aria-live": "polite", children: message }),
      /* @__PURE__ */ u3("dialog", { ref: dialog, class: "import-dialog community-share-dialog", "aria-labelledby": "community-preview-title", onCancel: (event) => {
        if (saving) event.preventDefault();
      }, onClose: () => {
        setPendingAuto(false);
        setSelected([]);
      }, children: [
        /* @__PURE__ */ u3("div", { class: "import-dialog-heading", children: [
          /* @__PURE__ */ u3("h3", { id: "community-preview-title", children: pendingAuto ? "Enable Auto share" : "Review reports to share" }),
          /* @__PURE__ */ u3("button", { type: "button", class: "dialog-close", "aria-label": "Close sharing preview", disabled: saving, onClick: () => dialog.current?.close(), children: "\xD7" })
        ] }),
        /* @__PURE__ */ u3("p", { class: "import-dialog-description", children: "These are the exact public report payloads prepared by your local Certainted server. They include public hostnames and certificate evidence. The receiving site accepts unauthenticated submissions and does not independently verify the probe." }),
        pendingAuto && /* @__PURE__ */ u3("p", { class: "import-dialog-note", children: [
          "Enabling Auto share sends ",
          /* @__PURE__ */ u3("strong", { children: "future" }),
          " eligible reports to certainted.com without asking again. Reports below are examples from existing findings and are not sent when you enable Auto share."
        ] }),
        !preview.length && /* @__PURE__ */ u3("p", { class: "empty", children: "No eligible public reports are available to preview yet." }),
        /* @__PURE__ */ u3("div", { class: "community-preview-list", children: preview.map((item, index) => {
          const id = String(item.id);
          return /* @__PURE__ */ u3("div", { class: "community-preview-item", children: [
            /* @__PURE__ */ u3("div", { class: "community-preview-label", children: [
              pendingAuto ? /* @__PURE__ */ u3("strong", { children: [
                "Example ",
                index + 1
              ] }) : /* @__PURE__ */ u3("label", { children: [
                /* @__PURE__ */ u3("input", { type: "checkbox", checked: selected.includes(id), disabled: item.shared || saving, onChange: (event) => toggleSelection(id, event.currentTarget.checked) }),
                " Report ",
                index + 1
              ] }),
              item.shared && /* @__PURE__ */ u3("span", { class: "badge success", children: "Already shared" })
            ] }),
            /* @__PURE__ */ u3("pre", { children: JSON.stringify(item.report, null, 2) })
          ] }, `${id}-${index}`);
        }) }),
        /* @__PURE__ */ u3("p", { class: "import-dialog-note", children: "A certificate fingerprint and revocation or watchlist metadata help others check the claim, but the public site cannot establish what an application actually received or trusted." }),
        /* @__PURE__ */ u3("p", { class: "community-dialog-message", role: "status", "aria-live": "polite", children: dialogMessage }),
        /* @__PURE__ */ u3("div", { class: "dialog-actions", children: [
          /* @__PURE__ */ u3("button", { type: "button", class: "secondary-button", autoFocus: true, disabled: saving, onClick: () => dialog.current?.close(), children: "Cancel" }),
          /* @__PURE__ */ u3("button", { type: "button", class: "community-confirm", disabled: saving || !pendingAuto && (!selected.length || !unshared.length), onClick: () => void confirm(), children: saving ? "Sending\u2026" : pendingAuto ? "Enable Auto share" : `Share ${selected.length} selected` })
        ] })
      ] })
    ] });
  }
  function Exposure({ watches, destinations, findings, alerts, filter, setFilter, search, setSearch }) {
    const watchByID = new Map(watches.map((watch) => [watch.id, watch]));
    const destinationByID = new Map(destinations.map((destination) => [destination.id, destination]));
    const needle = search.trim().toLowerCase();
    const alertRows = alerts.filter((alert) => {
      const haystack = `${watchByID.get(alert.watch_id)?.name || ""} ${destinationTextOrID(destinationByID.get(alert.destination_id), alert.destination_id)}`.toLowerCase();
      return !needle || haystack.includes(needle);
    }).sort((a3, b2) => timestamp(b2.last_seen) - timestamp(a3.last_seen)).map((alert) => {
      const watch = watchByID.get(alert.watch_id);
      return { key: `${alert.watch_id}-${alert.destination_id}-${alert.evidence}`, cells: [
        /* @__PURE__ */ u3(Stacked, { primary: watch?.name || `Watch #${alert.watch_id}`, secondary: watch?.status }),
        destinationTextOrID(destinationByID.get(alert.destination_id), alert.destination_id),
        /* @__PURE__ */ u3(Badge, { evidence: alert.evidence, children: evidenceText(alert.evidence) }),
        alert.observation_count,
        /* @__PURE__ */ u3(Stacked, { primary: dateText(alert.first_seen), secondary: `Last: ${dateText(alert.last_seen)}` })
      ] };
    });
    const findingRows = findings.filter((finding) => {
      const watch = watchByID.get(finding.watch_id);
      const destination = destinationByID.get(finding.destination_id);
      const haystack = `${watch?.name || ""} ${watch?.group || ""} ${destinationTextOrID(destination, finding.destination_id)} ${finding.certificate_fingerprint}`.toLowerCase();
      return !needle || haystack.includes(needle);
    }).sort((a3, b2) => timestamp(b2.time) - timestamp(a3.time)).map((finding) => {
      const watch = watchByID.get(finding.watch_id);
      const destination = destinationByID.get(finding.destination_id);
      return { key: String(finding.id), cells: [
        /* @__PURE__ */ u3(Stacked, { primary: watch?.name || `Watch #${finding.watch_id}`, secondary: watch ? `${watch.status} \xB7 ${watch.severity}` : void 0 }),
        /* @__PURE__ */ u3(Stacked, { primary: destinationTextOrID(destination, finding.destination_id), secondary: destination?.vantage ? `Vantage: ${destination.vantage}` : void 0 }),
        /* @__PURE__ */ u3(Badge, { evidence: finding.evidence, children: evidenceText(finding.evidence) }),
        /* @__PURE__ */ u3("code", { class: "mono", children: finding.certificate_fingerprint || "\u2014" }),
        dateText(finding.time),
        /* @__PURE__ */ u3("code", { class: "mono", children: finding.probe_id })
      ] };
    });
    return /* @__PURE__ */ u3("section", { id: "exposure", "aria-labelledby": "exposure-title", children: [
      /* @__PURE__ */ u3(SectionHeader, { number: "04", eyebrow: "Investigation", title: "Potential CA exposure", titleID: "exposure-title", exportResource: "findings", filter }),
      /* @__PURE__ */ u3("p", { class: "section-description", children: "Direct means the watched certificate or key was presented to a probe. Candidate means it appeared only in a reconstructed path using the configured trust store. Name only requires investigation." }),
      /* @__PURE__ */ u3(CommunityShare, {}),
      /* @__PURE__ */ u3("div", { class: "filters", children: [
        /* @__PURE__ */ u3("div", { children: [
          /* @__PURE__ */ u3("label", { htmlFor: "finding-watch", children: "Watched CA" }),
          /* @__PURE__ */ u3("select", { id: "finding-watch", value: filter.watchID, onChange: (event) => setFilter({ ...filter, watchID: event.currentTarget.value }), children: [
            /* @__PURE__ */ u3("option", { value: "", children: "All watched CAs" }),
            watches.map((watch) => /* @__PURE__ */ u3("option", { value: watch.id, children: watch.name }, watch.id))
          ] })
        ] }),
        /* @__PURE__ */ u3("div", { children: [
          /* @__PURE__ */ u3("label", { htmlFor: "finding-from", children: "From" }),
          /* @__PURE__ */ u3("input", { id: "finding-from", type: "datetime-local", value: filter.from, onChange: (event) => setFilter({ ...filter, from: event.currentTarget.value }) })
        ] }),
        /* @__PURE__ */ u3("div", { children: [
          /* @__PURE__ */ u3("label", { htmlFor: "finding-to", children: "Through" }),
          /* @__PURE__ */ u3("input", { id: "finding-to", type: "datetime-local", value: filter.to, onChange: (event) => setFilter({ ...filter, to: event.currentTarget.value }) })
        ] }),
        /* @__PURE__ */ u3("div", { children: [
          /* @__PURE__ */ u3("label", { htmlFor: "finding-search", children: "Search" }),
          /* @__PURE__ */ u3("input", { id: "finding-search", type: "search", placeholder: "Destination or CA", value: search, onInput: (event) => setSearch(event.currentTarget.value) })
        ] })
      ] }),
      /* @__PURE__ */ u3("h3", { children: "Grouped alerts" }),
      /* @__PURE__ */ u3("div", { class: "table-wrap", children: /* @__PURE__ */ u3(DataTable, { caption: `${alertRows.length} grouped alert${alertRows.length === 1 ? "" : "s"}`, headers: ["Watched CA", "Destination", "Evidence", "Observations", "First / last seen"], rows: alertRows, empty: "No grouped alerts match these filters." }) }),
      /* @__PURE__ */ u3("h3", { children: "Observation history" }),
      /* @__PURE__ */ u3("div", { class: "table-wrap", children: /* @__PURE__ */ u3(DataTable, { caption: `${findingRows.length} potential exposure finding${findingRows.length === 1 ? "" : "s"}${findings.length >= 1e4 ? " (API limit reached; use export for a wider result)" : ""}`, headers: ["Watched CA", "Destination", "Evidence", "Matched certificate", "Observed", "Probe ID"], rows: findingRows, empty: "No findings match these filters." }) })
    ] });
  }
  function DestinationsView({ destinations, probes, search, setSearch }) {
    const recentByKey = /* @__PURE__ */ new Map();
    const byID = new Map(destinations.map((destination) => [destination.id, destination]));
    for (const destination of destinations) {
      const key = destinationKey(destination);
      const previous = recentByKey.get(key);
      if (!previous || timestamp(destination.time) > timestamp(previous.time)) recentByKey.set(key, destination);
    }
    const probesByKey = /* @__PURE__ */ new Map();
    for (const probe of probes) {
      const destination = byID.get(probe.destination_id);
      if (!destination) continue;
      const key = destinationKey(destination);
      const list = probesByKey.get(key) || [];
      list.push(probe);
      probesByKey.set(key, list);
    }
    const needle = search.trim().toLowerCase();
    const rows = [...recentByKey.values()].filter((destination) => {
      const haystack = `${destinationText(destination)} ${destination.collector} ${destination.vantage} ${destination.workload || ""}`.toLowerCase();
      return !needle || haystack.includes(needle);
    }).sort((a3, b2) => timestamp(b2.time) - timestamp(a3.time)).map((destination) => {
      const list = [...probesByKey.get(destinationKey(destination)) || []].sort((a3, b2) => timestamp(b2.time) - timestamp(a3.time));
      const latest = list[0];
      const leafVersions = new Set(list.map((probe) => probe.presented?.[0]?.fingerprint_sha256).filter(Boolean));
      const history = latest ? /* @__PURE__ */ u3("div", { children: [
        /* @__PURE__ */ u3(Stacked, { primary: dateText(latest.time), secondary: `${list.length} probe${list.length === 1 ? "" : "s"}; ${leafVersions.size} observed leaf version${leafVersions.size === 1 ? "" : "s"}` }),
        /* @__PURE__ */ u3(ProbeDetails, { probe: latest }),
        list.length > 1 && /* @__PURE__ */ u3("details", { children: [
          /* @__PURE__ */ u3("summary", { children: "Certificate history" }),
          /* @__PURE__ */ u3("ol", { class: "detail-content", children: list.map((probe) => {
            const leaf = probe.presented?.[0];
            return /* @__PURE__ */ u3("li", { children: [
              dateText(probe.time),
              " \xB7 ",
              leaf?.subject || (probe.failure ? `Probe failed: ${probe.failure}` : "No leaf recorded"),
              " \xB7 ",
              shortHash(leaf?.fingerprint_sha256)
            ] }, probe.id);
          }) })
        ] })
      ] }) : "Not probed yet";
      return { key: destinationKey(destination), cells: [
        /* @__PURE__ */ u3(Stacked, { primary: destinationText(destination), secondary: destination.hostname && destination.ip ? `Resolved target IP: ${destination.ip}` : void 0 }),
        /* @__PURE__ */ u3(Stacked, { primary: destination.collector || "Unknown", secondary: `Vantage: ${destination.vantage || "unknown"}` }),
        destination.attribution_reliable && destination.workload ? destination.workload : "Not supplied reliably",
        dateText(destination.time),
        history
      ] };
    });
    return /* @__PURE__ */ u3("section", { id: "destinations", "aria-labelledby": "destinations-title", children: [
      /* @__PURE__ */ u3(SectionHeader, { number: "05", eyebrow: "Collection", title: "Destinations", titleID: "destinations-title", exportResource: "destinations" }),
      /* @__PURE__ */ u3("p", { class: "section-description", children: "Destination identities and optional workload attribution come from collectors. Chain evidence comes only from independent probes." }),
      /* @__PURE__ */ u3("div", { class: "filters", children: /* @__PURE__ */ u3("div", { children: [
        /* @__PURE__ */ u3("label", { htmlFor: "destination-search", children: "Search destinations" }),
        /* @__PURE__ */ u3("input", { id: "destination-search", type: "search", placeholder: "Hostname, IP, source, or vantage", value: search, onInput: (event) => setSearch(event.currentTarget.value) })
      ] }) }),
      /* @__PURE__ */ u3("div", { class: "table-wrap", children: /* @__PURE__ */ u3(DataTable, { caption: `${rows.length} unique destination${rows.length === 1 ? "" : "s"} shown${destinations.length >= 1e4 ? " (recent API limit reached)" : ""}`, headers: ["Destination", "Collector", "Workload attribution", "Last event", "Latest independent probe"], rows, empty: "No destinations have been collected yet." }) })
    ] });
  }
  function CAView({ cas, destinations, probes, search, setSearch }) {
    const destinationsByID = new Map(destinations.map((destination) => [destination.id, destination]));
    const associated = /* @__PURE__ */ new Map();
    function add(certificate, label) {
      if (!certificate.is_ca || !certificate.fingerprint_sha256) return;
      const key = certificate.fingerprint_sha256.toLowerCase();
      const labels = associated.get(key) || /* @__PURE__ */ new Set();
      labels.add(label);
      associated.set(key, labels);
    }
    for (const probe of probes) {
      const label = destinationText(destinationsByID.get(probe.destination_id));
      for (const certificate of probe.presented || []) add(certificate, label);
      for (const path of probe.candidate_paths || []) for (const certificate of path.certificates || []) add(certificate, label);
    }
    const needle = search.trim().toLowerCase();
    const rows = cas.filter(({ certificate }) => {
      const haystack = `${certificate.subject} ${certificate.issuer} ${certificate.fingerprint_sha256} ${certificate.spki_sha256}`.toLowerCase();
      return !needle || haystack.includes(needle);
    }).sort((a3, b2) => timestamp(b2.last_seen) - timestamp(a3.last_seen)).map((record) => {
      const certificate = record.certificate;
      const labels = [...associated.get(certificate.fingerprint_sha256.toLowerCase()) || []].sort();
      return { key: certificate.fingerprint_sha256, cells: [
        /* @__PURE__ */ u3(Stacked, { primary: certificate.subject || "Unknown subject", secondary: `Issuer: ${certificate.issuer || "unknown"}` }),
        /* @__PURE__ */ u3("div", { children: [
          /* @__PURE__ */ u3("div", { class: "mono", children: [
            "Cert: ",
            certificate.fingerprint_sha256 || "unknown"
          ] }),
          /* @__PURE__ */ u3("div", { class: "mono", children: [
            "Key: ",
            certificate.spki_sha256 || "unknown"
          ] })
        ] }),
        /* @__PURE__ */ u3("div", { children: [
          record.presented_observations > 0 && /* @__PURE__ */ u3(Badge, { evidence: "direct", children: [
            "Presented \xB7 ",
            record.presented_observations
          ] }),
          record.candidate_observations > 0 && /* @__PURE__ */ u3(Badge, { evidence: "candidate", children: [
            "Candidate \xB7 ",
            record.candidate_observations
          ] })
        ] }),
        /* @__PURE__ */ u3("div", { children: record.watch_matches?.length ? record.watch_matches.map((watch) => /* @__PURE__ */ u3(Badge, { evidence: watch.evidence, children: [
          watch.name,
          ": ",
          watch.status
        ] }, `${watch.watch_id}-${watch.evidence}`)) : "\u2014" }),
        /* @__PURE__ */ u3("div", { children: [
          record.destination_count ?? 0,
          labels.length > 0 && /* @__PURE__ */ u3("details", { children: [
            /* @__PURE__ */ u3("summary", { children: "View recent loaded destinations" }),
            /* @__PURE__ */ u3("ul", { class: "detail-content", children: labels.map((label) => /* @__PURE__ */ u3("li", { children: label }, label)) })
          ] })
        ] }),
        /* @__PURE__ */ u3(Stacked, { primary: dateText(record.first_seen), secondary: `Last: ${dateText(record.last_seen)}` })
      ] };
    });
    return /* @__PURE__ */ u3("section", { id: "ca-inventory", "aria-labelledby": "ca-title", children: [
      /* @__PURE__ */ u3(SectionHeader, { number: "06", eyebrow: "Certificates", title: "CA inventory", titleID: "ca-title", exportResource: "cas" }),
      /* @__PURE__ */ u3("p", { class: "section-description", children: "Presented intermediates are observed directly. Candidate roots are supplied by a configured trust store and are labeled inferred." }),
      /* @__PURE__ */ u3("div", { class: "filters", children: /* @__PURE__ */ u3("div", { children: [
        /* @__PURE__ */ u3("label", { htmlFor: "ca-search", children: "Search CA certificates" }),
        /* @__PURE__ */ u3("input", { id: "ca-search", type: "search", placeholder: "Subject, issuer, fingerprint, or key", value: search, onInput: (event) => setSearch(event.currentTarget.value) })
      ] }) }),
      /* @__PURE__ */ u3("div", { class: "table-wrap", children: /* @__PURE__ */ u3(DataTable, { caption: `${rows.length} CA certificate${rows.length === 1 ? "" : "s"}`, headers: ["Certificate", "SHA-256 identities", "Evidence", "Watch status", "Destinations", "First / last observation"], rows, empty: "No CA certificates have been inventoried yet." }) })
    ] });
  }
  function ProbeView({ probes, destinations, filter, setFilter }) {
    const destinationsByID = new Map(destinations.map((destination) => [destination.id, destination]));
    const rows = probes.filter((probe) => filter === "all" || Boolean(probe.failure)).sort((a3, b2) => timestamp(b2.time) - timestamp(a3.time)).map((probe) => ({
      key: String(probe.id),
      cells: [
        dateText(probe.time),
        /* @__PURE__ */ u3(Stacked, { primary: destinationTextOrID(destinationsByID.get(probe.destination_id), probe.destination_id), secondary: `Vantage: ${probe.vantage || "unknown"}` }),
        /* @__PURE__ */ u3("div", { children: [
          /* @__PURE__ */ u3(Badge, { evidence: probe.failure ? "failed" : "success", children: probe.failure ? "Inspection failed" : "Connection completed" }),
          /* @__PURE__ */ u3("div", { class: "secondary", children: probe.failure || probe.validation_error || (probe.incomplete_chain ? "Incomplete presented chain" : "No validation error recorded") })
        ] }),
        probe.presented?.length || 0,
        /* @__PURE__ */ u3(ProbeDetails, { probe })
      ]
    }));
    return /* @__PURE__ */ u3("section", { id: "probes", "aria-labelledby": "probes-title", children: [
      /* @__PURE__ */ u3(SectionHeader, { number: "07", eyebrow: "Independent connections", title: "Probe history", titleID: "probes-title", exportResource: "probes" }),
      /* @__PURE__ */ u3("p", { class: "section-description", children: "Failures and validation errors are inspection results, not evidence of compromise. Expand a probe for presented certificates and candidate paths." }),
      /* @__PURE__ */ u3("div", { class: "filters", children: /* @__PURE__ */ u3("div", { children: [
        /* @__PURE__ */ u3("label", { htmlFor: "probe-result-filter", children: "Result" }),
        /* @__PURE__ */ u3("select", { id: "probe-result-filter", value: filter, onChange: (event) => setFilter(event.currentTarget.value), children: [
          /* @__PURE__ */ u3("option", { value: "all", children: "All probes" }),
          /* @__PURE__ */ u3("option", { value: "failed", children: "Failed probes" })
        ] })
      ] }) }),
      /* @__PURE__ */ u3("div", { class: "table-wrap", children: /* @__PURE__ */ u3(DataTable, { caption: `${rows.length} ${filter === "failed" ? "failed " : ""}independent TLS probe${rows.length === 1 ? "" : "s"}${probes.length >= 1e4 ? " (recent API limit reached)" : ""}`, headers: ["Time", "Destination", "Result", "Presented certificates", "Evidence"], rows, empty: filter === "failed" ? "No failed probes are in the loaded history." : "No independent probes have run yet." }) })
    ] });
  }
  function WatchView({ watches, crls, incident, onSaved }) {
    const rows = [...watches].sort((a3, b2) => a3.name.localeCompare(b2.name)).map((watch) => ({
      key: String(watch.id),
      cells: [
        /* @__PURE__ */ u3(Stacked, { primary: watch.name, secondary: watch.group }),
        /* @__PURE__ */ u3(Stacked, { primary: watch.match_type, secondary: /* @__PURE__ */ u3("code", { class: "mono", children: watch.value }) }),
        /* @__PURE__ */ u3("div", { children: [
          /* @__PURE__ */ u3(Badge, { children: watch.status }),
          /* @__PURE__ */ u3("div", { class: "secondary", children: [
            "Severity: ",
            watch.severity
          ] })
        ] }),
        watch.reason || "\u2014",
        /* @__PURE__ */ u3(Stacked, { primary: watch.source || "Manual dashboard entry", secondary: `${dateText(watch.effective_from)} to ${dateText(watch.effective_to)}` })
      ]
    }));
    const incidentRows = (incident?.intermediates || []).flatMap((ca) => ca.certificates.map((cert) => ({
      key: cert.sha256,
      cells: [
        /* @__PURE__ */ u3(Stacked, { primary: ca.name, secondary: ca.usage === "tls" ? "TLS intermediate" : "Code-signing intermediate" }),
        cert.issued_by,
        /* @__PURE__ */ u3("code", { class: "mono", children: cert.sha256 }),
        /* @__PURE__ */ u3("code", { class: "mono", children: cert.serial_hex }),
        /* @__PURE__ */ u3("code", { class: "mono", children: ca.spki_sha256 })
      ]
    })));
    return /* @__PURE__ */ u3("section", { id: "watchlist", "aria-labelledby": "watchlist-title", children: [
      /* @__PURE__ */ u3(SectionHeader, { number: "02", eyebrow: "Monitoring sources", title: "CA watchlist & CRLs", titleID: "watchlist-title", exportResource: "watches" }),
      /* @__PURE__ */ u3("p", { class: "section-description", children: "Certainted starts with eight exact eMudhra intermediate-key watches covering 16 certificates reported revoked in the 2026 incident. Six keys are for TLS and two are for code signing, which ordinary TLS probes will not encounter. These incident reports are source-based watch entries, not imported or signature-verified CRLs. You can also load JSON or CSV watches or import a signed CRL here. Historical probes are reevaluated when watches are added." }),
      /* @__PURE__ */ u3(MonitoringImports, { onImported: onSaved }),
      /* @__PURE__ */ u3("h3", { children: "CA watches" }),
      /* @__PURE__ */ u3("div", { class: "table-wrap", children: /* @__PURE__ */ u3(DataTable, { caption: `${rows.length} watchlist entr${rows.length === 1 ? "y" : "ies"}`, headers: ["CA / group", "Match rule", "Status", "Reason", "Provenance / effective dates"], rows, empty: "No watchlist entries have been configured yet." }) }),
      incident && /* @__PURE__ */ u3("details", { class: "watch-form-wrap", children: [
        /* @__PURE__ */ u3("summary", { children: "View the 16 documented eMudhra certificate identities" }),
        /* @__PURE__ */ u3("p", { children: "Each pair shares one watched public key. This bundled incident record is source-attributed, but Certainted has not verified a CRL for these entries. A match is potential exposure from an independent probe, not proof of what an application received. Historical matches may predate revocation. Active watches are listed above and may be edited or removed." }),
        /* @__PURE__ */ u3("div", { class: "table-wrap", role: "region", "aria-label": "eMudhra incident certificate identities", tabIndex: 0, children: /* @__PURE__ */ u3(DataTable, { caption: `${incidentRows.length} reported revoked certificate variants`, headers: ["Intermediate", "Issued by", "Certificate SHA-256", "Serial (hex)", "Public-key SHA-256"], rows: incidentRows, empty: "Incident identifiers unavailable." }) }),
        /* @__PURE__ */ u3("p", { children: [
          "Sources: ",
          /* @__PURE__ */ u3("a", { href: incident.sources[0], target: "_blank", rel: "noopener noreferrer", children: "Mozilla incident record" }),
          " and ",
          /* @__PURE__ */ u3("a", { href: incident.sources[2], target: "_blank", rel: "noopener noreferrer", children: "eMudhra statement" }),
          ". Bundled as of ",
          incident.as_of,
          "."
        ] })
      ] }),
      /* @__PURE__ */ u3(WatchForm, { onSaved }),
      /* @__PURE__ */ u3("p", { class: "monitoring-crl-link", children: [
        crls.length,
        " imported CRL",
        crls.length === 1 ? "" : "s",
        ". ",
        /* @__PURE__ */ u3("a", { href: "#imported-crls", children: "View CRL history and freshness" }),
        "."
      ] })
    ] });
  }
  function App() {
    const [stats, setStats] = d2({});
    const [destinations, setDestinations] = d2([]);
    const [probes, setProbes] = d2([]);
    const [cas, setCAs] = d2([]);
    const [watches, setWatches] = d2([]);
    const [incident, setIncident] = d2(null);
    const [findings, setFindings] = d2([]);
    const [revocationFindings, setRevocationFindings] = d2([]);
    const [allRevocationFindings, setAllRevocationFindings] = d2([]);
    const [crls, setCRLs] = d2([]);
    const [alerts, setAlerts] = d2([]);
    const [filter, setFilter] = d2({ watchID: "", from: "", to: "" });
    const [revocationFilter, setRevocationFilter] = d2({ from: "", to: "", evidence: "" });
    const [revocationSearch, setRevocationSearch] = d2("");
    const [findingSearch, setFindingSearch] = d2("");
    const [destinationSearch, setDestinationSearch] = d2("");
    const [caSearch, setCASearch] = d2("");
    const [probeFilter, setProbeFilter] = d2("all");
    const [status, setStatus] = d2("Loading local inventory\u2026");
    const [refreshKey, setRefreshKey] = d2(0);
    const refreshInventory = q2(() => setRefreshKey((key) => key + 1), []);
    const openExposure = q2(() => {
      setFilter({ watchID: "", from: "", to: "" });
      setFindingSearch("");
      window.location.hash = "exposure";
    }, []);
    const openRevocations = q2(() => {
      window.location.hash = "revocations";
    }, []);
    h2(() => {
      let active = true;
      setStatus("Loading local inventory\u2026");
      const paths = ["stats", "destinations?limit=10000", "probes?limit=10000", "cas", "watches", "revocations/crls", "revocations/findings?limit=10000", "incidents"];
      void Promise.allSettled(paths.map((path) => getJSON(`/api/${path}`))).then((results) => {
        if (!active) return;
        const errors = [];
        for (const [index, result] of results.entries()) {
          if (result.status === "rejected") {
            errors.push(result.reason instanceof Error ? result.reason.message : String(result.reason));
            continue;
          }
          const value = result.value;
          if (index === 0) setStats(value || {});
          if (index === 1) setDestinations(asList(value));
          if (index === 2) setProbes(asList(value));
          if (index === 3) setCAs(asList(value));
          if (index === 4) setWatches(asList(value));
          if (index === 5) setCRLs(asList(value));
          if (index === 6) setAllRevocationFindings(asList(value));
          if (index === 7) setIncident(value);
        }
        setStatus(errors.length ? `Some local data could not be loaded: ${errors.join("; ")}` : `Inventory updated ${(/* @__PURE__ */ new Date()).toLocaleTimeString()}.`);
      });
      return () => {
        active = false;
      };
    }, [refreshKey]);
    h2(() => {
      let active = true;
      const query = timeQuery(filter);
      void Promise.all([
        getJSON(`/api/findings?${query.toString()}`),
        getJSON(`/api/alerts?${query.toString()}`)
      ]).then(([findingData, alertData]) => {
        if (!active) return;
        setFindings(asList(findingData));
        setAlerts(asList(alertData));
      }).catch((error) => {
        if (active) setStatus(`Could not load historical findings: ${error instanceof Error ? error.message : String(error)}`);
      });
      return () => {
        active = false;
      };
    }, [filter.watchID, filter.from, filter.to, refreshKey]);
    h2(() => {
      let active = true;
      const query = revocationQuery(revocationFilter);
      void getJSON(`/api/revocations/findings?${query.toString()}`).then((data) => {
        if (active) setRevocationFindings(asList(data));
      }).catch((error) => {
        if (active) setStatus(`Could not load revocation findings: ${error instanceof Error ? error.message : String(error)}`);
      });
      return () => {
        active = false;
      };
    }, [revocationFilter.from, revocationFilter.to, revocationFilter.evidence, refreshKey]);
    return /* @__PURE__ */ u3(S, { children: [
      /* @__PURE__ */ u3("a", { class: "skip-link", href: "#main", children: "Skip to content" }),
      /* @__PURE__ */ u3("header", { class: "site-header", children: [
        /* @__PURE__ */ u3("div", { class: "brand", children: [
          /* @__PURE__ */ u3("figure", { class: "brand-avatar", children: [
            /* @__PURE__ */ u3("img", { class: "brand-mark", src: "/sir-tainted-mark.svg", alt: "", width: "52", height: "52" }),
            /* @__PURE__ */ u3("figcaption", { children: "Sir Tainted" })
          ] }),
          /* @__PURE__ */ u3("div", { children: [
            /* @__PURE__ */ u3("strong", { children: "Certainted" }),
            /* @__PURE__ */ u3("span", { children: "Revoked Certificate Watch" })
          ] })
        ] }),
        /* @__PURE__ */ u3("nav", { "aria-label": "Sections", children: [
          /* @__PURE__ */ u3("a", { href: "#overview", children: "Overview" }),
          /* @__PURE__ */ u3("a", { href: "#watchlist", children: "CA watchlist & CRLs" }),
          /* @__PURE__ */ u3("a", { href: "#revocations", children: "Revoked certificates" }),
          /* @__PURE__ */ u3("a", { href: "#exposure", children: "CA exposure" }),
          /* @__PURE__ */ u3("a", { href: "#destinations", children: "Destinations" }),
          /* @__PURE__ */ u3("a", { href: "#ca-inventory", children: "CA inventory" }),
          /* @__PURE__ */ u3("a", { href: "#probes", children: "Probes" })
        ] }),
        /* @__PURE__ */ u3("div", { class: "header-actions", children: [
          /* @__PURE__ */ u3("span", { class: "local-pill", children: "Local instance" }),
          /* @__PURE__ */ u3("button", { type: "button", onClick: refreshInventory, children: "Refresh inventory" })
        ] })
      ] }),
      /* @__PURE__ */ u3("main", { id: "main", tabIndex: -1, children: [
        /* @__PURE__ */ u3("div", { class: "intro", children: [
          /* @__PURE__ */ u3("div", { class: "intro-copy", children: [
            /* @__PURE__ */ u3("p", { class: "eyebrow", children: "The field ledger / Local observation" }),
            /* @__PURE__ */ u3("h1", { children: "Revoked Certificate Watch" }),
            /* @__PURE__ */ u3("p", { class: "intro-lede", children: "Certainted runs on your computer or router. Its optional proxy relays encrypted traffic without decrypting or inspecting your application data, and never terminates your application's TLS session. Certainted opens a separate TLS connection to retrieve the destination's certificate chain." }),
            /* @__PURE__ */ u3("p", { class: "scope-note", children: [
              /* @__PURE__ */ u3("strong", { children: "A note from the watchtower" }),
              " A probe records what a destination presented to Certainted at that time and network vantage. It cannot show the original application's chain or trust decision."
            ] })
          ] }),
          /* @__PURE__ */ u3("figure", { class: "intro-portrait", children: [
            /* @__PURE__ */ u3("img", { src: "/sir-tainted-mark.svg", alt: "Sir Tainted, a smiling face in a knight's helmet", width: "400", height: "400" }),
            /* @__PURE__ */ u3("figcaption", { children: [
              /* @__PURE__ */ u3("strong", { children: "Sir Tainted" }),
              /* @__PURE__ */ u3("span", { children: "Observer of chains" })
            ] })
          ] })
        ] }),
        /* @__PURE__ */ u3("p", { class: "status", role: "status", "aria-live": "polite", children: status }),
        /* @__PURE__ */ u3(Overview, { stats, destinations, probes, findings, revocationFindings: allRevocationFindings, crlCount: crls.length, watchCount: watches.length, onNewAlert: refreshInventory, onOpenAlert: openExposure, onOpenRevocation: openRevocations, onProbeFilter: setProbeFilter }),
        /* @__PURE__ */ u3(WatchView, { watches, crls, incident, onSaved: async () => {
          refreshInventory();
        } }),
        /* @__PURE__ */ u3(RevocationsView, { crls, findings: revocationFindings, destinations, filter: revocationFilter, setFilter: setRevocationFilter, search: revocationSearch, setSearch: setRevocationSearch }),
        /* @__PURE__ */ u3(Exposure, { watches, destinations, findings, alerts, filter, setFilter, search: findingSearch, setSearch: setFindingSearch }),
        /* @__PURE__ */ u3(DestinationsView, { destinations, probes, search: destinationSearch, setSearch: setDestinationSearch }),
        /* @__PURE__ */ u3(CAView, { cas, destinations, probes, search: caSearch, setSearch: setCASearch }),
        /* @__PURE__ */ u3(ProbeView, { probes, destinations, filter: probeFilter, setFilter: setProbeFilter })
      ] }),
      /* @__PURE__ */ u3("footer", { children: [
        /* @__PURE__ */ u3("strong", { children: "Certainted observes; it does not block connections." }),
        " No external reporting unless you enable sharing; no third-party enrichment by default."
      ] })
    ] });
  }
  var mount = document.getElementById("app");
  if (mount) R(/* @__PURE__ */ u3(App, {}), mount);
})();
