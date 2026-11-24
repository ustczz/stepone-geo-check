'use strict';

/**
 * StepOneAI GEO Check Engine (Zero-Dependency Pure Code)
 * 6 Dimensions × 28 Real Verifiable AI Search & GEO Readiness Checks
 * Zero LLM token cost · Strict SSRF protection · Chinese/English encoding aware
 */

const http = require('http');
const https = require('https');
const dns = require('dns');
const net = require('net');
const zlib = require('zlib');
const { URL } = require('url');

const ENGINE_VERSION = '1.0.0';
const USER_AGENT = 'StepOneGEOCheck/1.0 (+https://geo.steponeai.com/check)';
const MAX_BODY_BYTES = 1.5 * 1024 * 1024; // 1.5 MB cap per fetch
const MAX_REDIRECTS = 4;

const AI_BOTS = [
  { id: 'Bytespider', label: '豆包 / 字节', family: 'china_ai', desc: '字节跳动豆包与头条 AI 搜索抓取' },
  { id: 'Baiduspider', label: '百度 / 文心', family: 'china_search', desc: '百度搜索与文心一言抓取' },
  { id: 'YisouSpider', label: '夸克 / 千问', family: 'china_search', desc: '阿里夸克与通义千问联网检索' },
  { id: 'OAI-SearchBot', label: 'ChatGPT 搜索', family: 'global_ai', desc: 'OpenAI ChatGPT 实时搜索引用' },
  { id: 'GPTBot', label: 'OpenAI 模型', family: 'global_ai', desc: 'OpenAI 语料与检索爬虫' },
  { id: 'DeepSeekBot', label: 'DeepSeek', family: 'china_ai', desc: 'DeepSeek 深度搜索与引用' },
  { id: 'ClaudeBot', label: 'Claude', family: 'global_ai', desc: 'Anthropic Claude 联网爬虫' },
  { id: 'PerplexityBot', label: 'Perplexity', family: 'global_ai', desc: 'Perplexity AI 答案引擎爬虫' },
  { id: 'Bingbot', label: '必应 Bing', family: 'global_search', desc: '微软必应与 Copilot 搜索底座' },
  { id: 'Googlebot', label: 'Google', family: 'global_search', desc: 'Google 搜索与 AI Overviews' }
];

// ==================== SSRF Guard ====================
function isPrivateOrBlockedIp(ip) {
  if (!ip) return true;
  let clean = String(ip).trim().toLowerCase();
  if (clean.startsWith('::ffff:')) clean = clean.slice(7);

  if (net.isIPv4(clean)) {
    const parts = clean.split('.').map(Number);
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true; // link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true; // multicast / reserved
    return false;
  }

  if (net.isIPv6(clean)) {
    if (clean === '::1' || clean === '::') return true;
    if (clean.startsWith('fc') || clean.startsWith('fd')) return true; // ULA
    if (clean.startsWith('fe8') || clean.startsWith('fe9') || clean.startsWith('fea') || clean.startsWith('feb')) return true; // link-local
    return false;
  }
  return true;
}

function normalizeTargetUrl(rawInput) {
  let s = String(rawInput || '').trim();
  if (!s) throw new Error('请输入有效的企业官网网址（例如 https://www.steponeai.com）');
  // Strip accidental trailing Chinese/English punctuation or surrounding quotes
  s = s.replace(/^["'「『（(]+|["'」』）)。，,;；]+$/g, '').trim();
  if (!/^https?:\/\//i.test(s)) {
    s = 'https://' + s;
  }
  let u;
  try {
    u = new URL(s);
  } catch (_) {
    throw new Error('网址格式不正确，请输入标准域名或网址（如 example.com）');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new Error('仅支持 http 或 https 协议的公开网站');
  }
  const host = u.hostname.toLowerCase();
  if (!host || !host.includes('.') || host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal')) {
    throw new Error('不支持检测本机或内网域名，请输入公开可访问的企业官网域名');
  }
  if (net.isIP(host) && isPrivateOrBlockedIp(host)) {
    throw new Error('出于安全限制，不允许检测私有或内网 IP 地址');
  }
  u.hash = '';
  return u;
}

function lookupPublicAddresses(hostname) {
  return new Promise((resolve, reject) => {
    dns.lookup(hostname, { all: true }, (err, addresses) => {
      if (err || !addresses || !addresses.length) {
        return reject(new Error(`域名 DNS 解析失败：${hostname}`));
      }
      for (const rec of addresses) {
        if (isPrivateOrBlockedIp(rec.address)) {
          return reject(new Error('目标域名解析到了受保护的内网地址，已拒绝探测'));
        }
      }
      resolve(addresses);
    });
  });
}

function decodeBuffer(buf, contentTypeHeader = '') {
  const ct = String(contentTypeHeader || '').toLowerCase();
  let encoding = 'utf-8';
  const mCt = ct.match(/charset=([a-z0-9\-_]+)/i);
  if (mCt) encoding = mCt[1].toLowerCase();

  let preview = buf.slice(0, 4096).toString('latin1');
  if (encoding === 'utf-8') {
    const mMeta = preview.match(/charset=["']?\s*(gb2312|gbk|gb18030)/i);
    if (mMeta) encoding = 'gb18030';
  }
  if (encoding === 'gb2312' || encoding === 'gbk') encoding = 'gb18030';

  try {
    return new TextDecoder(encoding).decode(buf);
  } catch (_) {
    return buf.toString('utf8');
  }
}

function decompressBody(buf, contentEncoding = '') {
  const ce = String(contentEncoding || '').toLowerCase();
  try {
    if (ce.includes('br')) return zlib.brotliDecompressSync(buf);
    if (ce.includes('gzip')) return zlib.gunzipSync(buf);
    if (ce.includes('deflate')) return zlib.inflateSync(buf);
  } catch (_) {}
  return buf;
}

async function safeFetch(urlStr, opts = {}) {
  const timeoutMs = opts.timeoutMs || 7000;
  const maxBytes = opts.maxBytes || MAX_BODY_BYTES;
  const allowInsecureTlsFallback = Boolean(opts.allowInsecureTlsFallback);

  let currentUrl = new URL(urlStr);
  let redirects = 0;
  const startedAt = Date.now();
  let lastTtfb = 0;

  while (redirects <= MAX_REDIRECTS) {
    const host = currentUrl.hostname.toLowerCase();
    if (!host || host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal')) {
      throw new Error('重定向目标为内网地址，已阻断');
    }
    const addrs = await lookupPublicAddresses(host);
    const chosenIp = addrs[0].address;
    const chosenFamily = addrs[0].family;

    const result = await new Promise((resolve, reject) => {
      const isHttps = currentUrl.protocol === 'https:';
      const client = isHttps ? https : http;
      const reqStart = Date.now();
      let settled = false;

      const finish = (err, val) => {
        if (settled) return;
        settled = true;
        if (err) reject(err);
        else resolve(val);
      };

      const reqOpts = {
        hostname: host,
        port: currentUrl.port || (isHttps ? 443 : 80),
        path: (currentUrl.pathname || '/') + (currentUrl.search || ''),
        method: 'GET',
        timeout: timeoutMs,
        lookup: (_h, opts, cb) => {
          if (opts && opts.all) {
            cb(null, [{ address: chosenIp, family: chosenFamily }]);
          } else {
            cb(null, chosenIp, chosenFamily);
          }
        },
        headers: {
          'User-Agent': USER_AGENT,
          'Accept': opts.accept || 'text/html,application/xhtml+xml,text/plain,application/xml,*/*;q=0.8',
          'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
          'Accept-Encoding': 'gzip, deflate, br',
          'Connection': 'close'
        }
      };
      if (isHttps && allowInsecureTlsFallback) {
        reqOpts.rejectUnauthorized = false;
      }

      const req = client.request(reqOpts, (res) => {
        lastTtfb = Date.now() - reqStart;
        const status = res.statusCode || 0;
        const headers = res.headers || {};

        if (status >= 300 && status < 400 && headers.location) {
          res.resume();
          return finish(null, { redirect: headers.location, status, headers });
        }

        const chunks = [];
        let total = 0;
        let truncated = false;
        res.on('data', (chunk) => {
          if (total < maxBytes) {
            const remain = maxBytes - total;
            chunks.push(chunk.length > remain ? chunk.slice(0, remain) : chunk);
            total += Math.min(chunk.length, remain);
          } else {
            truncated = true;
          }
        });
        res.on('end', () => {
          const rawBuf = Buffer.concat(chunks);
          const bodyBuf = decompressBody(rawBuf, headers['content-encoding']);
          const text = decodeBuffer(bodyBuf, headers['content-type']);
          finish(null, {
            ok: status >= 200 && status < 300,
            status,
            headers,
            text,
            rawBytes: bodyBuf.length,
            truncated,
            finalUrl: currentUrl.href,
            ttfbMs: lastTtfb,
            elapsedMs: Date.now() - startedAt
          });
        });
        res.on('error', (e) => finish(e));
      });

      req.on('timeout', () => {
        req.destroy(new Error(`连接超时 (${timeoutMs}ms)`));
      });
      req.on('error', (e) => finish(e));
      req.end();
    });

    if (result.redirect) {
      redirects += 1;
      currentUrl = new URL(result.redirect, currentUrl);
      if (currentUrl.protocol !== 'http:' && currentUrl.protocol !== 'https:') {
        throw new Error('非法的重定向协议');
      }
      continue;
    }

    return result;
  }

  throw new Error('重定向次数过多');
}

// ==================== Robots.txt Parser ====================
function parseRobotsTxt(rawText) {
  const text = String(rawText || '');
  const lines = text.split(/\r?\n/);
  const groups = [];
  let curGroup = null;
  const sitemaps = [];

  for (const rawLine of lines) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const val = line.slice(colon + 1).trim();
    if (key === 'sitemap' && val) {
      sitemaps.push(val);
    } else if (key === 'user-agent') {
      if (!curGroup || curGroup.rules.length > 0) {
        curGroup = { agents: [], rules: [] };
        groups.push(curGroup);
      }
      curGroup.agents.push(val.toLowerCase());
    } else if ((key === 'disallow' || key === 'allow') && curGroup) {
      curGroup.rules.push({ type: key, path: val });
    }
  }

  function evaluateBot(botName) {
    const botLow = botName.toLowerCase();
    // Exact or substring match takes precedence over wildcard '*'
    const specificRules = [];
    const wildcardRules = [];
    for (const g of groups) {
      if (g.agents.some(a => a === botLow || (a !== '*' && botLow.includes(a)))) {
        specificRules.push(...g.rules);
      } else if (g.agents.includes('*')) {
        wildcardRules.push(...g.rules);
      }
    }
    const rules = specificRules.length ? specificRules : wildcardRules;
    const matchedExplicit = specificRules.length > 0;
    if (!rules.length) {
      return { allowed: true, explicit: false, reason: '默认放行（未设限制）' };
    }
    // Check root path "/"
    let bestMatch = null;
    for (const r of rules) {
      if (r.path === '') {
        if (r.type === 'disallow' && !bestMatch) {
          bestMatch = { type: 'allow', len: 0 };
        }
        continue;
      }
      if (r.path === '/' || r.path === '/*') {
        const len = r.path.length;
        if (!bestMatch || len > bestMatch.len || (len === bestMatch.len && r.type === 'allow')) {
          bestMatch = { type: r.type, len };
        }
      }
    }
    if (bestMatch && bestMatch.type === 'disallow') {
      return {
        allowed: false,
        explicit: matchedExplicit,
        reason: matchedExplicit ? `被明确 Disallow: / 拦截` : `被全局 User-agent: * Disallow: / 拦截`
      };
    }
    return {
      allowed: true,
      explicit: matchedExplicit,
      reason: matchedExplicit ? '显式 Allow 放行' : '正常放行'
    };
  }

  return { groups, sitemaps, evaluateBot };
}

// ==================== HTML & Structured Data Analyzer ====================
function decodeHtmlEntities(str) {
  return String(str || '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

function extractMetaContent(html, attrName, attrValue) {
  const re = new RegExp(`<meta\\b[^>]*${attrName}=["']${attrValue}["'][^>]*>`, 'i');
  const m = html.match(re);
  if (!m) return '';
  const c = m[0].match(/content=["']([^"']*)["']/i);
  return c ? decodeHtmlEntities(c[1]) : '';
}

function analyzeHtmlDocument(html, headers = {}) {
  const rawHtml = String(html || '');
  const htmlBytes = Buffer.byteLength(rawHtml, 'utf8');

  const titleMatch = rawHtml.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleMatch ? decodeHtmlEntities(titleMatch[1]) : '';

  const description = extractMetaContent(rawHtml, 'name', 'description');
  const metaRobots = extractMetaContent(rawHtml, 'name', 'robots').toLowerCase();
  const xRobotsTag = String(headers['x-robots-tag'] || '').toLowerCase();

  const ogTitle = extractMetaContent(rawHtml, 'property', 'og:title');
  const ogDesc = extractMetaContent(rawHtml, 'property', 'og:description');
  const ogImage = extractMetaContent(rawHtml, 'property', 'og:image');

  const canonicalMatch = rawHtml.match(/<link\b[^>]*rel=["']canonical["'][^>]*href=["']([^"']+)["']/i)
    || rawHtml.match(/<link\b[^>]*href=["']([^"']+)["'][^>]*rel=["']canonical["']/i);
  const canonical = canonicalMatch ? canonicalMatch[1].trim() : '';

  const hasLlmsLinkRel = /<link\b[^>]*href=["'][^"']*llms(?:-full)?\.txt["']/i.test(rawHtml)
    || /<link\b[^>]*type=["']text\/markdown["']/i.test(rawHtml);

  // Extract JSON-LD blocks
  const jsonLdTypes = new Set();
  let jsonLdCount = 0;
  let jsonLdParseErrors = 0;
  let hasSameAs = false;
  let hasContactPoint = false;

  const ldRe = /<script\b[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let ldMatch;
  while ((ldMatch = ldRe.exec(rawHtml)) !== null) {
    const block = ldMatch[1].trim();
    if (!block) continue;
    try {
      const parsed = JSON.parse(block);
      jsonLdCount += 1;
      const walk = (node) => {
        if (!node || typeof node !== 'object') return;
        if (Array.isArray(node)) {
          node.forEach(walk);
          return;
        }
        if (node['@type']) {
          if (Array.isArray(node['@type'])) node['@type'].forEach(t => jsonLdTypes.add(String(t)));
          else jsonLdTypes.add(String(node['@type']));
        }
        if (node.sameAs && ((Array.isArray(node.sameAs) && node.sameAs.length) || typeof node.sameAs === 'string')) {
          hasSameAs = true;
        }
        if (node.contactPoint) hasContactPoint = true;
        if (node['@graph']) walk(node['@graph']);
        for (const v of Object.values(node)) {
          if (v && typeof v === 'object') walk(v);
        }
      };
      walk(parsed);
    } catch (_) {
      jsonLdParseErrors += 1;
    }
  }

  // Extract headings
  const extractTags = (tag) => {
    const out = [];
    const re = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'gi');
    let m;
    while ((m = re.exec(rawHtml)) !== null) {
      const clean = decodeHtmlEntities(m[1].replace(/<[^>]+>/g, ' '));
      if (clean) out.push(clean);
    }
    return out;
  };
  const h1List = extractTags('h1');
  const h2List = extractTags('h2');
  const h3List = extractTags('h3');

  // Count real HTML tables with rows/cells
  const tables = rawHtml.match(/<table\b[\s\S]*?<\/table>/gi) || [];
  const semanticTables = tables.filter(t => /<tr\b/i.test(t) && (/<th\b/i.test(t) || (t.match(/<td\b/gi) || []).length >= 4));

  // Image alt coverage
  const imgs = rawHtml.match(/<img\b[^>]*>/gi) || [];
  let imgsWithAlt = 0;
  for (const tag of imgs) {
    const am = tag.match(/\balt=["']([^"']+)["']/i);
    if (am && am[1].trim().length >= 2) imgsWithAlt += 1;
  }

  // Strip non-content tags to measure SSR visible text
  const stripped = rawHtml
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<script\b[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[\s\S]*?<\/style>/gi, ' ')
    .replace(/<svg\b[\s\S]*?<\/svg>/gi, ' ')
    .replace(/<noscript\b[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<head\b[\s\S]*?<\/head>/gi, ' ')
    .replace(/<[^>]+>/g, ' ');
  const visibleText = decodeHtmlEntities(stripped);
  const visibleCharCount = visibleText.length;
  const textToHtmlRatio = htmlBytes > 0 ? Number(((Buffer.byteLength(visibleText, 'utf8') / htmlBytes) * 100).toFixed(1)) : 0;

  // Detect hollow SPA shell
  const hasSpaMountRoot = /<div\s+id=["'](?:root|app|__next|__nuxt)["'][^>]*>\s*<\/div>/i.test(rawHtml);
  const isHollowSpa = visibleCharCount < 220 && (hasSpaMountRoot || (rawHtml.match(/<script\b/gi) || []).length >= 2);

  // Authority & trust signals
  const hasIcp = /[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼]ICP备\s*\d+号?/i.test(visibleText);
  const hasLegalEntity = /(?:有限责任公司|股份有限公司|科技有限公司|集团有限公司|信息技术有限公司|Co\.?,?\s*Ltd\.?|Inc\.|Corporation)/i.test(visibleText);
  const hasContactSignal = /mailto:|tel:|\b1[3-9]\d{9}\b|400[-\s]?\d{3}[-\s]?\d{4}|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i.test(rawHtml);
  const faqHeadingHits = [...h2List, ...h3List].filter(h => /[?？]|常见问题|FAQ|如何|怎么|区别|多少钱|哪家|对比/i.test(h)).length;

  const isNoIndex = metaRobots.includes('noindex') || xRobotsTag.includes('noindex');
  const isNoAi = metaRobots.includes('noai') || metaRobots.includes('noimageai') || xRobotsTag.includes('noai');

  return {
    htmlBytes,
    title,
    description,
    metaRobots,
    xRobotsTag,
    isNoIndex,
    isNoAi,
    ogTitle,
    ogDesc,
    ogImage,
    canonical,
    hasLlmsLinkRel,
    jsonLdCount,
    jsonLdParseErrors,
    jsonLdTypes: Array.from(jsonLdTypes),
    hasSameAs,
    hasContactPoint,
    h1List,
    h2List,
    h3List,
    tableCount: semanticTables.length,
    imgCount: imgs.length,
    imgsWithAlt,
    visibleCharCount,
    textToHtmlRatio,
    isHollowSpa,
    hasIcp,
    hasLegalEntity,
    hasContactSignal,
    faqHeadingHits
  };
}

// ==================== Custom Ready-to-Paste Fix Code Synthesizer ====================
function buildRemediationSnippets(targetUrl, htmlInfo, origin) {
  const host = targetUrl.hostname;
  const siteName = (htmlInfo.title || host).split(/[|\-_—·]/)[0].trim() || host;
  const siteDesc = htmlInfo.description || `${siteName} 官方网站与核心产品服务介绍。`;
  const topH2s = (htmlInfo.h2List || []).slice(0, 5);

  const llmsTxt = [
    `# ${siteName}`,
    '',
    `> ${siteDesc}`,
    '',
    `## 核心信息`,
    `- 官方网站：${origin}/`,
    `- 核心定位：${htmlInfo.h1List[0] || siteName}`,
    '',
    `## 核心产品与栏目`,
    ...(topH2s.length
      ? topH2s.map(h => `- ${h}`)
      : [`- 产品与解决方案：${origin}/`, `- 客户案例与选型说明：${origin}/`, `- 联系我们与商务对接：${origin}/contact`]),
    '',
    `## 机器可读索引`,
    `- 站点地图：${origin}/sitemap.xml`,
    `- 全量知识语料：${origin}/llms-full.txt`
  ].join('\n');

  const robotsTxt = [
    `# AI 搜索与主流搜索引擎友好放行配置 (由基智 GEO 体检生成)`,
    `User-agent: *`,
    `Allow: /`,
    '',
    `# 显式放行豆包 / 百度 / 夸克千问 / ChatGPT / Claude / Perplexity / Bing`,
    `User-agent: Bytespider`,
    `Allow: /`,
    '',
    `User-agent: Baiduspider`,
    `Allow: /`,
    '',
    `User-agent: YisouSpider`,
    `Allow: /`,
    '',
    `User-agent: OAI-SearchBot`,
    `Allow: /`,
    '',
    `User-agent: GPTBot`,
    `Allow: /`,
    '',
    `User-agent: ClaudeBot`,
    `Allow: /`,
    '',
    `User-agent: PerplexityBot`,
    `Allow: /`,
    '',
    `Sitemap: ${origin}/sitemap.xml`
  ].join('\n');

  const schemaObj = {
    '@context': 'https://schema.org',
    '@graph': [
      {
        '@type': 'Organization',
        '@id': `${origin}/#organization`,
        name: siteName,
        url: `${origin}/`,
        description: siteDesc,
        sameAs: [`${origin}/`]
      },
      {
        '@type': 'WebSite',
        '@id': `${origin}/#website`,
        name: siteName,
        url: `${origin}/`,
        publisher: { '@id': `${origin}/#organization` }
      },
      {
        '@type': 'FAQPage',
        mainEntity: [
          {
            '@type': 'Question',
            name: `${siteName} 核心提供哪些产品与服务？`,
            acceptedAnswer: {
              '@type': 'Answer',
              text: siteDesc
            }
          }
        ]
      }
    ]
  };
  const jsonLd = `<script type="application/ld+json">\n${JSON.stringify(schemaObj, null, 2)}\n</script>`;

  return { llmsTxt, robotsTxt, jsonLd };
}

function gradeFromScore(score) {
  if (score >= 90) return { grade: 'S', label: 'AI 搜索标杆级', color: '#10B981' };
  if (score >= 78) return { grade: 'A', label: 'AI 高度友好', color: '#016DFF' };
  if (score >= 62) return { grade: 'B', label: '基础可被收录', color: '#3B82F6' };
  if (score >= 45) return { grade: 'C', label: '明显缺失待优化', color: '#F59E0B' };
  return { grade: 'D', label: 'AI 几乎不可见 · 急需改造', color: '#EF4444' };
}

// ==================== Main Audit Entrypoint ====================
async function runGeoCheck(rawUrl) {
  const startedAt = Date.now();
  const targetUrl = normalizeTargetUrl(rawUrl);

  // 1. Fetch main HTML (fallback to HTTP or relaxed TLS if HTTPS fails)
  let mainRes = null;
  let usedHttps = targetUrl.protocol === 'https:';
  try {
    mainRes = await safeFetch(targetUrl.href, { timeoutMs: 8000 });
  } catch (err1) {
    if (usedHttps) {
      try {
        mainRes = await safeFetch(targetUrl.href, { timeoutMs: 7000, allowInsecureTlsFallback: true });
      } catch (_) {
        const httpFallback = new URL(targetUrl.href);
        httpFallback.protocol = 'http:';
        mainRes = await safeFetch(httpFallback.href, { timeoutMs: 7000 });
        usedHttps = false;
      }
    } else {
      throw err1;
    }
  }

  const finalUrlObj = new URL(mainRes.finalUrl || targetUrl.href);
  const origin = `${finalUrlObj.protocol}//${finalUrlObj.host}`;
  usedHttps = finalUrlObj.protocol === 'https:';

  // 2. Parallel auxiliary probes (robots.txt, llms.txt, llms-full.txt, sitemap.xml, content.json)
  const probe = async (pathStr, accept) => {
    try {
      return await safeFetch(`${origin}${pathStr}`, { timeoutMs: 5000, maxBytes: 512 * 1024, accept, allowInsecureTlsFallback: true });
    } catch (e) {
      return { ok: false, status: 0, text: '', rawBytes: 0, error: e.message };
    }
  };

  const [robotsRes, llmsRes, llmsFullRes, sitemapRes, contentJsonRes] = await Promise.all([
    probe('/robots.txt', 'text/plain,*/*'),
    probe('/llms.txt', 'text/markdown,text/plain,*/*'),
    probe('/llms-full.txt', 'text/markdown,text/plain,*/*'),
    probe('/sitemap.xml', 'application/xml,text/xml,*/*'),
    probe('/content.json', 'application/json,*/*')
  ]);

  const htmlInfo = analyzeHtmlDocument(mainRes.text, mainRes.headers);
  const robotsValid = robotsRes.ok && robotsRes.text && !/^\s*<!doctype\s+html|<html/i.test(robotsRes.text);
  const robotsParsed = parseRobotsTxt(robotsValid ? robotsRes.text : '');

  const llmsValid = llmsRes.ok && llmsRes.text && !/^\s*<!doctype\s+html|<html/i.test(llmsRes.text) && llmsRes.text.trim().length >= 40;
  const llmsFullValid = llmsFullRes.ok && llmsFullRes.text && !/^\s*<!doctype\s+html|<html/i.test(llmsFullRes.text) && llmsFullRes.text.trim().length >= 400;
  const sitemapValid = sitemapRes.ok && /<(?:urlset|sitemapindex)\b/i.test(sitemapRes.text || '');
  const sitemapUrlCount = sitemapValid ? ((sitemapRes.text.match(/<loc>/gi) || []).length) : 0;
  let contentJsonValid = false;
  if (contentJsonRes.ok && contentJsonRes.text) {
    try {
      const cj = JSON.parse(contentJsonRes.text);
      contentJsonValid = Boolean(cj && typeof cj === 'object');
    } catch (_) {}
  }

  // Evaluate 10 AI & search crawlers
  const botMatrix = AI_BOTS.map((b) => {
    const ev = robotsParsed.evaluateBot(b.id);
    const blocked = !ev.allowed || htmlInfo.isNoIndex || (htmlInfo.isNoAi && b.family.includes('ai'));
    return {
      id: b.id,
      label: b.label,
      family: b.family,
      desc: b.desc,
      allowed: !blocked,
      explicit: ev.explicit,
      reason: htmlInfo.isNoIndex ? '页面含 noindex 阻断' : (htmlInfo.isNoAi && b.family.includes('ai') ? '页面含 noai 阻断' : ev.reason)
    };
  });

  const botAllowed = (id) => Boolean((botMatrix.find(x => x.id === id) || {}).allowed);

  // ==================== Build 6 Dimensions × 28 Checks ====================
  const checks = [];
  const addCheck = (dim, id, title, maxPoints, earnedPoints, status, evidence, fixAdvice) => {
    checks.push({ dim, id, title, maxPoints, earnedPoints, status, evidence, fixAdvice });
  };

  // --- Dimension 1: AI 爬虫准入与协议合规 (20分, 6项) ---
  addCheck('crawl', 'robots_exists', '部署规范 /robots.txt 爬虫协议', 3, robotsValid ? 3 : 0,
    robotsValid ? 'pass' : 'fail',
    robotsValid ? `HTTP ${robotsRes.status} · 大小 ${robotsRes.rawBytes} B` : `未检测到有效 robots.txt (HTTP ${robotsRes.status || '超时'})`,
    '在站点根目录部署标准 /robots.txt 并显式声明 AI 与搜索引擎放行策略。');

  const byteOk = botAllowed('Bytespider');
  addCheck('crawl', 'bot_bytespider', '放行字节豆包爬虫 (Bytespider)', 4, byteOk ? 4 : 0,
    byteOk ? 'pass' : 'fail',
    byteOk ? '允许抓取（豆包 / 头条搜索可正常访问）' : '被 robots.txt 拦截，豆包无法抓取官网',
    '在 robots.txt 中移除对 Bytespider 的 Disallow，并显式添加 User-agent: Bytespider / Allow: /。');

  const oaiOk = botAllowed('OAI-SearchBot') && botAllowed('GPTBot');
  addCheck('crawl', 'bot_openai', '放行 ChatGPT 检索爬虫 (OAI-SearchBot / GPTBot)', 4, oaiOk ? 4 : (botAllowed('OAI-SearchBot') ? 2 : 0),
    oaiOk ? 'pass' : (botAllowed('OAI-SearchBot') ? 'warn' : 'fail'),
    oaiOk ? 'OAI-SearchBot 与 GPTBot 均已放行' : `OAI-SearchBot: ${botAllowed('OAI-SearchBot') ? '放行' : '拦截'} · GPTBot: ${botAllowed('GPTBot') ? '放行' : '拦截'}`,
    '显式放行 OAI-SearchBot 与 GPTBot，确保 ChatGPT 联网搜索可实时引用官网。');

  const otherAiOk = botAllowed('ClaudeBot') && botAllowed('PerplexityBot') && botAllowed('DeepSeekBot');
  addCheck('crawl', 'bot_global_ai', '放行 DeepSeek / Claude / Perplexity 爬虫', 3, otherAiOk ? 3 : 1,
    otherAiOk ? 'pass' : 'warn',
    otherAiOk ? 'DeepSeek / ClaudeBot / PerplexityBot 均正常放行' : '部分海外/AI 爬虫存在拦截规则',
    '检查 robots.txt 中是否存在误伤 AI 爬虫的屏蔽段并放行主流检索爬虫。');

  const searchOk = botAllowed('Baiduspider') && botAllowed('YisouSpider') && botAllowed('Bingbot') && botAllowed('Googlebot');
  addCheck('crawl', 'bot_search', '放行百度 / 夸克千问 / 必应 / Google 搜索爬虫', 3, searchOk ? 3 : 0,
    searchOk ? 'pass' : 'fail',
    searchOk ? '4 大传统与 AI 融合搜索底层爬虫全部放行' : '存在主流搜索引擎爬虫被禁止抓取',
    '确保 Baiduspider、YisouSpider（夸克/千问）、Bingbot 与 Googlebot 均为 Allow。');

  const noBlockMeta = !htmlInfo.isNoIndex && !htmlInfo.isNoAi;
  addCheck('crawl', 'meta_robots_clean', '未误设 noindex / noai 阻断指令', 3, noBlockMeta ? 3 : 0,
    noBlockMeta ? 'pass' : 'fail',
    noBlockMeta ? 'Meta Robots 与 X-Robots-Tag 均无阻断标记' : `检测到阻断标签：meta="${htmlInfo.metaRobots}" header="${htmlInfo.xRobotsTag}"`,
    '删除页面 <meta name="robots" content="noindex"> 及响应头中的 noindex / noai 限制。');

  // --- Dimension 2: AI 知识清单与索引完备度 (20分, 5项) ---
  addCheck('manifest', 'llms_txt', '配置标准 /llms.txt AI 官网摘要索引', 6, llmsValid ? 6 : 0,
    llmsValid ? 'pass' : 'fail',
    llmsValid ? `HTTP 200 · ${llmsRes.rawBytes} 字节有效 Markdown 索引` : `缺失 /llms.txt (HTTP ${llmsRes.status || 404})`,
    '在站点根目录上线 /llms.txt，用清晰 Markdown 列出企业主体、核心产品与关键页面 URL。');

  addCheck('manifest', 'llms_full_txt', '提供 /llms-full.txt 全量机器可读知识语料', 5, llmsFullValid ? 5 : 0,
    llmsFullValid ? 'pass' : 'fail',
    llmsFullValid ? `HTTP 200 · ${(llmsFullRes.rawBytes / 1024).toFixed(1)} KB 全量语料` : `未提供 /llms-full.txt (HTTP ${llmsFullRes.status || 404})`,
    '构建 /llms-full.txt 汇总产品参数、选型表格与 FAQ，让大模型一次拉取完整权威事实。');

  addCheck('manifest', 'sitemap_xml', '部署规范 /sitemap.xml 站点地图', 4, sitemapValid ? 4 : 0,
    sitemapValid ? 'pass' : 'fail',
    sitemapValid ? `HTTP 200 · 有效收录 ${sitemapUrlCount} 条 URL` : `未检测到有效 /sitemap.xml (HTTP ${sitemapRes.status || 404})`,
    '生成标准 XML Sitemap 并定期同步至百度站长平台、Bing Webmaster 与 Google Search Console。');

  const aiDiscovery = contentJsonValid || htmlInfo.hasLlmsLinkRel;
  addCheck('manifest', 'ai_discovery_link', '声明 AI 发现入口 (<link alternate> 或 /content.json)', 3, aiDiscovery ? 3 : 0,
    aiDiscovery ? 'pass' : 'warn',
    aiDiscovery ? `${htmlInfo.hasLlmsLinkRel ? '含 Markdown alternate 声明' : ''}${contentJsonValid ? ' · 含 /content.json' : ''}`.replace(/^\s*·\s*/, '') : '未在 <head> 声明 llms.txt 关联标签或 /content.json',
    '在 HTML <head> 中添加 <link rel="alternate" type="text/markdown" href="/llms.txt"> 提升爬虫发现率。');

  const robotsHasSitemap = robotsParsed.sitemaps.length > 0;
  addCheck('manifest', 'robots_sitemap_ref', 'robots.txt 显式指向 Sitemap 地址', 2, robotsHasSitemap ? 2 : 0,
    robotsHasSitemap ? 'pass' : 'warn',
    robotsHasSitemap ? `已声明 ${robotsParsed.sitemaps.length} 条 Sitemap 索引` : 'robots.txt 中未包含 Sitemap: 行',
    '在 /robots.txt 末尾增加 Sitemap: https://你的域名/sitemap.xml。');

  // --- Dimension 3: SSR 首屏可读性与纯文本信噪比 (20分, 5项) ---
  const notHollow = !htmlInfo.isHollowSpa && htmlInfo.visibleCharCount >= 300;
  addCheck('ssr', 'ssr_not_hollow', '无 JS 首屏 SSR 可读（非空壳 SPA）', 7, notHollow ? 7 : (htmlInfo.visibleCharCount >= 150 ? 3 : 0),
    notHollow ? 'pass' : (htmlInfo.visibleCharCount >= 150 ? 'warn' : 'fail'),
    notHollow ? `无 JS 原始 HTML 含 ${htmlInfo.visibleCharCount} 字符有效正文` : `无 JS 首屏仅 ${htmlInfo.visibleCharCount} 字符，疑似纯前端 SPA 空壳，AI 爬虫几乎读不到正文`,
    '改用 SSR 服务端渲染或预渲染静态 HTML，确保不执行 JS 也能完整输出核心产品文案。');

  const richText = htmlInfo.visibleCharCount >= 800;
  addCheck('ssr', 'ssr_text_density', '首屏核心业务信息充实度 (≥ 800 字符)', 4, richText ? 4 : (htmlInfo.visibleCharCount >= 400 ? 2 : 0),
    richText ? 'pass' : (htmlInfo.visibleCharCount >= 400 ? 'warn' : 'fail'),
    `首屏提取纯文本 ${htmlInfo.visibleCharCount} 字符`,
    '补充清晰的场景说明、核心参数对比与客户问题解答，避免纯图片堆砌导致文本稀薄。');

  const goodRatio = htmlInfo.textToHtmlRatio >= 8;
  addCheck('ssr', 'ssr_signal_ratio', 'HTML 纯文本信噪比健康 (≥ 8%)', 3, goodRatio ? 3 : (htmlInfo.textToHtmlRatio >= 3 ? 1 : 0),
    goodRatio ? 'pass' : (htmlInfo.textToHtmlRatio >= 3 ? 'warn' : 'fail'),
    `正文占比 ${htmlInfo.textToHtmlRatio}%（HTML ${(htmlInfo.htmlBytes / 1024).toFixed(1)} KB）`,
    '精简内联冗余 JS/CSS，将核心文本前置到 HTML 主干区域，提高大模型切片提取质量。');

  const fastTtfb = mainRes.ttfbMs <= 800;
  const okTtfb = mainRes.ttfbMs <= 1800;
  addCheck('ssr', 'ssr_ttfb', '首屏服务器响应速度 (TTFB)', 3, fastTtfb ? 3 : (okTtfb ? 2 : 0),
    fastTtfb ? 'pass' : (okTtfb ? 'warn' : 'fail'),
    `实测 TTFB ${mainRes.ttfbMs} ms（HTTP ${mainRes.status}）`,
    '启用服务端缓存、Gzip/Brotli 压缩或 CDN 边缘加速，将 TTFB 控制在 800ms 以内。');

  addCheck('ssr', 'https_security', '全站 HTTPS 安全加密传输', 3, usedHttps ? 3 : 0,
    usedHttps ? 'pass' : 'fail',
    usedHttps ? `已启用 HTTPS (${finalUrlObj.origin})` : '当前仅通过不安全的 HTTP 访问',
    '配置有效 SSL 证书并将全站 HTTP 301 强制跳转至 HTTPS。');

  // --- Dimension 4: 结构化实体与 Schema 知识图谱 (20分, 5项) ---
  const hasJsonLd = htmlInfo.jsonLdCount > 0 && htmlInfo.jsonLdParseErrors === 0;
  addCheck('schema', 'schema_jsonld', '嵌入合法可解析 JSON-LD 结构化数据', 5, hasJsonLd ? 5 : (htmlInfo.jsonLdCount > 0 ? 2 : 0),
    hasJsonLd ? 'pass' : (htmlInfo.jsonLdCount > 0 ? 'warn' : 'fail'),
    hasJsonLd ? `解析到 ${htmlInfo.jsonLdCount} 个 JSON-LD 块：${htmlInfo.jsonLdTypes.slice(0, 6).join(', ') || '已声明'}` : (htmlInfo.jsonLdParseErrors > 0 ? `存在 ${htmlInfo.jsonLdParseErrors} 个语法错误 JSON-LD` : '页面完全缺失 JSON-LD 结构化数据'),
    '在页面 <head> 嵌入标准 Schema.org JSON-LD，明确定义企业实体、产品与 FAQ。');

  const hasOrg = htmlInfo.jsonLdTypes.some(t => /Organization|Corporation|LocalBusiness/i.test(t));
  addCheck('schema', 'schema_org', '声明企业主体实体 (Organization + sameAs)', 5, (hasOrg && htmlInfo.hasSameAs) ? 5 : (hasOrg ? 3 : 0),
    (hasOrg && htmlInfo.hasSameAs) ? 'pass' : (hasOrg ? 'warn' : 'fail'),
    hasOrg ? `已声明 Organization${htmlInfo.hasSameAs ? ' 且含 sameAs 官方矩阵对齐' : '（建议补齐 sameAs 与 contactPoint）'}` : '未声明 Organization 企业实体 Schema',
    '补充 Organization JSON-LD，写入法定全称、官方域名、sameAs 官方矩阵与商务联系方式。');

  const hasBizSchema = htmlInfo.jsonLdTypes.some(t => /FAQPage|Product|SoftwareApplication|Service|Article|WebSite/i.test(t));
  addCheck('schema', 'schema_faq_product', '声明业务 / 产品 / 问答 Schema (FAQPage / Product)', 4, hasBizSchema ? 4 : 0,
    hasBizSchema ? 'pass' : 'fail',
    hasBizSchema ? `命中业务实体：${htmlInfo.jsonLdTypes.filter(t => /FAQPage|Product|SoftwareApplication|Service|Article|WebSite/i.test(t)).join(', ')}` : '缺失 FAQPage / Product / SoftwareApplication 业务 Schema',
    '在核心落地页补充 FAQPage 与 Product/SoftwareApplication JSON-LD，直喂大模型问答槽位。');

  addCheck('schema', 'html_tables', '包含原生 HTML <table> 参数/选型对比表', 3, htmlInfo.tableCount > 0 ? 3 : 0,
    htmlInfo.tableCount > 0 ? 'pass' : 'warn',
    htmlInfo.tableCount > 0 ? `检测到 ${htmlInfo.tableCount} 个规范 HTML 结构化数据表` : '首屏未检测到原生 HTML <table> 对比表（仅用 div/图片排版不利于 AI 抽取对比结论）',
    '用标准 <table><thead><tbody> 呈现核心参数、版本对比或代际优势，显著提升 DeepSeek/千问引用率。');

  const hasOgCanonical = Boolean(htmlInfo.canonical && htmlInfo.ogTitle && htmlInfo.ogDesc);
  addCheck('schema', 'og_canonical', 'Canonical 权威链接与 OpenGraph 卡片齐全', 3, hasOgCanonical ? 3 : ((htmlInfo.canonical || htmlInfo.ogTitle) ? 1 : 0),
    hasOgCanonical ? 'pass' : ((htmlInfo.canonical || htmlInfo.ogTitle) ? 'warn' : 'fail'),
    `canonical: ${htmlInfo.canonical ? '有' : '缺'} · og:title: ${htmlInfo.ogTitle ? '有' : '缺'} · og:image: ${htmlInfo.ogImage ? '有' : '缺'}`,
    '补全 <link rel="canonical"> 与 og:title / og:description / og:image，防止多 URL 权重分散。');

  // --- Dimension 5: 语义层级与引用友好度 (10分, 4项) ---
  const titleLen = htmlInfo.title.length;
  const goodTitle = titleLen >= 10 && titleLen <= 75;
  addCheck('semantic', 'meta_title', '页面标题 <title> 清晰规范', 3, goodTitle ? 3 : (titleLen > 0 ? 1 : 0),
    goodTitle ? 'pass' : (titleLen > 0 ? 'warn' : 'fail'),
    titleLen > 0 ? `长度 ${titleLen} 字：“${htmlInfo.title.slice(0, 48)}${titleLen > 48 ? '...' : ''}”` : '缺失 <title> 标签',
    '将 <title> 控制在 15–60 字内，前置「品牌名 + 核心买方业务词」。');

  const descLen = htmlInfo.description.length;
  const goodDesc = descLen >= 35 && descLen <= 200;
  addCheck('semantic', 'meta_desc', '元描述 <meta description> 精准概括价值', 2, goodDesc ? 2 : (descLen > 0 ? 1 : 0),
    goodDesc ? 'pass' : (descLen > 0 ? 'warn' : 'fail'),
    descLen > 0 ? `长度 ${descLen} 字` : '缺失 <meta name="description">',
    '撰写 50–150 字包含核心业务词与差异化事实的 description，作为搜索引擎与 AI 首屏摘要。');

  const goodHeadings = htmlInfo.h1List.length === 1 && htmlInfo.h2List.length >= 2;
  addCheck('semantic', 'heading_hierarchy', '唯一 <h1> 主标题 + 完整 <h2> 语义骨架', 3, goodHeadings ? 3 : (htmlInfo.h1List.length >= 1 ? 1 : 0),
    goodHeadings ? 'pass' : (htmlInfo.h1List.length >= 1 ? 'warn' : 'fail'),
    `H1: ${htmlInfo.h1List.length} 个 · H2: ${htmlInfo.h2List.length} 个 · H3: ${htmlInfo.h3List.length} 个`,
    '保证每页仅 1 个聚焦核心业务的 <h1>，用 <h2>/<h3> 拆解清晰模块便于 RAG 分块。');

  const altRate = htmlInfo.imgCount > 0 ? Math.round((htmlInfo.imgsWithAlt / htmlInfo.imgCount) * 100) : 100;
  addCheck('semantic', 'img_alt', '图片 alt 语义描述覆盖率 (多模态友好)', 2, altRate >= 70 ? 2 : (altRate >= 35 ? 1 : 0),
    altRate >= 70 ? 'pass' : (altRate >= 35 ? 'warn' : 'fail'),
    htmlInfo.imgCount > 0 ? `${htmlInfo.imgsWithAlt}/${htmlInfo.imgCount} 张图片含有效 alt（${altRate}%）` : '页面无 <img> 标签（纯文本/CSS 展示）',
    '为产品界面图与架构图补全包含产品名与场景词的中文 alt 文本，助力豆包等多模态检索。');

  // --- Dimension 6: 企业权威主体与转化信任信号 (10分, 3项) ---
  const hasEntityTrust = htmlInfo.hasLegalEntity || htmlInfo.hasIcp;
  addCheck('authority', 'entity_icp', '明确企业法定主体与 ICP 备案信任背书', 4, (htmlInfo.hasLegalEntity && htmlInfo.hasIcp) ? 4 : (hasEntityTrust ? 2 : 0),
    (htmlInfo.hasLegalEntity && htmlInfo.hasIcp) ? 'pass' : (hasEntityTrust ? 'warn' : 'fail'),
    `企业主体词：${htmlInfo.hasLegalEntity ? '已识别' : '未识别'} · ICP 备案号：${htmlInfo.hasIcp ? '已识别' : '未识别'}`,
    '在首屏/页脚清晰公示企业法定全称、资质背书与 ICP 备案号，强化大模型可信度校验。');

  addCheck('authority', 'faq_quotable', '包含问答型 / 选型决策直接可引用段落', 3, htmlInfo.faqHeadingHits > 0 ? 3 : 0,
    htmlInfo.faqHeadingHits > 0 ? 'pass' : 'warn',
    htmlInfo.faqHeadingHits > 0 ? `识别到 ${htmlInfo.faqHeadingHits} 个问答/选型类小标题` : '未识别到“如何/怎么/多少钱/常见问题”类直接问答小标题',
    '增设买家真实高频选型 FAQ（先给直接结论再展开事实），大幅提高 AI 直接整段引用概率。');

  addCheck('authority', 'contact_anchor', '具备清晰商务联系与官方核验通道', 3, htmlInfo.hasContactSignal ? 3 : 0,
    htmlInfo.hasContactSignal ? 'pass' : 'warn',
    htmlInfo.hasContactSignal ? '检测到邮箱 / 电话等明确商务联系锚点' : '首屏 HTML 中未检测到清晰商务邮箱或电话锚点',
    '公开官方企业邮箱、联系页或企微对接通道，方便 AI 回答“怎么联系该公司”时准确输出。');

  // Aggregate per-dimension scores
  const dimDefs = [
    { key: 'crawl', name: 'AI 爬虫准入', max: 20 },
    { key: 'manifest', name: 'AI 知识清单', max: 20 },
    { key: 'ssr', name: 'SSR 首屏可读', max: 20 },
    { key: 'schema', name: '结构化 Schema', max: 20 },
    { key: 'semantic', name: '语义引用层级', max: 10 },
    { key: 'authority', name: '权威信任信号', max: 10 }
  ];

  const dimensions = dimDefs.map((d) => {
    const items = checks.filter(c => c.dim === d.key);
    const earned = items.reduce((sum, c) => sum + c.earnedPoints, 0);
    const pct = Math.round((earned / d.max) * 100);
    return { key: d.key, name: d.name, earned, max: d.max, pct };
  });

  const totalScore = dimensions.reduce((sum, d) => sum + d.earned, 0);
  const gradeInfo = gradeFromScore(totalScore);

  const failedChecks = checks
    .filter(c => c.status !== 'pass')
    .sort((a, b) => (b.maxPoints - b.earnedPoints) - (a.maxPoints - a.earnedPoints));

  const topIssues = failedChecks.slice(0, 3).map(c => ({
    id: c.id,
    title: c.title,
    status: c.status,
    lostPoints: c.maxPoints - c.earnedPoints,
    evidence: c.evidence,
    fixAdvice: c.fixAdvice
  }));

  const passCount = checks.filter(c => c.status === 'pass').length;
  const warnCount = checks.filter(c => c.status === 'warn').length;
  const failCount = checks.filter(c => c.status === 'fail').length;

  const snippets = buildRemediationSnippets(finalUrlObj, htmlInfo, origin);

  return {
    engineVersion: ENGINE_VERSION,
    checkedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    inputUrl: String(rawUrl || '').trim(),
    finalUrl: finalUrlObj.href,
    origin,
    hostname: finalUrlObj.hostname,
    siteTitle: htmlInfo.title || finalUrlObj.hostname,
    httpStatus: mainRes.status,
    ttfbMs: mainRes.ttfbMs,
    totalScore,
    grade: gradeInfo.grade,
    gradeLabel: gradeInfo.label,
    gradeColor: gradeInfo.color,
    summaryCounts: { total: checks.length, pass: passCount, warn: warnCount, fail: failCount },
    dimensions,
    botMatrix,
    topIssues,
    checks,
    snippets,
    rawMetrics: {
      visibleCharCount: htmlInfo.visibleCharCount,
      htmlBytes: htmlInfo.htmlBytes,
      textToHtmlRatio: htmlInfo.textToHtmlRatio,
      isHollowSpa: htmlInfo.isHollowSpa,
      jsonLdCount: htmlInfo.jsonLdCount,
      jsonLdTypes: htmlInfo.jsonLdTypes,
      tableCount: htmlInfo.tableCount,
      sitemapUrlCount,
      llmsBytes: llmsValid ? llmsRes.rawBytes : 0,
      llmsFullBytes: llmsFullValid ? llmsFullRes.rawBytes : 0
    }
  };
}

module.exports = {
  ENGINE_VERSION,
  AI_BOTS,
  normalizeTargetUrl,
  runGeoCheck
};
