require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { firefox } = require('playwright');
const { searchSubtitles, parseToVTT } = require('wyzie-lib');

const app = express();
app.use(cors());
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', req.header('Access-Control-Request-Headers') || '*');
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
});
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const bcrypt = require('bcryptjs');

const TMDB_API_KEY = process.env.TMDB_API_KEY || 'YOUR_TMDB_API_KEY';
const TMDB_BASE = 'https://api.themoviedb.org/3';

// User account store persisted to disk
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MAX_PROFILES_PER_ACCOUNT = 5;

function ensureDataDir() {
    try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) {}
}

function readUsersStore() {
    ensureDataDir();
    try {
        if (!fs.existsSync(USERS_FILE)) return {};
        const raw = fs.readFileSync(USERS_FILE, 'utf8');
        return raw ? JSON.parse(raw) : {};
    } catch (e) {
        console.warn('Failed to read users store:', e.message);
        return {};
    }
}

function writeUsersStore(store) {
    ensureDataDir();
    const tmp = USERS_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(store || {}, null, 2), 'utf8');
    fs.renameSync(tmp, USERS_FILE);
}

function generateToken() {
    return crypto.randomBytes(32).toString('base64url');
}

function sanitizeUserData(data) {
    const safe = { profiles: [], recents: {}, updatedAt: Date.now() };
    if (!data || typeof data !== 'object') return safe;

    const profiles = Array.isArray(data.profiles) ? data.profiles : [];
    safe.profiles = profiles
        .filter(p => p && typeof p === 'object')
        .slice(0, MAX_PROFILES_PER_ACCOUNT)
        .map(p => ({
            id: String(p.id || '').slice(0, 64),
            name: String(p.name || '').slice(0, 24),
            color: String(p.color || '').slice(0, 32)
        }))
        .filter(p => p.id && p.name);

    const recents = data.recents && typeof data.recents === 'object' ? data.recents : {};
    for (const [profileId, list] of Object.entries(recents)) {
        if (!profileId) continue;
        const arr = Array.isArray(list) ? list : [];
        safe.recents[String(profileId).slice(0, 64)] = arr
            .filter(x => x && typeof x === 'object')
            .slice(0, 50)
            .map(x => ({
                id: Number(x.id) || 0,
                title: String(x.title || '').slice(0, 200),
                poster: x.poster ? String(x.poster).slice(0, 200) : null,
                type: x.type === 'tv' ? 'tv' : 'movie',
                season: x.season != null ? String(x.season).slice(0, 16) : null,
                episode: x.episode != null ? String(x.episode).slice(0, 16) : null,
                timestamp: Number(x.timestamp) || 0,
                videoTime: Number(x.videoTime) || 0,
                duration: x.duration != null ? Number(x.duration) || 0 : undefined
            }))
            .filter(x => x.id && x.title);
    }

    return safe;
}

function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function validatePassword(password) {
    return password && password.length >= 6;
}

// Register new user
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body || {};
    
    if (!email || !validateEmail(email)) {
        return res.status(400).json({ error: 'Valid email required' });
    }
    if (!validatePassword(password)) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    const normalizedEmail = email.toLowerCase().trim();
    const store = readUsersStore();
    
    if (store[normalizedEmail]) {
        return res.status(409).json({ error: 'Email already registered' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const token = generateToken();
    
    store[normalizedEmail] = {
        email: normalizedEmail,
        password: hashedPassword,
        token,
        data: sanitizeUserData({ profiles: [], recents: {} }),
        createdAt: Date.now()
    };
    
    writeUsersStore(store);
    res.json({ token, email: normalizedEmail, data: store[normalizedEmail].data });
});

// Login user
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body || {};
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
    }
    
    const normalizedEmail = email.toLowerCase().trim();
    const store = readUsersStore();
    const user = store[normalizedEmail];
    
    if (!user) {
        return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Generate new token on login
    const token = generateToken();
    user.token = token;
    writeUsersStore(store);
    
    res.json({ token, email: normalizedEmail, data: user.data });
});

// Verify token and get user data
app.get('/api/auth/verify', (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ error: 'Token required' });
    }
    
    const store = readUsersStore();
    const user = Object.values(store).find(u => u.token === token);
    
    if (!user) {
        return res.status(401).json({ error: 'Invalid token' });
    }
    
    res.json({ email: user.email, data: user.data });
});

// Get user data
app.get('/api/user/data', (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ error: 'Token required' });
    }
    
    const store = readUsersStore();
    const user = Object.values(store).find(u => u.token === token);
    
    if (!user) {
        return res.status(401).json({ error: 'Invalid token' });
    }
    
    res.json(user.data);
});

// Update user data (profiles and recents)
app.post('/api/user/data', (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ error: 'Token required' });
    }
    
    const store = readUsersStore();
    const userEntry = Object.entries(store).find(([, u]) => u.token === token);
    
    if (!userEntry) {
        return res.status(401).json({ error: 'Invalid token' });
    }
    
    const [email, user] = userEntry;
    const { data } = req.body || {};
    
    // Check profile limit
    if (data?.profiles?.length > MAX_PROFILES_PER_ACCOUNT) {
        return res.status(400).json({ error: `Maximum ${MAX_PROFILES_PER_ACCOUNT} profiles allowed per account` });
    }
    
    user.data = sanitizeUserData(data);
    store[email] = user;
    writeUsersStore(store);
    
    res.json({ ok: true, updatedAt: user.data.updatedAt });
});

// Logout (invalidate token)
app.post('/api/auth/logout', (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ error: 'Token required' });
    }
    
    const store = readUsersStore();
    const userEntry = Object.entries(store).find(([, u]) => u.token === token);
    
    if (userEntry) {
        const [email, user] = userEntry;
        user.token = null;
        store[email] = user;
        writeUsersStore(store);
    }
    
    res.json({ ok: true });
});

// M3U8 cache (1 hour TTL)
const m3u8Cache = new Map();
const CACHE_TTL = 60 * 60 * 1000; // 1 hour in ms

function getCached(url) {
    const cached = m3u8Cache.get(url);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
        console.log(`Cache hit for: ${url}`);
        return cached.m3u8Url;
    }
    if (cached) m3u8Cache.delete(url);
    return null;
}

function setCache(url, m3u8Url) {
    m3u8Cache.set(url, { m3u8Url, timestamp: Date.now() });
    console.log(`Cached: ${url}`);
}

// Segment prefetch cache - stores downloaded segments in memory
const segmentCache = new Map();
const SEGMENT_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const SEGMENT_CACHE_MAX_SIZE = 200; // Max segments in cache
const PREFETCH_AHEAD = 30; // Prefetch 30 segments ahead (~2-3 min at 6s segments)
const CONCURRENT_DOWNLOADS = 8; // Like yt-dlp -N 8

// Active prefetch sessions per stream
const prefetchSessions = new Map();

function cleanSegmentCache() {
    const now = Date.now();
    for (const [key, entry] of segmentCache) {
        if (now - entry.timestamp > SEGMENT_CACHE_TTL) {
            segmentCache.delete(key);
        }
    }
    // Also enforce max size - remove oldest entries
    if (segmentCache.size > SEGMENT_CACHE_MAX_SIZE) {
        const entries = [...segmentCache.entries()].sort((a, b) => a[1].timestamp - b[1].timestamp);
        const toRemove = entries.slice(0, segmentCache.size - SEGMENT_CACHE_MAX_SIZE);
        for (const [key] of toRemove) {
            segmentCache.delete(key);
        }
    }
}

// Parallel download function (like yt-dlp -N)
async function downloadSegment(url, referer, retries = 3) {
    const cacheKey = url;
    const cached = segmentCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < SEGMENT_CACHE_TTL) {
        return cached.data;
    }

    const headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
    };
    if (referer) {
        headers['Referer'] = referer;
        try { headers['Origin'] = new URL(referer).origin; } catch {}
    }

    for (let attempt = 0; attempt < retries; attempt++) {
        try {
            const response = await fetch(url, { headers, signal: AbortSignal.timeout(30000) });
            if (response.ok) {
                const buffer = Buffer.from(await response.arrayBuffer());
                segmentCache.set(cacheKey, { data: buffer, timestamp: Date.now() });
                return buffer;
            }
        } catch (e) {
            if (attempt === retries - 1) throw e;
            await new Promise(r => setTimeout(r, 500 * (attempt + 1)));
        }
    }
    return null;
}

// Parse m3u8 playlist to get segment URLs
function parseM3U8Segments(m3u8Content, baseUrl) {
    const lines = m3u8Content.split('\n');
    const segments = [];
    let keyUrl = null;
    
    for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith('#EXT-X-KEY') && trimmed.includes('URI="')) {
            const match = trimmed.match(/URI="([^"]+)"/);
            if (match) {
                try { keyUrl = new URL(match[1], baseUrl).toString(); } catch { keyUrl = match[1]; }
            }
        } else if (trimmed && !trimmed.startsWith('#')) {
            try {
                segments.push(new URL(trimmed, baseUrl).toString());
            } catch {
                segments.push(trimmed.startsWith('http') ? trimmed : baseUrl + trimmed);
            }
        }
    }
    return { segments, keyUrl };
}

// Prefetch segments in parallel
async function prefetchSegments(m3u8Url, referer, fromIndex = 0) {
    const sessionKey = m3u8Url;
    
    // Check if already prefetching
    if (prefetchSessions.has(sessionKey)) {
        const session = prefetchSessions.get(sessionKey);
        if (Date.now() - session.startTime < 60000) return; // Still running
    }
    
    prefetchSessions.set(sessionKey, { startTime: Date.now(), status: 'running' });
    
    try {
        const headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
        };
        if (referer) headers['Referer'] = referer;
        
        const response = await fetch(m3u8Url, { headers });
        if (!response.ok) return;
        
        const m3u8Content = await response.text();
        const baseUrl = m3u8Url.substring(0, m3u8Url.lastIndexOf('/') + 1);
        const { segments, keyUrl } = parseM3U8Segments(m3u8Content, baseUrl);
        
        // Download encryption key first if present
        if (keyUrl && !segmentCache.has(keyUrl)) {
            await downloadSegment(keyUrl, referer);
        }
        
        // Download segments in parallel batches
        const toDownload = segments.slice(fromIndex, fromIndex + PREFETCH_AHEAD);
        console.log(`Prefetching ${toDownload.length} segments from index ${fromIndex}`);
        
        for (let i = 0; i < toDownload.length; i += CONCURRENT_DOWNLOADS) {
            const batch = toDownload.slice(i, i + CONCURRENT_DOWNLOADS);
            const promises = batch.map(url => 
                downloadSegment(url, referer).catch(e => {
                    console.warn(`Prefetch failed for segment: ${e.message}`);
                    return null;
                })
            );
            await Promise.all(promises);
            
            // Small delay between batches to avoid overwhelming server
            if (i + CONCURRENT_DOWNLOADS < toDownload.length) {
                await new Promise(r => setTimeout(r, 100));
            }
        }
        
        console.log(`Prefetch complete: ${toDownload.length} segments`);
        cleanSegmentCache();
    } catch (e) {
        console.error('Prefetch error:', e.message);
    } finally {
        prefetchSessions.delete(sessionKey);
    }
}

// Get segment from cache or download
async function getSegmentFromCacheOrDownload(url, referer) {
    const cached = segmentCache.get(url);
    if (cached && Date.now() - cached.timestamp < SEGMENT_CACHE_TTL) {
        cached.timestamp = Date.now(); // Refresh TTL on access
        return { data: cached.data, fromCache: true };
    }
    
    const data = await downloadSegment(url, referer);
    return { data, fromCache: false };
}

// Search movies/TV shows
app.get('/api/search', async (req, res) => {
    const { q, type = 'multi' } = req.query;
    if (!q) return res.status(400).json({ error: 'Query required' });
    
    try {
        const response = await fetch(
            `${TMDB_BASE}/search/${type}?api_key=${TMDB_API_KEY}&query=${encodeURIComponent(q)}`
        );
        const data = await response.json();
        res.json(data.results || []);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get TV show seasons/episodes
app.get('/api/tv/:id', async (req, res) => {
    try {
        const response = await fetch(
            `${TMDB_BASE}/tv/${req.params.id}?api_key=${TMDB_API_KEY}`
        );
        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get season episodes
app.get('/api/tv/:id/season/:season', async (req, res) => {
    try {
        const response = await fetch(
            `${TMDB_BASE}/tv/${req.params.id}/season/${req.params.season}?api_key=${TMDB_API_KEY}`
        );
        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get subtitles
app.get('/api/subtitles/:id', async (req, res) => {
    try {
        const { season, episode, language } = req.query;
        const params = { tmdb_id: parseInt(req.params.id) };
        if (season) params.season = parseInt(season);
        if (episode) params.episode = parseInt(episode);
        if (language) params.language = language;
        
        const subs = await searchSubtitles(params);
        res.json(subs || []);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get subtitle content as VTT
app.get('/api/subtitle-vtt', async (req, res) => {
    try {
        const { url } = req.query;
        if (!url) return res.status(400).json({ error: 'URL required' });
        
        const vtt = await parseToVTT(url);
        res.set('Content-Type', 'text/vtt');
        res.send(vtt);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Start prefetching segments for a stream
app.post('/api/prefetch', async (req, res) => {
    const { m3u8Url, referer } = req.body || {};
    if (!m3u8Url) {
        return res.status(400).json({ error: 'm3u8Url required' });
    }
    
    res.json({ ok: true, message: 'Prefetch started' });
    
    // Start prefetching in background
    prefetchSegments(m3u8Url, referer, 0).catch(e => {
        console.error('Background prefetch error:', e.message);
    });
});

// Get prefetch/cache stats
app.get('/api/prefetch/stats', (req, res) => {
    res.json({
        cachedSegments: segmentCache.size,
        activePrefetches: prefetchSessions.size,
        maxCacheSize: SEGMENT_CACHE_MAX_SIZE,
        prefetchAhead: PREFETCH_AHEAD,
        concurrentDownloads: CONCURRENT_DOWNLOADS
    });
});

// Proxy for m3u8 and video segments (fixes CORS on mobile)
app.get('/api/proxy', async (req, res) => {
    try {
        let { url } = req.query;
        if (!url) return res.status(400).json({ error: 'URL required' });
        
        // Decode URL if double-encoded
        try {
            while (url.includes('%25') || url.includes('%3A%2F%2F')) {
                const decoded = decodeURIComponent(url);
                if (decoded === url) break;
                url = decoded;
            }
        } catch (e) {}
        
        // Extract referer from the URL domain
        let urlObj;
        try {
            urlObj = new URL(url);
        } catch (e) {
            console.error('Invalid URL:', url);
            return res.status(400).json({ error: 'Invalid URL' });
        }
        const refererOverride = req.query.referer;
        const defaultReferer = (refererOverride || `${urlObj.origin}/`).trim();
        const fallbackReferer = 'https://vidfast.pro/';
        const pathHostMatch = urlObj.pathname.match(/^\/?([a-zA-Z0-9.-]+)\//);
        const pathDerivedHost = pathHostMatch ? pathHostMatch[1] : null;
        const pathReferer = pathDerivedHost ? `https://${pathDerivedHost}/` : null;
        
        // Check if this is a segment request and we have it cached
        const isSegment = url.includes('.ts') || url.includes('.m4s') || url.includes('.fmp4') || 
                         (url.includes('seg') && !url.includes('.m3u8'));
        
        if (isSegment) {
            const cached = segmentCache.get(url);
            if (cached && Date.now() - cached.timestamp < SEGMENT_CACHE_TTL) {
                cached.timestamp = Date.now(); // Refresh TTL
                res.set('Content-Type', 'video/mp2t');
                res.set('Access-Control-Allow-Origin', '*');
                res.set('X-Cache', 'HIT');
                return res.send(cached.data);
            }
        }

        const originFromDefault = (() => { try { return new URL(defaultReferer).origin; } catch { return undefined; } })();
        const originFromFallback = (() => { try { return new URL(fallbackReferer).origin; } catch { return undefined; } })();
        const originFromPath = (() => { try { return pathReferer ? new URL(pathReferer).origin : undefined; } catch { return undefined; } })();

        const commonHeaders = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9'
        };

        async function doFetch(headers) {
            return fetch(url, { headers, redirect: 'follow' });
        }

        const attempts = [
            { name: 'with-target-origin', headers: { ...commonHeaders, ...(defaultReferer ? { Referer: defaultReferer } : {}), ...(originFromDefault ? { Origin: originFromDefault } : {}) } },
            { name: 'no-ref', headers: { ...commonHeaders } },
            { name: 'with-fallback-referer', headers: { ...commonHeaders, Referer: fallbackReferer, ...(originFromFallback ? { Origin: originFromFallback } : {}) } },
            { name: 'with-path-referer', headers: { ...commonHeaders, ...(pathReferer ? { Referer: pathReferer } : {}), ...(originFromPath ? { Origin: originFromPath } : {}) } },
        ];

        let response = null;
        let usedReferer = defaultReferer;
        for (const attempt of attempts) {
            response = await doFetch(attempt.headers);
            if (response.ok || ![400,401,403].includes(response.status)) {
                if (attempt.headers.Referer) usedReferer = attempt.headers.Referer;
                break;
            }
            console.warn(`Fetch ${attempt.name} failed with ${response.status}`);
        }
        if (!usedReferer) usedReferer = defaultReferer || fallbackReferer || pathReferer;
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Proxy fetch failed:', response.status, errorText.substring(0, 500));
            res.set('Access-Control-Allow-Origin', '*');
            res.set('Access-Control-Allow-Private-Network', 'true');
            return res.status(response.status).json({ error: 'Upstream error: ' + response.statusText });
        }
        
        const contentType = response.headers.get('content-type') || 'application/octet-stream';
        
        // Handle m3u8 playlists - rewrite URLs to go through proxy
        if (url.includes('.m3u8') || contentType.includes('mpegurl') || contentType.includes('x-mpegurl')) {
            let data = await response.text();
            
            if (!data || !data.includes('#EXTM3U')) {
                console.error('Invalid m3u8 response:', data.substring(0, 200));
                return res.status(500).json({ error: 'Invalid m3u8 response' });
            }
            
            const baseUrl = url.substring(0, url.lastIndexOf('/') + 1);
            
            // Trigger background prefetch for media playlist (contains segments, not variant streams)
            if (!data.includes('#EXT-X-STREAM-INF')) {
                prefetchSegments(url, usedReferer, 0).catch(e => {
                    console.warn('Auto-prefetch error:', e.message);
                });
            }
            
            data = data.split('\n').map(line => {
                line = line.trim();
                // Rewrite URLs but not empty lines or comments
                if (line && !line.startsWith('#')) {
                    const fullUrl = (() => {
                        try { return new URL(line, url).toString(); } catch { return line.startsWith('http') ? line : baseUrl + line; }
                    })();
                    return '/api/proxy?url=' + encodeURIComponent(fullUrl) + (usedReferer ? `&referer=${encodeURIComponent(usedReferer)}` : '');
                }
                // Also rewrite URI in EXT-X-KEY lines
                if (line.startsWith('#EXT-X-KEY') && line.includes('URI="')) {
                    return line.replace(/URI="([^"]+)"/, (match, uri) => {
                        const fullUri = (() => {
                            try { return new URL(uri, url).toString(); } catch { return uri.startsWith('http') ? uri : baseUrl + uri; }
                        })();
                        const refererParam = usedReferer ? `&referer=${encodeURIComponent(usedReferer)}` : '';
                        return 'URI="/api/proxy?url=' + encodeURIComponent(fullUri) + refererParam + '"';
                    });
                }
                return line;
            }).join('\n');
            
            res.set('Content-Type', 'application/vnd.apple.mpegurl');
            res.set('Access-Control-Allow-Origin', '*');
            res.send(data);
        } else {
            // Handle binary data (ts segments, keys, etc)
            const buffer = Buffer.from(await response.arrayBuffer());
            
            // Cache segment data
            if (isSegment && buffer.length > 0) {
                segmentCache.set(url, { data: buffer, timestamp: Date.now() });
                cleanSegmentCache();
            }
            
            res.set('Content-Type', contentType);
            res.set('Access-Control-Allow-Origin', '*');
            res.set('X-Cache', 'MISS');
            res.send(buffer);
        }
    } catch (error) {
        console.error('Proxy error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

async function extractM3U8(url) {
    console.log(`Extracting m3u8 from: ${url}`);
    
    const browser = await firefox.launch({
        headless: true,
    });

    const context = await browser.newContext({
        viewport: { width: 1920, height: 1080 },
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0',
        locale: 'en-US',
    });

    const page = await context.newPage();
    let m3u8Url = null;

    page.on('response', async (response) => {
        const responseUrl = response.url();
        if (responseUrl.includes('.m3u8') && !m3u8Url) {
            m3u8Url = responseUrl;
            console.log(`Found m3u8: ${m3u8Url}`);
        }
    });

    try {
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });
        console.log('Page loaded');

        // Mouse movements
        await page.mouse.move(200, 300);
        await page.waitForTimeout(800);
        await page.mouse.move(600, 400);
        
        // Wait for FETCHING to disappear
        console.log('Waiting for page to finish fetching...');
        await page.waitForFunction(
            () => !document.body.innerText.includes('FETCHING'),
            { timeout: 120000 }
        ).catch(() => console.log('Fetch wait timed out'));

        await page.waitForTimeout(2000);

        // Wait for button
        const buttonLocator = page.locator('div.MuiBox-root.mui-oaxqi3').locator('button').nth(0);
        await buttonLocator.waitFor({ state: 'visible', timeout: 30000 });
        console.log('Button found');

        // Click sequence
        for (let attempt = 0; attempt < 3 && !m3u8Url; attempt++) {
            console.log(`Click attempt ${attempt + 1}`);
            
            const pagesBefore = context.pages().length;
            
            await page.waitForTimeout(500);
            await buttonLocator.click();
            await page.waitForTimeout(2500);

            // Close popup tabs
            const pagesAfter = context.pages();
            if (pagesAfter.length > pagesBefore) {
                for (let i = 1; i < pagesAfter.length; i++) {
                    try {
                        await pagesAfter[i].close();
                        console.log('Closed popup');
                    } catch (e) {}
                }
            }

            await page.waitForTimeout(1500);
        }

        if (!m3u8Url) {
            console.log('Waiting extra for m3u8...');
            await page.waitForTimeout(10000);
        }

    } catch (error) {
        console.error('Error:', error.message);
    } finally {
        await browser.close();
    }

    return m3u8Url;
}

app.post('/api/extract', async (req, res) => {
    const { url } = req.body;
    
    if (!url || !url.startsWith('https://vidfast.pro/')) {
        return res.status(400).json({ error: 'Invalid URL' });
    }

    // Check cache first
    const cached = getCached(url);
    if (cached) {
        return res.json({ success: true, m3u8Url: cached, cached: true });
    }

    try {
        const m3u8Url = await extractM3U8(url);
        
        if (m3u8Url) {
            setCache(url, m3u8Url);
            res.json({ success: true, m3u8Url });
        } else {
            res.status(404).json({ error: 'Could not find m3u8 stream' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
