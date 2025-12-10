// api/playlist.js
// Vercel / Node serverless endpoint — multi-segment HLS restreamer

// Load environment variables
if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
  try {
    require('dotenv').config();
  } catch (e) {
    // dotenv not available, use Vercel's env vars
  }
}

// =============== CONFIGURATION ===============
const ERROR_TS_URL = process.env.ERROR_TS_URL
const SOURCE_BASE_URL = process.env.SOURCE_BASE_URL

// Block lists
const BLOCKED_HOSTS = process.env.BLOCKED_HOSTS
const BLOCKED_PATTERNS = process.env.BLOCKED_PATTERNS

// Tunables (with environment variable fallbacks)
const TIMEOUT_MS = parseInt(process.env.TIMEOUT_MS) || 8000; // Increased for redirects
const MAX_SEGMENTS = parseInt(process.env.MAX_SEGMENTS) || 10;
const MIN_SEGMENTS = parseInt(process.env.MIN_SEGMENTS) || 3;
const MAX_CONSECUTIVE_MISSES = parseInt(process.env.MAX_CONSECUTIVE_MISSES) || 4;
const RANGE_PROBE = 'bytes=0-0';
const TARGET_DURATION = 10;
const MAX_RESPONSE_SIZE = 10 * 1024 * 1024; // 10MB limit
const FUNCTION_TIMEOUT = 10000; // Vercel limits

// Cache for resolved segments (5-second TTL)
const segmentCache = new Map();
const CACHE_TTL_MS = 5000;

// Debug mode
const DEBUG = process.env.NODE_ENV === 'development' || process.env.DEBUG === 'true';

// =============== INITIALIZATION ===============
// Use global fetch if available (Node 18+), otherwise fall back to node-fetch
let fetchFn = global.fetch;
if (!fetchFn) {
  try {
    fetchFn = require('node-fetch');
  } catch (e) {
    throw new Error('No fetch available. Please use Node 18+ or install node-fetch.');
  }
}

const { URL } = require('url');

// =============== LOGGING ===============
function log(level, message, data = {}) {
  if (!DEBUG && level === 'DEBUG') return;
  
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...data
  };
  
  if (DEBUG) {
    console.log(JSON.stringify(entry));
  } else if (level === 'ERROR' || level === 'WARN') {
    console.log(JSON.stringify(entry));
  }
}

// =============== MAIN HANDLER ===============
module.exports = async (req, res) => {
  const startTime = Date.now();
  
  try {
    // Handle OPTIONS for CORS
    if (req.method === 'OPTIONS') {
      addCorsHeaders(res);
      return res.status(200).end();
    }
    
    // Health check endpoint
    if (req.url.includes('/health')) {
      return res.status(200).json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
      });
    }
    
    // Stats endpoint - MOVED INSIDE HANDLER
    if (req.url === '/api/playlist/stats' || req.url.includes('/stats')) {
      return res.status(200).json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        cacheSize: segmentCache.size,
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        config: {
          sourceBaseUrl: SOURCE_BASE_URL ? '✓ Set' : '✗ Missing',
          errorTsUrl: ERROR_TS_URL ? '✓ Set' : '✗ Missing',
          timeoutMs: TIMEOUT_MS,
          maxSegments: MAX_SEGMENTS,
          debug: DEBUG
        }
      });
    }
    
    // Validate request
    if (req.method !== 'GET') {
      return serveError(res, ERROR_TS_URL, 'Method not allowed', 405);
    }
    
    const id = req.query.id;
    if (!id) {
      return serveError(res, ERROR_TS_URL, 'Missing channel ID (id query param)', 400);
    }
    
    // Validate channel ID format
    if (!validateChannelId(id)) {
      log('WARN', 'Invalid channel ID format', { id });
      return serveError(res, ERROR_TS_URL, 'Invalid channel ID format', 400);
    }
    
    // CRITICAL: Validate that environment variables are set
    if (!SOURCE_BASE_URL) {
      log('ERROR', 'SOURCE_BASE_URL environment variable is not set');
      return res.status(500).json({
        error: 'Server configuration error',
        message: 'SOURCE_BASE_URL environment variable is required'
      });
    }
    
    // Add CORS headers for actual response
    addCorsHeaders(res);
    
    log('INFO', 'Processing request', { id, url: req.url });
    
    // Process the playlist request
    const result = await processPlaylistRequest(id);
    
    // Log successful request
    const duration = Date.now() - startTime;
    log('INFO', 'Playlist generated successfully', { 
      id, 
      durationMs: duration,
      segments: result.segments?.length || 0,
      firstSegment: truncateUrl(result.segments[0], 100)
    });
    
    // Serve the playlist
    return serveM3u8(res, result.segments, { 
      targetDuration: TARGET_DURATION, 
      mediaSequence: result.mediaSequence || 0 
    });
    
  } catch (err) {
    const duration = Date.now() - startTime;
    
    if (err.message.includes('timeout') || err.message.includes('Timeout')) {
      log('ERROR', 'Function timeout', { durationMs: duration });
      return serveError(res, ERROR_TS_URL, 'Request timeout', 408);
    }
    
    log('ERROR', 'Unexpected handler error', { 
      error: err.message, 
      durationMs: duration,
      stack: DEBUG ? err.stack : undefined
    });
    
    return serveError(res, ERROR_TS_URL, `Server error: ${err.message}`, 500);
  }
};

// =============== CORE LOGIC ===============
async function processPlaylistRequest(id) {
  // CRITICAL: Check SOURCE_BASE_URL again
  if (!SOURCE_BASE_URL) {
    throw new Error('SOURCE_BASE_URL environment variable is not configured');
  }
  
  const entryUrl = `${SOURCE_BASE_URL}/${id}.ts`;
  
  log('DEBUG', 'Starting playlist generation', { entryUrl });
  
  // 1) Resolve initial redirect with token preservation
  const initial = await resolveUrlWithRetry(entryUrl, { 
    probeRange: true, 
    followToFinal: true,
    preserveQueryParams: true // CRITICAL: Preserve token params
  }, 2);
  
  if (!initial.ok) {
    log('ERROR', 'Initial resolve failed', { error: initial.error });
    throw new Error(`Initial resolve failed: ${initial.error}`);
  }

  const firstFinal = initial.finalUrl;
  log('DEBUG', 'Initial redirect resolved', { 
    original: truncateUrl(entryUrl, 80),
    final: truncateUrl(firstFinal, 100)
  });

  if (isBlocked(firstFinal)) {
    log('ERROR', 'Blocked URL detected', { url: firstFinal });
    throw new Error(`Blocked initial URL: ${firstFinal}`);
  }

  // 2) Detect numeric sequence pattern with query parameter preservation
  const detected = detectNumericSequenceWithParams(firstFinal);
  
  let segments = [];
  let detectionMethod = 'none';

  if (detected) {
    detectionMethod = 'numeric-sequence';
    log('DEBUG', 'Numeric sequence detected', { 
      template: detected.template,
      startNum: detected.startNum,
      pad: detected.pad,
      hasQueryParams: detected.hasQueryParams
    });
    
    // Try to fetch segments concurrently
    const candidateUrls = [];
    let { template, startNum, pad, queryParams } = detected;
    
    // Generate candidate URLs for concurrent checking
    for (let i = 0; i < MAX_SEGMENTS * 2; i++) {
      const seq = startNum + i;
      const candidatePath = template.replace('%%SEQ%%', padNumber(seq, pad));
      
      // Re-add query parameters if they exist
      let candidateUrl = candidatePath;
      if (queryParams) {
        candidateUrl += queryParams;
      }
      
      const fullUrl = makeAbsoluteUrl(candidateUrl, firstFinal);
      candidateUrls.push(fullUrl);
    }
    
    // Check candidate segments concurrently with limits
    segments = await checkSegmentsConcurrently(
      candidateUrls, 
      MAX_SEGMENTS,
      MAX_CONSECUTIVE_MISSES
    );
    
    log('DEBUG', 'Sequence detection results', { 
      candidates: candidateUrls.length,
      valid: segments.length,
      firstFew: segments.slice(0, 3).map(url => truncateUrl(url, 80))
    });
  }

  // 3) Fallback heuristics if detection failed or produced too few segments
  if (segments.length < MIN_SEGMENTS) {
    detectionMethod = detectionMethod === 'none' ? 'fallback' : 'mixed';
    
    // Start with the initial final URL (best available)
    segments = [firstFinal];
    log('DEBUG', 'Using fallback detection', { currentSegments: segments.length });

    // Generate guessed neighbors WITH query parameters
    const guesses = guessNearbyPathsWithParams(firstFinal, MAX_SEGMENTS * 3);
    
    // Check guesses concurrently
    const guessedSegments = await checkSegmentsConcurrently(
      guesses, 
      MAX_SEGMENTS - 1,
      MAX_CONSECUTIVE_MISSES
    );
    
    // Add unique valid segments
    for (const seg of guessedSegments) {
      if (segments.length >= MAX_SEGMENTS) break;
      if (!segments.includes(seg)) segments.push(seg);
    }
    
    log('DEBUG', 'Fallback results', { 
      guesses: guesses.length,
      valid: guessedSegments.length,
      total: segments.length
    });
  }

  // 4) Final validation
  if (!segments || segments.length === 0) {
    throw new Error('Could not assemble any segment URLs');
  }

  if (segments.length < MIN_SEGMENTS) {
    log('WARN', 'Low segment count', { 
      found: segments.length, 
      minRequired: MIN_SEGMENTS,
      detectionMethod,
      firstSegment: truncateUrl(segments[0], 100)
    });
  }

  // 5) Calculate media sequence (simple incrementing counter)
  const mediaSequence = Math.floor(Date.now() / 1000);

  return {
    segments,
    mediaSequence,
    sourceCount: segments.length,
    detectionMethod
  };
}

// =============== HELPER FUNCTIONS ===============
function serveError(res, errorUrl, reason, statusCode = 500) {
  log('ERROR', reason);
  
  res.setHeader('Content-Type', 'application/json');
  addCorsHeaders(res);
  
  if (statusCode === 429) {
    return res.status(statusCode).json({ error: reason });
  }
  
  // For playlist errors, still return a valid HLS playlist with error segment
  return serveM3u8(res, [errorUrl], { 
    targetDuration: TARGET_DURATION, 
    mediaSequence: 0,
    isError: true
  });
}

function serveM3u8(res, segments, opts = {}) {
  const targetDuration = opts.targetDuration || TARGET_DURATION;
  const mediaSequence = opts.mediaSequence || 0;
  const isError = opts.isError || false;

  res.setHeader('Content-Type', 'application/vnd.apple.mpegurl');
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  
  // Add CORS headers for web player compatibility
  addCorsHeaders(res);

  const lines = [
    '#EXTM3U',
    '#EXT-X-VERSION:3',
    `#EXT-X-TARGETDURATION:${targetDuration}`,
    `#EXT-X-MEDIA-SEQUENCE:${mediaSequence}`,
  ];

  // Add error tag if this is an error playlist
  if (isError) {
    lines.push('#EXT-X-PLAYLIST-TYPE:EVENT');
  }

  for (const seg of segments) {
    lines.push(`#EXTINF:${targetDuration}.0,`);
    lines.push(seg);
  }

  // Don't add ENDLIST for live streams
  const body = lines.join('\n');
  
  // Check response size
  const bodySize = Buffer.byteLength(body, 'utf8');
  if (bodySize > MAX_RESPONSE_SIZE) {
    log('WARN', 'Response too large, truncating', { size: bodySize, max: MAX_RESPONSE_SIZE });
    // Return at least first segment
    const truncatedBody = lines.slice(0, 6).join('\n') + '\n';
    return res.status(200).send(truncatedBody);
  }

  res.status(200).send(body);
}

function addCorsHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Range');
  res.setHeader('Access-Control-Expose-Headers', 'Content-Length, Content-Range');
}

// =============== IMPROVED URL RESOLUTION WITH TOKEN PRESERVATION ===============
async function resolveUrl(url, opts = {}) {
  const probeRange = opts.probeRange === true;
  const followToFinal = opts.followToFinal === true;
  const preserveQueryParams = opts.preserveQueryParams === true;

  // Check cache first
  const cacheKey = `${url}|${probeRange}|${followToFinal}|${preserveQueryParams}`;
  const cached = segmentCache.get(cacheKey);
  
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    log('DEBUG', 'Cache hit', { url: truncateUrl(url) });
    return cached.result;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    // Browser-like headers to avoid blocking
    const headers = {
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
      'Accept-Encoding': 'gzip, deflate, br',
      'Accept-Language': 'en-US,en;q=0.9',
      'Connection': 'keep-alive',
      'Upgrade-Insecure-Requests': '1',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Cache-Control': 'no-cache',
      'Pragma': 'no-cache'
    };

    if (probeRange) {
      headers['Range'] = RANGE_PROBE;
    }

    log('DEBUG', 'Resolving URL', { 
      url: truncateUrl(url), 
      probeRange, 
      followToFinal 
    });

    // Use manual redirect to inspect Location header
    const resp = await fetchFn(url, {
      method: 'GET',
      headers,
      redirect: 'manual', // Don't follow automatically
      signal: controller.signal,
    });

    log('DEBUG', 'Response received', { 
      url: truncateUrl(url),
      status: resp.status,
      redirected: resp.redirected
    });

    // Handle redirect with query parameter preservation
    if (resp.status >= 300 && resp.status < 400) {
      const location = resp.headers.get('location');
      log('DEBUG', 'Redirect detected', { 
        status: resp.status, 
        location: truncateUrl(location, 120)
      });

      if (!location) {
        const result = { ok: false, finalUrl: null, error: `Redirected (${resp.status}) without location header` };
        cacheResult(cacheKey, result);
        return result;
      }

      // Build absolute URL with query parameter preservation
      const redirectUrl = makeAbsoluteUrl(location, url);
      log('DEBUG', 'Redirect URL built', { 
        original: truncateUrl(url),
        redirect: truncateUrl(redirectUrl, 120)
      });

      // If we need to follow to final URL
      if (followToFinal) {
        log('DEBUG', 'Following redirect to final URL');
        
        // For the final follow, use 'follow' redirect mode to get the actual segment
        const finalResp = await fetchFn(redirectUrl, {
          method: 'GET',
          headers: {
            ...headers,
            'Range': probeRange ? RANGE_PROBE : undefined
          },
          redirect: 'follow', // Follow any further redirects
          signal: controller.signal,
        });

        const finalUrl = finalResp.url || redirectUrl;
        const result = { ok: true, finalUrl: finalUrl, error: null };
        
        log('DEBUG', 'Final URL resolved', { 
          final: truncateUrl(finalUrl, 120),
          status: finalResp.status
        });
        
        cacheResult(cacheKey, result);
        return result;
      }

      const result = { ok: true, finalUrl: redirectUrl, error: null };
      cacheResult(cacheKey, result);
      return result;
    }

    // If status is OK (200 or 206)
    if (resp.status === 200 || resp.status === 206) {
      const finalUrl = resp.url || url;
      const result = { ok: true, finalUrl: finalUrl, error: null };
      cacheResult(cacheKey, result);
      return result;
    }

    const result = { ok: false, finalUrl: null, error: `Unexpected status ${resp.status}` };
    cacheResult(cacheKey, result);
    return result;

  } catch (err) {
    let errorMsg;
    if (err && err.name === 'AbortError') {
      errorMsg = `Timeout after ${TIMEOUT_MS}ms`;
    } else {
      errorMsg = err.message || String(err);
    }
    
    log('DEBUG', 'URL resolution error', { 
      url: truncateUrl(url), 
      error: errorMsg 
    });
    
    const result = { ok: false, finalUrl: null, error: errorMsg };
    cacheResult(cacheKey, result);
    return result;
  } finally {
    clearTimeout(timer);
  }
}

async function resolveUrlWithRetry(url, opts = {}, maxRetries = 2) {
  for (let i = 0; i <= maxRetries; i++) {
    const result = await resolveUrl(url, opts);
    
    if (result.ok) {
      if (i > 0) {
        log('DEBUG', 'Retry successful', { 
          url: truncateUrl(url), 
          attempt: i + 1 
        });
      }
      return result;
    }
    
    if (i < maxRetries) {
      const delay = Math.min(1000 * Math.pow(2, i), 5000);
      log('DEBUG', 'Retrying URL', { 
        url: truncateUrl(url), 
        attempt: i + 1, 
        delay,
        error: result.error 
      });
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  
  return { ok: false, finalUrl: null, error: `All ${maxRetries} retries failed` };
}

async function checkSegmentsConcurrently(candidateUrls, maxToFind, maxConsecutiveMisses) {
  const validSegments = [];
  let consecutiveMisses = 0;
  
  // Process in batches for efficiency
  const batchSize = 5;
  
  for (let i = 0; i < candidateUrls.length; i += batchSize) {
    const batch = candidateUrls.slice(i, i + batchSize);
    
    const batchChecks = await Promise.allSettled(
      batch.map(url => resolveUrlWithRetry(url, { 
        probeRange: true, 
        followToFinal: true,
        preserveQueryParams: true 
      }, 1))
    );
    
    for (const result of batchChecks) {
      if (validSegments.length >= maxToFind) break;
      
      if (result.status === 'fulfilled' && 
          result.value.ok && 
          result.value.finalUrl && 
          !isBlocked(result.value.finalUrl)) {
        
        // Avoid duplicates
        if (!validSegments.includes(result.value.finalUrl)) {
          validSegments.push(result.value.finalUrl);
          consecutiveMisses = 0;
        }
      } else {
        consecutiveMisses++;
      }
      
      if (consecutiveMisses >= maxConsecutiveMisses) {
        log('DEBUG', 'Max consecutive misses reached', { misses: consecutiveMisses });
        return validSegments;
      }
    }
    
    if (validSegments.length >= maxToFind) break;
  }
  
  return validSegments;
}

// =============== IMPROVED SEQUENCE DETECTION WITH QUERY PARAMS ===============
function detectNumericSequenceWithParams(finalUrl) {
  try {
    const u = new URL(finalUrl);
    const pathname = u.pathname;
    const search = u.search; // Includes ? and query params
    const hash = u.hash;
    
    // Match last number before extension
    const m = pathname.match(/(.*?)(\d+)(\.\w+)$/);
    if (!m) return null;
    
    const prefix = m[1];
    const numberStr = m[2];
    const ext = m[3];
    const pad = numberStr.length;
    const startNum = parseInt(numberStr, 10);
    
    if (isNaN(startNum)) return null;
    
    // Include query parameters and hash in template
    const template = prefix + '%%SEQ%%' + ext;
    const hasQueryParams = search || hash;
    
    log('DEBUG', 'Sequence detection details', {
      pathname,
      prefix,
      numberStr,
      ext,
      search,
      hash,
      hasQueryParams
    });
    
    return { 
      template, 
      startNum, 
      pad, 
      queryParams: search + hash, // Preserve both query and fragment
      hasQueryParams: !!hasQueryParams
    };
  } catch (e) {
    log('DEBUG', 'Sequence detection error', { error: e.message });
    return null;
  }
}

function makeAbsoluteUrl(candidate, base) {
  try {
    // If candidate already has protocol
    if (/^https?:\/\//i.test(candidate)) {
      return candidate;
    }
    
    // Use URL constructor which properly handles query parameters
    const resolved = new URL(candidate, base);
    return resolved.toString();
    
  } catch (e) {
    log('DEBUG', 'makeAbsoluteUrl fallback', { 
      candidate, 
      base: truncateUrl(base),
      error: e.message 
    });
    
    try {
      const baseUrl = new URL(base);
      
      // If candidate starts with /
      if (candidate.startsWith('/')) {
        // Parse the path and query separately
        const [path, ...queryParts] = candidate.split('?');
        const query = queryParts.length > 0 ? '?' + queryParts.join('?') : '';
        return baseUrl.origin + path + query;
      }
      
      // Relative path
      const dir = baseUrl.pathname.endsWith('/') 
        ? baseUrl.pathname 
        : baseUrl.pathname.replace(/\/[^/]*$/, '/');
      
      const [path, ...queryParts] = candidate.split('?');
      const query = queryParts.length > 0 ? '?' + queryParts.join('?') : '';
      
      return baseUrl.origin + dir + path + query;
      
    } catch (_) {
      return candidate;
    }
  }
}

function isBlocked(urlStr) {
  try {
    const u = new URL(urlStr);
    const hostname = u.hostname.toLowerCase();
    
    for (const host of BLOCKED_HOSTS) {
      const h = host.toLowerCase();
      if (hostname === h || hostname.endsWith('.' + h)) return true;
    }
    
    for (const patt of BLOCKED_PATTERNS) {
      if (urlStr.includes(patt)) return true;
    }
    
    return false;
  } catch (e) {
    return true;
  }
}

function guessNearbyPathsWithParams(finalUrl, limit = 5) {
  const guesses = new Set();
  
  try {
    const u = new URL(finalUrl);
    const pathname = u.pathname;
    const search = u.search; // Query parameters
    const hash = u.hash; // Fragment
    const extMatch = pathname.match(/(\.\w+)$/);
    const ext = extMatch ? extMatch[1] : '';
    const base = ext ? pathname.slice(0, -ext.length) : pathname;
    
    // Combine query params and hash
    const querySuffix = search + hash;

    for (let i = 1; i <= limit; i++) {
      // Try different numbering patterns WITH query params
      guesses.add(makeAbsoluteUrl(`${base}-${i}${ext}${querySuffix}`, finalUrl));
      guesses.add(makeAbsoluteUrl(`${base}_${i}${ext}${querySuffix}`, finalUrl));
      guesses.add(makeAbsoluteUrl(`${base}${i}${ext}${querySuffix}`, finalUrl));
      
      // Try with zero-padding for common patterns
      if (i < 100) {
        const padded = String(i).padStart(2, '0');
        guesses.add(makeAbsoluteUrl(`${base}-${padded}${ext}${querySuffix}`, finalUrl));
        guesses.add(makeAbsoluteUrl(`${base}_${padded}${ext}${querySuffix}`, finalUrl));
        guesses.add(makeAbsoluteUrl(`${base}${padded}${ext}${querySuffix}`, finalUrl));
      }
      
      // Also try without query params (some servers might work without them)
      guesses.add(makeAbsoluteUrl(`${base}-${i}${ext}`, finalUrl));
      guesses.add(makeAbsoluteUrl(`${base}_${i}${ext}`, finalUrl));
      guesses.add(makeAbsoluteUrl(`${base}${i}${ext}`, finalUrl));
    }
    
    // Try incrementing/decrementing the original number if we found one
    const numberMatch = pathname.match(/(\d+)(\.\w+)$/);
    if (numberMatch) {
      const numberStr = numberMatch[1];
      const ext = numberMatch[2];
      const base = pathname.slice(0, -(numberStr.length + ext.length));
      const originalNum = parseInt(numberStr, 10);
      
      for (let offset = 1; offset <= 5; offset++) {
        const nextNum = originalNum + offset;
        const prevNum = originalNum - offset;
        
        // Preserve zero padding
        const nextNumStr = padNumber(nextNum, numberStr.length);
        const prevNumStr = padNumber(prevNum > 0 ? prevNum : 0, numberStr.length);
        
        guesses.add(makeAbsoluteUrl(`${base}${nextNumStr}${ext}${querySuffix}`, finalUrl));
        if (prevNum > 0) {
          guesses.add(makeAbsoluteUrl(`${base}${prevNumStr}${ext}${querySuffix}`, finalUrl));
        }
      }
    }
    
  } catch (e) {
    log('DEBUG', 'Error generating nearby paths', { error: e.message });
  }
  
  return Array.from(guesses);
}

function padNumber(n, width) {
  const s = String(n);
  if (s.length >= width) return s;
  return '0'.repeat(width - s.length) + s;
}

function validateChannelId(id) {
  // Allow alphanumeric, dots, dashes, underscores
  // Limit length to prevent abuse
  return /^[a-zA-Z0-9._-]+$/.test(id) && id.length <= 100;
}

function cacheResult(key, result) {
  segmentCache.set(key, { 
    result, 
    timestamp: Date.now() 
  });
  
  // Clean old cache entries
  if (segmentCache.size > 200) {
    const cutoff = Date.now() - CACHE_TTL_MS * 2;
    for (const [cacheKey, value] of segmentCache.entries()) {
      if (value.timestamp < cutoff) segmentCache.delete(cacheKey);
    }
  }
}

function truncateUrl(url, maxLength = 50) {
  if (!url || url.length <= maxLength) return url;
  return url.substring(0, maxLength) + '...';
}