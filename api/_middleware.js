// api/_middleware.js - Vercel Middleware for rate limiting
import { NextResponse } from 'next/server';

// Simple in-memory rate limiting (for production, use Redis)
const rateLimit = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 60; // 60 requests per minute

export function middleware(request) {
  const ip = request.ip || request.headers.get('x-forwarded-for') || 'unknown';
  const now = Date.now();
  
  const requests = rateLimit.get(ip) || [];
  const windowStart = now - RATE_LIMIT_WINDOW;
  
  // Filter requests within window
  const recentRequests = requests.filter(time => time > windowStart);
  
  if (recentRequests.length >= RATE_LIMIT_MAX) {
    return new NextResponse(
      JSON.stringify({ 
        error: 'Too Many Requests',
        retryAfter: 60 
      }),
      { 
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': '60'
        }
      }
    );
  }
  
  // Add current request
  recentRequests.push(now);
  rateLimit.set(ip, recentRequests);
  
  // Clean up old entries occasionally
  if (Math.random() < 0.01) { // 1% chance
    for (const [key, times] of rateLimit.entries()) {
      const recent = times.filter(time => time > now - RATE_LIMIT_WINDOW * 2);
      if (recent.length === 0) {
        rateLimit.delete(key);
      }
    }
  }
  
  return NextResponse.next();
}

export const config = {
  matcher: '/api/:path*'
};