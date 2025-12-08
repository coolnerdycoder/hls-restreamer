// local-dev-server.js
const http = require('http');
const url = require('url');
const fs = require('fs');
const path = require('path');

// Load environment variables
try {
  require('dotenv').config();
} catch (e) {
  console.log('dotenv not available');
}

// Import your Vercel function
const handler = require('./api/playlist');

const PORT = 3000;

const server = http.createServer(async (req, res) => {
  try {
    console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
    
    // Parse URL
    const parsedUrl = url.parse(req.url, true);
    
    // Create a mock request object similar to Vercel's
    const mockReq = {
      method: req.method,
      url: req.url,
      query: parsedUrl.query,
      headers: req.headers,
      connection: {
        remoteAddress: req.connection.remoteAddress
      }
    };
    
    // Create a mock response object
    const mockRes = {
      _headers: {},
      _status: 200,
      _body: '',
      
      setHeader: function(key, value) {
        this._headers[key] = value;
        res.setHeader(key, value);
      },
      
      status: function(code) {
        this._status = code;
        return this;
      },
      
      send: function(body) {
        this._body = body;
        res.statusCode = this._status;
        res.end(body);
      },
      
      json: function(obj) {
        this.setHeader('Content-Type', 'application/json');
        this.send(JSON.stringify(obj));
      },
      
      end: function(body) {
        if (body) this._body = body;
        res.statusCode = this._status;
        res.end(this._body || body);
      }
    };
    
    // Call your Vercel function handler
    await handler(mockReq, mockRes);
    
  } catch (error) {
    console.error('Server error:', error);
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ 
      error: 'Internal Server Error',
      message: error.message 
    }));
  }
});

server.listen(PORT, () => {
  console.log(`🚀 Local development server running at http://localhost:${PORT}`);
  console.log(`📺 Test playlist: http://localhost:${PORT}/api/playlist?id=test123`);
  console.log(`🏥 Health check: http://localhost:${PORT}/api/playlist/health`);
  console.log(`Press Ctrl+C to stop\n`);
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down server...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});