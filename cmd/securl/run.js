#!/usr/bin/env node
'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const DEFAULT_PUBLIC_PORT = 3000;
const SHUTDOWN_TIMEOUT_MS = 10_000;
const BINARY_PATH = path.resolve(
    process.env.SECURL_BINARY_PATH || path.join(__dirname, 'securl')
);
const SOCKET_PATH = path.join(os.tmpdir(), `securl_${process.pid}.sock`);

let goProcess = null;
let proxyServer = null;
let shuttingDown = false;
let requestedExitCode = 0;
let shutdownTimer = null;

const unixAgent = new http.Agent({ keepAlive: true });

function publicPort() {
    const configured = process.env.PORT;
    if (configured === undefined || configured === '') {
        return DEFAULT_PUBLIC_PORT;
    }
    if (!/^\d+$/.test(configured)) {
        throw new Error(`PORT must be an integer, received ${JSON.stringify(configured)}`);
    }
    const port = Number(configured);
    if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) {
        throw new Error(`PORT must be between 0 and 65535, received ${configured}`);
    }
    return port;
}

function removeSocket() {
    try {
        fs.unlinkSync(SOCKET_PATH);
    } catch (error) {
        if (error.code !== 'ENOENT') {
            console.error(`[Proxy] Failed to remove Unix socket ${SOCKET_PATH}:`, error);
        }
    }
}

function exitProcess(code) {
    if (shutdownTimer !== null) {
        clearTimeout(shutdownTimer);
        shutdownTimer = null;
    }
    unixAgent.destroy();
    removeSocket();
    process.exit(code);
}

function shutdown(code = 0) {
    if (shuttingDown) {
        return;
    }
    shuttingDown = true;
    requestedExitCode = code;

    if (proxyServer !== null) {
        proxyServer.close();
    }

    if (goProcess === null || goProcess.exitCode !== null || goProcess.signalCode !== null) {
        exitProcess(requestedExitCode);
        return;
    }

    goProcess.kill('SIGTERM');
    shutdownTimer = setTimeout(() => {
        console.error('[Proxy] SecURL did not stop before the shutdown deadline; sending SIGKILL');
        goProcess.kill('SIGKILL');
        exitProcess(requestedExitCode || 1);
    }, SHUTDOWN_TIMEOUT_MS);
    shutdownTimer.unref();
}

function sendProxyError(response, error) {
    if (response.destroyed) {
        return;
    }
    if (response.headersSent) {
        response.destroy(error);
        return;
    }

    const initializing = error.code === 'ENOENT' || error.code === 'ECONNREFUSED';
    response.writeHead(initializing ? 503 : 502, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store'
    });
    response.end(initializing ? 'Service initializing\n' : 'Bad gateway\n');
}

function proxyRequest(request, response) {
    if (shuttingDown) {
        response.writeHead(503, {
            'Content-Type': 'text/plain; charset=utf-8',
            'Cache-Control': 'no-store',
            'Connection': 'close'
        });
        response.end('Service shutting down\n');
        return;
    }

    const upstream = http.request({
        socketPath: SOCKET_PATH,
        path: request.url,
        method: request.method,
        headers: request.headers,
        agent: unixAgent
    }, (upstreamResponse) => {
        response.writeHead(upstreamResponse.statusCode || 502, upstreamResponse.headers);
        upstreamResponse.pipe(response);
        upstreamResponse.on('error', (error) => response.destroy(error));
    });

    upstream.on('error', (error) => {
        console.error(`[Proxy] Upstream request failed: ${error.message}`);
        sendProxyError(response, error);
    });
    request.on('aborted', () => upstream.destroy());
    response.on('close', () => {
        if (!response.writableEnded) {
            upstream.destroy();
        }
    });
    request.pipe(upstream);
}

function startGoProcess(port) {
    const environment = {
        ...process.env,
        SECURL_HTTP_ADDR: `unix:${SOCKET_PATH}`,
        SECURL_EXIT_ON_STDIN_EOF: 'true'
    };
    if (environment.SECURL_PUBLIC_ORIGINS === undefined) {
        environment.SECURL_PUBLIC_ORIGINS = `http://localhost:${port}`;
    }

    goProcess = spawn(BINARY_PATH, [], {
        env: environment,
        stdio: ['pipe', 'inherit', 'inherit']
    });

    goProcess.once('error', (error) => {
        console.error(`[Proxy] Failed to start SecURL from ${BINARY_PATH}:`, error);
        shutdown(1);
    });
    goProcess.once('exit', (code, signal) => {
        const expected = shuttingDown;
        const detail = signal === null ? `code ${code}` : `signal ${signal}`;
        if (!expected) {
            console.error(`[Proxy] SecURL exited unexpectedly with ${detail}`);
            shuttingDown = true;
            requestedExitCode = code === null || code === 0 ? 1 : code;
            if (proxyServer !== null) {
                proxyServer.close();
            }
        }
        exitProcess(requestedExitCode);
    });
}

function startProxyServer() {
    proxyServer = http.createServer(proxyRequest);
    proxyServer.once('error', (error) => {
        console.error('[Proxy] Public HTTP server failed:', error);
        shutdown(1);
    });
    proxyServer.listen(publicPort(), () => {
        const address = proxyServer.address();
        const port = typeof address === 'object' && address !== null ? address.port : publicPort();
        startGoProcess(port);
        console.log(`[Proxy] Public server listening on port ${port}`);
        console.log(`[Proxy] Forwarding requests to Unix socket ${SOCKET_PATH}`);
    });
}

process.once('SIGINT', () => shutdown(0));
process.once('SIGTERM', () => shutdown(0));
process.once('uncaughtException', (error) => {
    console.error('[Proxy] Uncaught exception:', error);
    shutdown(1);
});
process.once('unhandledRejection', (reason) => {
    console.error('[Proxy] Unhandled rejection:', reason);
    shutdown(1);
});
process.once('exit', removeSocket);

try {
    fs.accessSync(BINARY_PATH, fs.constants.X_OK);
    removeSocket();
    startProxyServer();
} catch (error) {
    console.error('[Proxy] Startup failed:', error);
    shutdown(1);
}
