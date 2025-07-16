// ==UserScript==
// @name         Bypass devtool-detection
// @namespace    http://tampermonkey.net/
// @version      0.5
// @description  Bypasses devtool detection
// @author       itzzzme
// @match        *://*/*
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    // --- Override Window Dimension Properties ---
    Object.defineProperty(window, 'outerWidth', {
        get: function() {
            return window.innerWidth;
        }
    });
    Object.defineProperty(window, 'outerHeight', {
        get: function() {
            return window.innerHeight;
        }
    });

    const originalSetInterval = window.setInterval;
    window.setInterval = function(callback, delay) {
        if (typeof callback === 'function' && typeof delay === 'number' && delay <= 2000) {
            console.log(`Blocked setInterval with delay ${delay}ms`);
            return originalSetInterval(function() {}, delay); // No-op callback
        }
        return originalSetInterval.apply(this, arguments);
    };

    const originalSetTimeout = window.setTimeout;
    window.setTimeout = function(callback, delay) {
        if (typeof callback === 'function' && typeof delay === 'number' && delay <= 2000) {
            console.log(`Blocked setTimeout with delay ${delay}ms`);
            return originalSetTimeout(function() {}, delay);
        }
        return originalSetTimeout.apply(this, arguments);
    };

    // --- Block or override resize events ---
    const originalAddEventListener = window.addEventListener;
    window.addEventListener = function(type, listener, options) {
        if (type === 'resize') {
            console.log('Blocked resize event listener');
            return;
        }
        return originalAddEventListener.apply(this, arguments);
    };
    window.onresize = function() {
        console.log('Blocked onresize event');
    };

    // --- Prevent Forced Reloads ---
    window.location.reload = function() {
        console.log('Reload attempt blocked');
    };


    const originalConsole = window.console;
    window.console = {
        log: function() {},
        warn: function() {},
        error: function() {},
        table: function() {},
        clear: function() {},
        ...originalConsole
    };

    const originalRegExpToString = RegExp.prototype.toString;
    RegExp.prototype.toString = function() {
        try {
            return originalRegExpToString.call(this);
        } catch (e) {
            return '';
        }
    };

    const originalDefineProperty = Object.defineProperty;
    Object.defineProperty = function(obj, prop, descriptor) {
        if (prop === 'id' && obj instanceof HTMLElement && descriptor.get) {
            console.log('Blocked suspicious id getter on element');
            return originalDefineProperty(obj, prop, {
                value: 'bypassed-id'
            });
        }
        return originalDefineProperty.apply(this, arguments);
    };

    console.log('Bypass for disable-devtool initialized');
})();