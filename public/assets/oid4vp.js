(function () {
    'use strict';

    // Read configuration from data attributes (CSP-safe, no inline script)
    var appEl = document.getElementById('oid4vp-app');
    if (!appEl) {
        console.error('OID4VP: Missing #oid4vp-app element');
        return;
    }

    var config = {
        openidUri: appEl.getAttribute('data-openid-uri'),
        sessionId: appEl.getAttribute('data-session-id'),
        statusUrl: appEl.getAttribute('data-status-url'),
        qrpageUrl: appEl.getAttribute('data-qrpage-url'),
        authState: appEl.getAttribute('data-auth-state'),
        timeout:   parseInt(appEl.getAttribute('data-timeout'), 10) || 300
    };

    if (!config.openidUri || !config.statusUrl) {
        console.error('OID4VP: Missing required data attributes');
        return;
    }

    var pollInterval = null;
    var timerInterval = null;
    var startTime = Date.now();
    var timeoutMs = config.timeout * 1000;

    // Detect mobile user-agent
    var isMobile = /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent);

    if (isMobile) {
        // On mobile: show deep link button instead of QR
        var mobileDiv = document.getElementById('oid4vp-mobile-link');
        var deeplinkBtn = document.getElementById('oid4vp-deeplink-btn');
        var qrWrapper = document.getElementById('oid4vp-qr-wrapper');

        if (mobileDiv && deeplinkBtn) {
            deeplinkBtn.href = config.openidUri;
            mobileDiv.classList.remove('oid4vp-hidden');
        }
        // Hide QR code container on mobile (can't scan own screen)
        if (qrWrapper) {
            qrWrapper.querySelector('#oid4vp-qr-code').classList.add('oid4vp-hidden');
        }
    } else {
        // On desktop: generate QR code
        var qrContainer = document.getElementById('oid4vp-qr-code');
        if (typeof QRCode !== 'undefined' && qrContainer) {
            QRCode.toCanvas(document.createElement('canvas'), config.openidUri, {
                width: 280,
                margin: 2,
                color: { dark: '#000000', light: '#ffffff' }
            }, function (error, canvas) {
                if (error) {
                    console.error('OID4VP: QR generation failed', error);
                    showError('Failed to generate QR code');
                    return;
                }
                qrContainer.appendChild(canvas);
            });
        } else {
            console.error('OID4VP: QRCode library not loaded');
        }
    }

    // Start polling for status (every 2s)
    pollInterval = setInterval(pollStatus, 2000);
    updateTimer();
    timerInterval = setInterval(updateTimer, 1000);

    function pollStatus() {
        // Check client-side timeout
        if (Date.now() - startTime > timeoutMs) {
            stopPolling();
            showError('Session expired. Please try again.');
            return;
        }

        var xhr = new XMLHttpRequest();
        xhr.open('GET', config.statusUrl);
        xhr.setRequestHeader('Accept', 'application/json');
        xhr.timeout = 5000;

        xhr.onload = function () {
            if (xhr.status === 200) {
                try {
                    var response = JSON.parse(xhr.responseText);
                    if (response.status === 'completed') {
                        stopPolling();
                        showSuccess();
                        // Redirect to qrpage?complete=1 to finish auth
                        setTimeout(function () {
                            window.location.href = config.qrpageUrl
                                + '?AuthState=' + encodeURIComponent(config.authState)
                                + '&complete=1';
                        }, 1000);
                    } else if (response.status === 'expired') {
                        stopPolling();
                        showError('Session expired. Please try again.');
                    }
                } catch (e) {
                    console.error('OID4VP: Invalid status response');
                }
            }
        };

        xhr.onerror = function () {
            console.warn('OID4VP: Status poll failed, retrying...');
        };

        xhr.send();
    }

    function stopPolling() {
        if (pollInterval) clearInterval(pollInterval);
        if (timerInterval) clearInterval(timerInterval);
    }

    function showError(message) {
        var errorDiv = document.getElementById('oid4vp-error');
        var errorText = document.getElementById('oid4vp-error-text');
        var qrWrapper = document.getElementById('oid4vp-qr-wrapper');

        if (errorDiv && errorText) {
            errorText.textContent = message;
            errorDiv.classList.remove('oid4vp-hidden');
        }
        if (qrWrapper) {
            qrWrapper.classList.add('oid4vp-expired');
        }

        var statusDiv = document.getElementById('oid4vp-status');
        if (statusDiv) {
            statusDiv.className = 'oid4vp-status oid4vp-status-error';
            var statusText = document.getElementById('oid4vp-status-text');
            if (statusText) statusText.textContent = message;
        }
    }

    function showSuccess() {
        var successDiv = document.getElementById('oid4vp-success');
        if (successDiv) {
            successDiv.classList.remove('oid4vp-hidden');
        }

        var statusDiv = document.getElementById('oid4vp-status');
        if (statusDiv) {
            statusDiv.className = 'oid4vp-status oid4vp-status-success';
            var icon = document.getElementById('oid4vp-status-icon');
            if (icon) icon.className = 'oid4vp-checkmark';
            var statusText = document.getElementById('oid4vp-status-text');
            if (statusText) statusText.textContent = 'Verified!';
        }
    }

    function updateTimer() {
        var elapsed = Date.now() - startTime;
        var remaining = Math.max(0, Math.ceil((timeoutMs - elapsed) / 1000));
        var minutes = Math.floor(remaining / 60);
        var seconds = remaining % 60;
        var timerText = document.getElementById('oid4vp-timer-text');
        if (timerText) {
            timerText.textContent = minutes + ':' + (seconds < 10 ? '0' : '') + seconds;
        }
    }
})();
