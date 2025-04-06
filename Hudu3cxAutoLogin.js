// ==UserScript==
// @name         Hudu → 3CX Auto-Login 
// @namespace    http://tampermonkey.net/
// @version      4.5
// @description  Auto 3cx login from Hudu
// @match        https://*.huducloud.com/*
// @grant        GM_xmlhttpRequest
// @grant        GM_addStyle
// @grant        GM_cookie
// @connect      huducloud.com
// @connect      *
// @updateURL   https://raw.githubusercontent.com/th0mas137/TM-Hudu3cxAutoLogin/refs/heads/main/Hudu3cxAutoLogin.js
// @downloadURL https://raw.githubusercontent.com/th0mas137/TM-Hudu3cxAutoLogin/refs/heads/main/Hudu3cxAutoLogin.js
// @run-at       document-end
// ==/UserScript==

(function() {
    'use strict';

    // We'll build Hudu URLs dynamically using window.location.origin
    // e.g. "https://teamtel.huducloud.com" or "https://myorg.huducloud.com"
    const baseHudu = window.location.origin;

    let isAlreadyInitialized = false;

    // Run once now
    initHudu3CXScript();

    // Re-run on partial page loads if Hudu uses Turbo or similar
    document.addEventListener('turbo:load', () => {
        initHudu3CXScript();
    });
    window.addEventListener('popstate', () => {
        initHudu3CXScript();
    });

    /**
     * If on /passwords page, poll for the container, attach observer, inject buttons
     */
    function initHudu3CXScript() {
        if (!location.href.includes('/passwords')) {
            return;
        }

        if (isAlreadyInitialized) {
            addButtonsIfPasswordsFound();
            return;
        }
        isAlreadyInitialized = true;

        // Poll for .table-scroll.table-scroll--fixed-column
        let pollingCount = 0;
        const maxPolls = 30;
        const pollIntervalMs = 200;

        const pollInterval = setInterval(() => {
            const container = document.querySelector('.table-scroll.table-scroll--fixed-column');
            if (container) {
                clearInterval(pollInterval);
                attachObserver(container);
                addButtonsIfPasswordsFound(container);
            } else {
                pollingCount++;
                if (pollingCount > maxPolls) {
                    clearInterval(pollInterval);
                    console.warn("Hudu → 3CX script: container not found after polling.");
                }
            }
        }, pollIntervalMs);
    }

    /**
     * Watch the container for newly added rows
     */
    function attachObserver(container) {
        const observer = new MutationObserver(() => {
            addButtonsIfPasswordsFound(container);
        });
        observer.observe(container, { childList: true, subtree: true });
    }

    /**
     * Finds numeric-username anchors, injects "Login" button
     */
    function addButtonsIfPasswordsFound(container) {
        container = container || document.querySelector('.table-scroll.table-scroll--fixed-column');
        if (!container) return;

        const userLinks = container.querySelectorAll('a[data-copy-button-text-value]:not([data-3cx-init])');
        userLinks.forEach(link => {
            const userVal = link.getAttribute('data-copy-button-text-value') || "";
            const isNumeric = /^[0-9]+(\.[0-9]+)?$/.test(userVal.trim());
            if (!isNumeric) {
                link.setAttribute('data-3cx-init', 'ignored');
                return;
            }

            link.setAttribute('data-3cx-init', 'true');

            const newBtn = document.createElement('a');
            newBtn.textContent = "Login";
            newBtn.className = "button button--plain";
            newBtn.style.cursor = "pointer";
            newBtn.style.marginLeft = "8px";

            newBtn.addEventListener('click', () => handle3CXLogin(link));
            link.insertAdjacentElement('afterend', newBtn);
        });
    }

    /**
     * 1) Finds row elements: 3CX link, password link, OTP link
     * 2) Fetches password + OTP (if link exists)
     * 3) Calls do3CXLogin with the fetched credentials
     */
    function handle3CXLogin(usernameLink) {
        const row = usernameLink.closest('tr') || usernameLink.parentNode;
        if (!row) {
            alert("Cannot find row for this username link!");
            return;
        }

        // The 3CX domain link
        let threeCxUrl = null;
        const link3cx = row.querySelector('a[href*=".3cx."]') 
                      || row.querySelector('a[href*="my3cx."]');
        if (link3cx) {
            threeCxUrl = link3cx.href;
        }
        if (!threeCxUrl) {
            alert("No 3CX link found in this row!");
            return;
        }

        // The password link
        const passLink = row.querySelector('a[data-copy-button-url-value*="/fetch_password"]');
        if (!passLink) {
            alert("No password link found in this row!");
            return;
        }
        // Build the full route from the local domain (no more "teamtel" hardcode)
        const passUrl = baseHudu + passLink.getAttribute('data-copy-button-url-value');

        // Possibly an OTP link (MFA)
        const otpLink = row.querySelector('a[data-copy-button-url-value*="/otp_authenticated_access"]');
        // If present, we assume 2FA is enabled
        const useMFA = !!otpLink;

        // The username from data-copy-button-text-value
        const username = usernameLink.getAttribute('data-copy-button-text-value') || "N/A";
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';

        // Step 1: fetch the password
        fetchHuduPassword(passUrl, csrfToken).then(password => {
            if (!password) {
                alert("Failed to fetch password from Hudu. See console.");
                return;
            }

            // Step 2: if an OTP link is present, fetch it up-front
            if (useMFA) {
                const otpUrl = baseHudu + otpLink.getAttribute('data-copy-button-url-value');
                fetchHuduOTP(otpUrl, csrfToken).then(otpCode => {
                    if (!otpCode) {
                        alert("Failed to fetch OTP code from Hudu. Check console.");
                        return;
                    }
                    // Now do a single login attempt with the OTP code
                    do3CXLogin(threeCxUrl, username, password, otpCode, useMFA);
                });
            } else {
                // No OTP link => login with empty code
                do3CXLogin(threeCxUrl, username, password, "", useMFA);
            }
        });
    }

    /**
     * GET the password from Hudu's /fetch_password route
     */
    function fetchHuduPassword(url, token) {
        return new Promise(resolve => {
            GM_xmlhttpRequest({
                method: "GET",
                url,
                anonymous: false,
                headers: {
                    'X-CSRF-Token': token,
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept': 'application/json'
                },
                onload: (res) => {
                    if (res.status !== 200) {
                        console.error(`Hudu password fetch error (status ${res.status}):`, res.responseText);
                        resolve(null);
                        return;
                    }
                    try {
                        const json = JSON.parse(res.responseText);
                        resolve(json.password);
                    } catch (err) {
                        console.error("Hudu JSON parse error:", err, res.responseText);
                        resolve(null);
                    }
                },
                onerror: (err) => {
                    console.error("Hudu password request error:", err);
                    resolve(null);
                }
            });
        });
    }

    /**
     * GET the OTP code from Hudu's /otp_authenticated_access route
     * Returns the code (e.g. '513400')
     */
    function fetchHuduOTP(url, token) {
        return new Promise(resolve => {
            GM_xmlhttpRequest({
                method: "GET",
                url,
                anonymous: false,
                headers: {
                    'X-CSRF-Token': token,
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept': 'application/json'
                },
                onload: (res) => {
                    if (res.status !== 200) {
                        console.error(`Hudu OTP fetch error (status ${res.status}):`, res.responseText);
                        resolve(null);
                        return;
                    }
                    try {
                        const json = JSON.parse(res.responseText);
                        // e.g. { otp: "513400", time_left: 5 }
                        resolve(json.otp);
                    } catch (err) {
                        console.error("Hudu OTP JSON parse error:", err, res.responseText);
                        resolve(null);
                    }
                },
                onerror: (err) => {
                    console.error("Hudu OTP request error:", err);
                    resolve(null);
                }
            });
        });
    }

    /**
     * Single-step 3CX login:
     *   - If 2FA is actually disabled, passing SecurityCode won't break anything.
     *   - If 2FA is enabled, we already got a fresh code from Hudu.
     *   - Different alert for 401 if useMFA === true
     */
    function do3CXLogin(threeCxUrl, username, password, securityCode, useMFA) {
        const urlObj = new URL(threeCxUrl);
        const origin = urlObj.origin; // e.g. "https://autoglassclinic.3cx.be"
        let domain = urlObj.hostname; // e.g. "autoglassclinic.3cx.be"

        const loginEndpoint = `${origin}/webclient/api/Login/GetAccessToken`;

        const postData = {
            Username: username,
            Password: password,
            SecurityCode: securityCode // either "" or OTP code
        };

        GM_xmlhttpRequest({
            method: "POST",
            url: loginEndpoint,
            headers: {
                "Content-Type": "application/json"
            },
            data: JSON.stringify(postData),
            onload: (resp) => {
                // If we get a 401 unauthorized, handle MFA vs non-MFA
                if (resp.status === 401) {
                    if (useMFA) {
                        alert("OTP Code already used, Refresh or wait a few seconds");
                    } else {
                        alert("3CX login failed! (401) Check console for details.");
                    }
                    console.error("3CX login failed (401). Response:", resp.responseText);
                    return;
                }

                if (resp.status !== 200) {
                    console.error(`3CX login failed: ${resp.status}`, resp.responseText);
                    alert(`3CX login failed! Status ${resp.status}. See console.`);
                    return;
                }

                let data;
                try {
                    data = JSON.parse(resp.responseText);
                } catch (e) {
                    console.error("3CX login parse error:", e, resp.responseText);
                    alert("3CX login parse error! See console.");
                    return;
                }

                if (data.Status !== "AuthSuccess" || !data.Token) {
                    console.error("3CX returned unexpected data:", data);
                    alert(`3CX auth unsuccessful! Status: ${data.Status}`);
                    return;
                }

                const { access_token, refresh_token } = data.Token;
                if (!access_token || !refresh_token) {
                    console.error("Missing tokens in 3CX response:", data.Token);
                    alert("3CX token missing! Check console.");
                    return;
                }

                const cookieValue = `${access_token}^${refresh_token}`;
                // Leading dot for subdomains
                if (!domain.startsWith('.')) {
                    domain = '.' + domain;
                }

                GM_cookie('set', {
                    name: "RefreshTokenCookie",
                    value: cookieValue,
                    domain: domain,
                    path: "/"
                }, (res1) => {
                    if (res1?.error) {
                        console.warn(`Cookie set error for domain="${domain}". Retrying w/o domain.`);
                        GM_cookie('set', {
                            name: "RefreshTokenCookie",
                            value: cookieValue,
                            path: "/"
                        }, (res2) => {
                            if (res2?.error) {
                                console.error("Retry cookie set error:", res2.error);
                                alert("Error setting 3CX cookie. See console.");
                                return;
                            }
                            window.open(`${origin}/webclient`, "_blank");
                        });
                    } else {
                        window.open(`${origin}/webclient`, "_blank");
                    }
                });
            },
            onerror: (err) => {
                console.error("3CX login request error:", err);
                alert("3CX login request error! See console.");
            }
        });
    }

})();
