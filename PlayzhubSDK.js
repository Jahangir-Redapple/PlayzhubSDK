/* global navigator, window, console, JSBridge */
/* eslint-disable */
(function () {
    function loadCryptoJS() {
        return new Promise((resolve, reject) => {
            // if (window.CryptoJS) return resolve();
            if (window.CryptoJS && window.CryptoJS.AES) {
                return resolve();
            }

            const script = document.createElement('script');
            script.src = 'https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js';
            script.onload = () => {
                console.log('✅ CryptoJS loaded');
                resolve();
            };
            script.onerror = reject;
            document.head.appendChild(script);
        });
    }
    class PlayzhubSDk_E6 {
        constructor() {
            this.baseUrl = 'https://feature-api.playzhub.com';
            this.verifySessionApiURL = '/verified-session';
            this.submitScoreApiURL = '/save-game-session';
            this.getGameStateApiURL = '/get-visitor-game-state';
            this.saveGameStateApiURL = '/save-visitor-game-state';
            this.signingServiceUrl = "https://feature-api.playzhub.com/sec/sign-request"
            this.key = null;
            this.iv = null;
            this.cryptoReady = false;
            this.cryptoInitPromise = null;
            this.listeners = {};
            this.setupMessageListener();
        };

        //#region-Bridge/Communication Part
        getMobileOperatingSystem() {
            const userAgent = navigator.userAgent || navigator.vendor || window.opera;
            if (/android/i.test(userAgent)) {
                return 'Android';
            }
            if (/iPad|iPhone|iPod/.test(userAgent) && !window.MSStream) {
                return 'iOS';
            }
            return 'Browser';
        };

        sendMessageForAnalytics(eventName, message) {
            const os = this.getMobileOperatingSystem();
            const data = JSON.stringify(message);

            // console.log(`sendMessageForAnalytics - ${eventName} called`, data);
            switch (os) {
                case 'Android':
                    try {
                        console.log(`Android - ${eventName} called`, data);
                        // window.parent.postMessage({ eventName, data }, '*');
                        window.postMessage({ eventName, data }, '*');
                        if (window.flutter_inappwebview) {
                            window.flutter_inappwebview.callHandler('playzhubsdk_event_handler', eventName, data);
                        } else {
                            JSBridge[eventName](data);
                        }
                    } catch (error) {
                        // console.error(`Android JS Bridge error: ${error}`);
                    }
                    break;

                case 'iOS':
                    try {
                        console.log(`iOS - ${eventName} called`, data);
                        // window.parent.postMessage({ eventName, data }, '*');
                        window.postMessage({ eventName, data }, '*');
                        const postData = { [eventName]: data };

                        if (window.flutter_inappwebview) {
                            window.flutter_inappwebview.callHandler('playzhubsdk_event_handler', eventName, data);
                        } else {
                            window.webkit.messageHandlers.jsHandler.postMessage(JSON.stringify(postData));
                        }
                    } catch (error) {
                        // console.error(`iOS JS Bridge error: ${error}`);
                    }
                    break;

                case 'Browser':
                    try {
                        console.log(`Browser - ${eventName} called`, data);
                        // window.parent.postMessage({ eventName, data }, '*');
                        window.postMessage({ eventName, data }, '*');
                        if (window.flutter_inappwebview) {
                            window.flutter_inappwebview.callHandler('playzhubsdk_event_handler', eventName, data);
                        } else { }
                    } catch (error) {
                        // console.error(`Browser JS Bridge error: ${error}`);
                    }
                    break;

                default:
                    try {
                        console.log(`Default - ${eventName} called`, data);
                        window.postMessage({ eventName, data }, '*');
                        if (window.flutter_inappwebview) {
                            window.flutter_inappwebview.callHandler('playzhubsdk_event_handler', eventName, data);
                        } else { }
                    } catch (error) {
                        // console.error(`Default JS Bridge error: ${error}`);
                    }
            }
        };

        // Emit an event to be sent to the platform
        async emitEvent(eventName, payload) {
            // console.log(`Emit event: ${eventName} =====> ${JSON.stringify(payload)}`);
            await this.callApiAsPerEvent(eventName, payload);
            this.sendMessageForAnalytics(eventName, payload);
        };

        // Listen for incoming events and parse the data
        listen(eventName, callback) {
            if (!this.listeners[eventName]) {
                this.listeners[eventName] = [];
            }
            this.listeners[eventName].push((payload) => {
                try {
                    // Ensure the payload is safely parsed
                    const parsedData = typeof payload === 'string' ? JSON.parse(payload) : payload;
                    callback(parsedData);
                } catch (error) {
                    // console.error(`Error parsing data for event "${eventName}":`, error);
                }
            });
            // console.log(`Listener added for event: ${eventName}`);
        };

        trigger(eventName, payload) {
            // console.log(`Triggering event: ${eventName}`, payload);
            // Ensure that the payload is parsed correctly
            try {
                payload = typeof payload === 'string' ? JSON.parse(payload) : payload;
            } catch (error) {
                // console.error(`Error parsing payload for event ${eventName}:`, error);
            }
            // Check if any listener is attached for the eventName
            if (this.listeners[eventName]) {
                this.listeners[eventName].forEach(callback => callback(payload));
            }
        };

        // Automatically handle incoming messages from the platform
        setupMessageListener() {
            window.addEventListener('message', (event) => {
                const { eventName, data } = event.data || {};
                if (eventName && this.listeners[eventName]) {
                    // console.log(`Received event: ${eventName}`, data);
                    // Parse the data and trigger the event
                    this.trigger(eventName, data);
                }
            });
        };
        //#endregion

        //#region-API Part
        getLaunchParams() {
            const params = new URLSearchParams(window.location.search);
            const result = {};
            for (const [key, value] of params.entries()) {
                result[key] = value;
            }
            return JSON.stringify(result);
        };

        async getData(path, options = {}) {
            const clientId = "playzhub"; // or retrieve dynamically if needed
            const method = options.method || "GET";
            let body = options.body || null;

            const originalHeaders =
                options.headers instanceof Headers
                    ? Object.fromEntries(options.headers.entries())
                    : options.headers || {};

            let signedHeaders = {};
            let temp = path;
            const isAdRoute = path.startsWith("/advertisement");

            try {
                if (body != null) {
                    if (body instanceof FormData) {
                        console.log("Body is FormData, setting it to null");
                        body = null;
                    }
                }
                if (isAdRoute) {
                    temp = path.replace("/advertisement/api", "");
                }
                const serializedBody = JSON.stringify({
                    clientId,
                    method,
                    path: isAdRoute ? temp : path,
                    body,
                });
                // const payload = this.encrypt(serializedBody);

                if (!this.cryptoReady) {
                    throw new Error(
                        "getData() called before crypto initialization"
                    );
                }
                const payload = this.encrypt(serializedBody);

                const signRes = await fetch(this.signingServiceUrl, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ payload: payload }),
                });
                const data = await signRes.json();
                const {
                    clientId: id,
                    timestamp,
                    nonce,
                    signature,
                } = JSON.parse(this.decrypt(data.payload));

                // Step 2: Call actual API with signed headers
                signedHeaders = {
                    "x-client-id": id,
                    "x-timestamp": timestamp,
                    "x-nonce": nonce,
                    "x-signature": signature,
                    ...originalHeaders,
                };
            } catch (error) {
                console.error("[ERROR] origin: server.js.\nREASON:", error);
                signedHeaders = {
                    "x-client-id": "NIL",
                    "x-timestamp": "NIL",
                    "x-nonce": "NIL",
                    "x-signature": "NIL",
                    ...originalHeaders,
                };
            }

            const prefix = "";
            try {
                const request = await fetch(this.baseUrl + prefix + path, {
                    method: "GET",
                    ...options,
                    headers: signedHeaders,
                });
                const result = await request.json();

                if ([400, 401, 403, 404, 406].includes(request.status) || result.error) {
                    throw result;
                }
                return result;
            } catch (err) {
                console.error("[ERROR] path:", path, "signed-headers:", signedHeaders);
                throw err;
            }
        };

        getHeaders(contentType, token) {
            const headers = new Headers();
            if (token) headers.append("Authorization", `Bearer ${token}`);
            if (!contentType) {
                headers.append("Content-Type", "application/json");
            } else if (contentType !== "formdata") {
                headers.append("Content-Type", contentType);
            }
            return headers;
        };

        async verifyGameSessionId(_token, _gameId, _sessionId, _hashKey) {
            try {
                const headers = this.getHeaders("application/json", _token);
                const body = {
                    game_id: _gameId,
                    session_id: _sessionId,
                    hash: _hashKey,
                };
                return await this.getData(this.verifySessionApiURL, {
                    method: "POST",
                    headers,
                    body: JSON.stringify(body),
                });
            } catch (error) { }
        };

        async getGameState(_token, _gameId, _hashKey) {
            try {
                const headers = this.getHeaders("application/json", _token);
                const body = {
                    'game_id': _gameId,
                    'hash': _hashKey
                };
                return await this.getData(this.getGameStateApiURL, {
                    method: "POST",
                    headers,
                    body: JSON.stringify(body),
                });
            } catch (error) { }
        };

        async saveGameScore(_token, _gameId, _score, _hashKey) {
            try {
                const headers = this.getHeaders("application/json", _token);
                const body = {
                    'game_id': _gameId,
                    'game_score': _score,
                    'hash': _hashKey
                };
                return await this.getData(this.submitScoreApiURL, {
                    method: "POST",
                    headers,
                    body: JSON.stringify(body),
                });
            } catch (error) { }
        };

        async saveGameState(_token, _gameId, _gameState, _hashKey) {
            try {
                const headers = this.getHeaders("application/json", _token);
                const body = {
                    'game_id': _gameId,
                    'game_state': _gameState,
                    'hash': _hashKey
                };
                return await this.getData(this.saveGameStateApiURL, {
                    method: "POST",
                    headers,
                    body: JSON.stringify(body),
                });
            } catch (error) { }
        };

        //region- Call API as per event 
        async callApiAsPerEvent(_eventName, _payload,) {
            const gameParams = JSON.parse(this.getLaunchParams());
            console.log('callApiAsPerEvent params...........', gameParams);
            console.log('callApiAsPerEvent _payload...........', _payload);
            if (_payload?.encKey && _payload?.iv) {
                await this.ensureCryptoInitialized(_payload.encKey, _payload.iv);
            } else if (!this.cryptoReady) {
                console.error("Missing crypto keys in payload");
                return;
            }
            switch (_eventName) {
                case 'RequestGameState':
                    await this.handleGameStateFetchApi(_payload, gameParams);
                    break;

                case 'GameScoreUpdate':
                    await this.handleGameScoreUpdateApi(_payload, gameParams);
                    break;

                case 'GameStateUpdate':
                    await this.handleSaveGameStateApi(_payload, gameParams);
                    break;

                default:
                    break;
            }
        };
        //endregion

        async handleGameStateFetchApi(_payload, gameParams) {
            // this.initializeKey(_payload.encKey, _payload.iv);
            console.log('handleGameStateFetchApi _payload...........', _payload);
            console.log('handleGameStateFetchApi params...........', gameParams);
            const gameId = gameParams.game_id;
            const sessionId = gameParams.session_id;
            const token = gameParams.token;
            const verify = await this.verifyGameSessionId(
                token,
                gameId,
                sessionId,
                _payload.session_verify_hash
            );
            console.log('HandleGameStateFetchApi VerifyGameSessionId: ', verify);
            if (!verify || !verify.is_verified || verify.status !== 1) {
                console.error(`Session verification failed`);
                return;
            }
            const response = await this.getGameState(
                token,
                gameId,
                _payload.request_game_state_hash
            );
            console.log('HandleGameStateFetchApi GetGameState: ', response);
            const gameState = response?.data?.game_state ?? null;
            this.sendMessageForAnalytics('ReceivedGameState', gameState);
        };

        async handleGameScoreUpdateApi(_payload, gameParams) {
            // this.initializeKey(_payload.encKey, _payload.iv);
            console.log('handleGameScoreUpdateApi _payload...........', _payload);
            console.log('handleGameScoreUpdateApi params...........', gameParams);
            const gameId = gameParams.game_id;
            const sessionId = gameParams.session_id;
            const token = gameParams.token;
            const verify = await this.verifyGameSessionId(
                token,
                gameId,
                sessionId,
                _payload.session_verify_hash
            );
            console.log('HandleGameScoreUpdateApi VerifyGameSessionId: ', verify);
            if (!verify || !verify.is_verified || verify.status !== 1) {
                console.error(`Session verification failed`);
                return;
            }
            const response = await this.saveGameScore(
                token,
                gameId,
                _payload.score,
                _payload.score_hash
            );
            console.log('HandleGameScoreUpdateApi SaveGameScore: ', response);
        };

        async handleSaveGameStateApi(_payload, gameParams) {
            // this.initializeKey(_payload.encKey, _payload.iv);
            console.log('handleSaveGameStateApi _payload...........', _payload);
            console.log('handleSaveGameStateApi params...........', gameParams);
            const gameId = gameParams.game_id;
            const sessionId = gameParams.session_id;
            const token = gameParams.token;
            const verify = await this.verifyGameSessionId(
                token,
                gameId,
                sessionId,
                _payload.session_verify_hash
            );
            console.log('HandleSaveGameStateApi VerifyGameSessionId: ', verify);
            if (!verify || !verify.is_verified || verify.status !== 1) {
                console.error(`Session verification failed`);
                return;
            }
            const response = await this.saveGameState(
                token,
                gameId,
                _payload.game_state,
                _payload.request_game_state_hash
            );
            console.log('HandleSaveGameStateApi SaveGameState: ', response);
        };
        //#endregion

        ensureCryptoInitialized(encKey, iv) {
            if (this.cryptoReady) return Promise.resolve();

            if (!encKey || !iv) {
                return Promise.reject(
                    new Error("Crypto initialization failed")
                );
            }

            if (!this.cryptoInitPromise) {
                this.cryptoInitPromise = new Promise((resolve) => {
                    this.initializeKey(encKey, iv);
                    this.cryptoReady = true;
                    resolve();
                });
            }

            return this.cryptoInitPromise;
        };


        //#region-Crypto Part
        initializeKey(_base64Key, _base64Iv) {
            console.log('_base64Key: ', _base64Key);
            console.log('_base64Iv: ', _base64Iv);

            if (!window.CryptoJS) {
                console.error('CryptoJS not loaded');
                return;
            }
            this.key = CryptoJS.enc.Base64.parse(_base64Key);
            this.iv = CryptoJS.enc.Base64.parse(_base64Iv);
            console.log('this.key: ', this.key);
            console.log('this.iv : ', this.iv);
        };
        encrypt(plaintext) {
            // if (!this.key || !this.iv) {
            //     console.error('Encryption key/IV not initialized');
            //     return null;
            // }
            if (!this.cryptoReady || !this.key || !this.iv) {
                throw new Error(
                    "encrypt() called before crypto initialization"
                );
            }
            return window.CryptoJS.AES.encrypt(plaintext, this.key, {
                iv: this.iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            }).toString(); // Base64 ciphertext
        };
        decrypt(ciphertext) {
            const decrypted = window.CryptoJS.AES.decrypt(ciphertext, this.key, {
                iv: this.iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7,
            });
            return decrypted.toString(CryptoJS.enc.Utf8);
        };
        //#endregion

    }
    // window.PlayzhubSDk = new PlayzhubSDk_E6();
    (async function bootstrap() {
        await loadCryptoJS();
        window.PlayzhubSDk = new PlayzhubSDk_E6();
        window.dispatchEvent(new Event('PlayzhubSDKReady'));
        console.log('✅ PlayzhubSDK initialized');
    })();
})();
