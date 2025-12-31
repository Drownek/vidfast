import { VidstackPlayer, VidstackPlayerLayout } from 'vidstack/global/player';

(function() {
    let player = null;
    let currentM3u8Url = null;

    // HLS.js config for aggressive buffering (handles 2min+ outages)
    const hlsConfig = {
        maxBufferLength: 180,           // Buffer up to 3 minutes ahead
        maxMaxBufferLength: 300,        // Allow up to 5 minutes in extreme cases
        maxBufferSize: 120 * 1000000,   // 120MB buffer size
        maxBufferHole: 2,               // Tolerate 2s gaps
        lowLatencyMode: false,          // Disable low latency for better buffering
        backBufferLength: 60,           // Keep 1min of played content
        liveDurationInfinity: true,     // For live streams
        enableWorker: true,
        startFragPrefetch: true,        // Prefetch next segment early
        testBandwidth: true,
        progressive: true,
        // Retry settings for outages
        fragLoadingMaxRetry: 10,
        fragLoadingRetryDelay: 1000,
        fragLoadingMaxRetryTimeout: 64000,
        levelLoadingMaxRetry: 6,
        levelLoadingRetryDelay: 1000,
        manifestLoadingMaxRetry: 6,
        manifestLoadingRetryDelay: 1000,
    };

    async function createPlayer(target, options = {}) {
        if (player) {
            try { player.destroy(); } catch(e) {}
            player = null;
        }
        
        // Clear target
        const targetEl = document.querySelector(target);
        if (targetEl) targetEl.innerHTML = '';

        // Store m3u8 URL for prefetch
        if (options.src && typeof options.src === 'string' && options.src.includes('.m3u8')) {
            currentM3u8Url = options.src;
            // Trigger server-side prefetch
            triggerPrefetch(options.src);
        }

        player = await VidstackPlayer.create({
            target,
            title: options.title || 'Video',
            src: options.src,
            poster: options.poster || '',
            crossOrigin: true,
            playsInline: true,
            layout: new VidstackPlayerLayout({
                captions: true,
            }),
            // Pass HLS config for aggressive buffering
            hls: hlsConfig,
        });

        return player;
    }

    // Trigger server-side prefetch
    async function triggerPrefetch(m3u8Url) {
        try {
            // Extract original m3u8 URL if proxied
            let originalUrl = m3u8Url;
            if (m3u8Url.includes('/api/proxy?url=')) {
                const params = new URLSearchParams(m3u8Url.split('?')[1]);
                originalUrl = params.get('url');
            }
            
            await fetch('/api/prefetch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ m3u8Url: originalUrl })
            });
        } catch (e) {
            console.warn('Prefetch request failed:', e.message);
        }
    }

    function getPlayer() {
        return player;
    }

    async function loadTextTrack(url, label = 'English', language = 'en', kind = 'subtitles') {
        if (!player) return;
        
        // Remove existing subtitle tracks
        try {
            const tracks = player.textTracks.toArray();
            for (const track of tracks) {
                if (track.kind === 'subtitles' || track.kind === 'captions') {
                    player.textTracks.remove(track);
                }
            }
        } catch(e) {}
        
        // Add new track
        player.textTracks.add({
            src: url,
            label,
            language,
            kind,
            default: true,
        });
        
        // Enable the track
        setTimeout(() => {
            try {
                const tracks = player.textTracks.toArray();
                const subTrack = tracks.find(t => t.kind === 'subtitles' || t.kind === 'captions');
                if (subTrack) {
                    subTrack.mode = 'showing';
                }
            } catch(e) {}
        }, 500);
    }

    function destroyPlayer() {
        if (player) {
            try { player.destroy(); } catch(e) {}
            player = null;
        }
    }

    // Expose to window
    window.VidstackHelper = {
        createPlayer,
        getPlayer,
        loadTextTrack,
        destroyPlayer
    };
})();
