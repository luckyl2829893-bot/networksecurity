document.addEventListener('DOMContentLoaded', async () => {
    const loadingOverlay = document.getElementById('loading-overlay');
    const loadingTimer = document.getElementById('loading-timer');
    const targetUrlElem = document.getElementById('target-url');
    const riskScoreElem = document.getElementById('risk-score');
    const statusBadge = document.getElementById('status-badge');
    const agentBrief = document.getElementById('agent-brief');
    const rescanBtn = document.getElementById('rescan-btn');
    const anomaliesList = document.getElementById('anomalies-list');
    const heuristicContainer = document.getElementById('heuristic-reasons');

    const API_URL = 'http://localhost:8000/api/v1/analyze';
    let timerInterval = null;

    async function analyzeCurrentTab() {
        showLoading(true);
        try {
            // Get current active tab
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tab || !tab.url) {
                showError('Could not read tab URL');
                return;
            }

            const url = tab.url;
            targetUrlElem.textContent = url;

            // Call Safe-Surf API with a 90-second timeout
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 90000);

            let response;
            try {
                response = await fetch(API_URL, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query: url }),
                    signal: controller.signal
                });
            } finally {
                clearTimeout(timeoutId);
            }

            const result = await response.json();

            if (result.status === 'success') {
                updateUI(result.data);
            } else {
                showError(result.message || 'API Analysis Failed');
            }
        } catch (error) {
            console.error('Analysis Error:', error);
            if (error.name === 'AbortError') {
                showError('Scan timed out (>90s). Server is running but taking too long.');
            } else {
                showError('Server Unreachable. Make sure FastAPI is running on port 8000.');
            }
        } finally {
            showLoading(false);
        }
    }

    function updateUI(data) {
        const score = data.risk_score;
        riskScoreElem.textContent = score;

        // Color coding
        if (score < 30) {
            riskScoreElem.style.color = 'var(--accent-success)';
            statusBadge.textContent = 'Secure';
            statusBadge.className = 'status-badge secure';
        } else if (score < 70) {
            riskScoreElem.style.color = 'var(--accent-warning)';
            statusBadge.textContent = 'Suspicious';
            statusBadge.className = 'status-badge warning';
        } else {
            riskScoreElem.style.color = 'var(--accent-danger)';
            statusBadge.textContent = 'Danger';
            statusBadge.className = 'status-badge danger';
        }

        // Briefing
        agentBrief.innerHTML = formatBrief(data.security_brief);

        // Heuristics
        if (data.heuristic_reasons && data.heuristic_reasons.length > 0) {
            heuristicContainer.style.display = 'block';
            anomaliesList.innerHTML = data.heuristic_reasons.map(reason =>
                `<div style="margin-bottom: 5px;">&#x2022; ${reason}</div>`
            ).join('');
        } else {
            heuristicContainer.style.display = 'none';
        }
    }

    function formatBrief(text) {
        // Simple markdown-ish to HTML conversion
        return text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                   .replace(/\n/g, '<br>');
    }

    function showLoading(isLoading) {
        loadingOverlay.style.opacity = isLoading ? '1' : '0';
        loadingOverlay.style.pointerEvents = isLoading ? 'all' : 'none';

        if (isLoading) {
            statusBadge.className = 'status-badge loading';
            statusBadge.textContent = 'Scanning...';

            // Start elapsed timer
            const startTime = Date.now();
            timerInterval = setInterval(() => {
                const elapsed = Math.floor((Date.now() - startTime) / 1000);
                loadingTimer.textContent = `${elapsed}s elapsed — Deep scan in progress`;
            }, 1000);
        } else {
            // Stop timer
            if (timerInterval) {
                clearInterval(timerInterval);
                timerInterval = null;
            }
        }
    }

    function showError(msg) {
        agentBrief.innerHTML = `<span style="color: var(--accent-danger);">${msg}</span>`;
        riskScoreElem.textContent = 'ERR';
        statusBadge.textContent = 'Error';
        statusBadge.className = 'status-badge danger';
    }

    rescanBtn.addEventListener('click', analyzeCurrentTab);

    // Initial Analysis
    analyzeCurrentTab();
});
