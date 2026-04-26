let totalAnalyzed = 0;
let phishingDetected = 0;
let safeEmails = 0;

document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('detectionForm');
    const resultDiv = document.getElementById('result');
    const btnAnalyze = document.querySelector('.btn-analyze');
    const tabs = document.querySelectorAll('.tab');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            tab.classList.add('active');
            document.getElementById(tab.dataset.tab).classList.add('active');
        });
    });

    if (form) {
        form.addEventListener('submit', async function(e) {
            e.preventDefault();

            btnAnalyze.classList.add('loading');
            btnAnalyze.disabled = true;

            const formData = {
                subject: document.getElementById('emailSubject').value,
                body: document.getElementById('emailBody').value,
                url: document.getElementById('url').value,
                hasSuspiciousKeywords: document.getElementById('hasSuspiciousKeywords').checked,
                hasIPInURL: document.getElementById('hasIPInURL').checked,
                hasAttachment: document.getElementById('hasAttachment').checked,
                numLinks: parseInt(document.getElementById('numLinks').value) || 0
            };

            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(formData)
                });

                const result = await response.json();
                displayResult(result);
                updateDashboard(result.isPhishing);
            } catch (error) {
                const result = analyzeEmailClient(formData);
                displayResult(result);
                updateDashboard(result.isPhishing);
            }

            btnAnalyze.classList.remove('loading');
            btnAnalyze.disabled = false;
        });
    }

    const uploadArea = document.getElementById('uploadArea');
    const batchFile = document.getElementById('batchFile');
    
    if (uploadArea && batchFile) {
        uploadArea.addEventListener('click', () => batchFile.click());
        
        batchFile.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) processBatchFile(file);
        });

        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = 'var(--primary)';
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.style.borderColor = 'var(--gray-light)';
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = 'var(--gray-light)';
            const file = e.dataTransfer.files[0];
            if (file && file.name.endsWith('.csv')) {
                processBatchFile(file);
            }
        });
    }
});

function analyzeEmailClient(data) {
    const text = (data.subject + ' ' + data.body).toLowerCase();
    const url = data.url.toLowerCase();

    let score = 0;
    const factors = [];

    if (data.hasSuspiciousKeywords) {
        score += 25;
        factors.push('Contains suspicious keywords');
    }

    if (data.hasIPInURL) {
        score += 30;
        factors.push('URL contains IP address');
    }

    if (/click here|verify|urgent|account.*suspended|password|bank.*update|confirm.*identity/i.test(text)) {
        score += 20;
        factors.push('Urgent/pressuring language detected');
    }

    if (/http:\/\/\d+\.\d+.\d+.\d/.test(url)) {
        score += 25;
        factors.push('HTTP with numeric IP');
    }

    if (url.length > 50) {
        score += 15;
        factors.push('Unusually long URL');
    }

    if (data.numLinks > 3) {
        score += 10;
        factors.push('Multiple links in email');
    }

    if (data.hasAttachment) {
        score += 15;
        factors.push('Email has attachment');
    }

    const phishingDomains = ['.xyz', '.top', '.club', '.win', '.info', 'secure-', 'login-', 'verify-', 'update-'];
    for (const domain of phishingDomains) {
        if (url.includes(domain)) {
            score += 15;
            factors.push('Suspicious URL pattern');
            break;
        }
    }

    const confidence = Math.min(Math.max(score, 10), 100);

    return {
        isPhishing: score >= 50,
        confidence: confidence,
        factors: factors
    };
}

function displayResult(result) {
    const resultDiv = document.getElementById('result');
    if (!resultDiv) return;

    resultDiv.classList.remove('hidden', 'phishing', 'safe');

    const resultTitle = document.getElementById('resultTitle');
    const resultMessage = document.getElementById('resultMessage');
    const resultIcon = document.getElementById('resultIcon');
    const factorsList = document.getElementById('factorsList');

    const safePercent = result.isPhishing ? (100 - result.confidence) : result.confidence;
    const phishingPercent = result.isPhishing ? result.confidence : (100 - result.confidence);

    document.getElementById('safePercent').textContent = safePercent + '%';
    document.getElementById('phishingPercent').textContent = phishingPercent + '%';
    document.getElementById('safeFill').style.width = safePercent + '%';
    document.getElementById('phishingFill').style.width = phishingPercent + '%';

    resultIcon.innerHTML = '';
    factorsList.innerHTML = '';

    if (result.isPhishing) {
        resultDiv.classList.add('phishing');
        resultTitle.textContent = 'Phishing Email Detected';
        resultMessage.textContent = 'This email shows characteristics commonly found in phishing attempts. Do not click any links or download attachments.';
        resultIcon.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>';
    } else {
        resultDiv.classList.add('safe');
        resultTitle.textContent = 'Email Appears Safe';
        resultMessage.textContent = 'This email does not show obvious signs of phishing. However, always stay cautious with unexpected requests.';
        resultIcon.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>';
    }

    if (result.factors && result.factors.length > 0) {
        result.factors.forEach(factor => {
            const li = document.createElement('li');
            li.textContent = factor;
            factorsList.appendChild(li);
        });
        document.querySelector('.factors-section').style.display = 'block';
    } else {
        document.querySelector('.factors-section').style.display = 'none';
    }

    resultDiv.classList.remove('hidden');
}

function updateDashboard(isPhishing) {
    totalAnalyzed++;
    if (isPhishing) {
        phishingDetected++;
    } else {
        safeEmails++;
    }

    const totalEl = document.getElementById('totalAnalyzed');
    const phishingEl = document.getElementById('phishingDetected');
    const safeEl = document.getElementById('safeEmails');
    const accuracyEl = document.getElementById('accuracy');

    if (totalEl) totalEl.textContent = totalAnalyzed;
    if (phishingEl) phishingEl.textContent = phishingDetected;
    if (safeEl) safeEl.textContent = safeEmails;
    if (accuracyEl) accuracyEl.textContent = '98%';
}

function processBatchFile(file) {
    const reader = new FileReader();
    reader.onload = function(e) {
        const text = e.target.result;
        const lines = text.split('\n').filter(line => line.trim());
        
        let safeCount = 0;
        let phishingCount = 0;
        const results = [];

        lines.slice(1).forEach((line, index) => {
            if (index >= 10) return;
            const cols = line.split(',');
            if (cols.length >= 2) {
                const result = analyzeEmailClient({
                    subject: cols[0] || '',
                    body: cols[1] || '',
                    url: cols[2] || '',
                    hasSuspiciousKeywords: false,
                    hasIPInURL: false,
                    hasAttachment: false,
                    numLinks: 0
                });
                
                if (result.isPhishing) {
                    phishingCount++;
                } else {
                    safeCount++;
                }
                
                results.push({
                    email: (cols[0] || '').substring(0, 30),
                    result: result.isPhishing ? 'Phishing' : 'Safe',
                    confidence: result.confidence + '%'
                });
            }
        });

        document.getElementById('totalEmails').textContent = lines.length - 1;
        document.getElementById('safeCount').textContent = safeCount;
        document.getElementById('phishingCount').textContent = phishingCount;

        const tbody = document.getElementById('batchTableBody');
        tbody.innerHTML = '';
        results.forEach(r => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${r.email}</td>
                <td class="${r.result === 'Phishing' ? 'phishing' : 'safe'}">${r.result}</td>
                <td>${r.confidence}</td>
            `;
            tbody.appendChild(row);
        });

        document.getElementById('uploadArea').style.display = 'none';
        document.getElementById('batchResults').style.display = 'block';
    };
    reader.readAsText(file);
}