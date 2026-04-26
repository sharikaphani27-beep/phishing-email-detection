document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('detectionForm');
    const resultDiv = document.getElementById('result');
    const btnAnalyze = document.querySelector('.btn-analyze');

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
        
        const result = await analyzeEmail(formData);
        displayResult(result);

        btnAnalyze.classList.remove('loading');
        btnAnalyze.disabled = false;
    });

    function analyzeEmail(data) {
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
        
        const urgentWords = (text.match(/\b(urgent|immediately|act now|limited time|expire|suspended|locked|unauthorized|verify|confirm)\b/gi) || []).length;
        score += Math.min(urgentWords * 5, 20);
        
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
        resultDiv.classList.remove('hidden', 'phishing', 'safe');
        
        const resultTitle = document.getElementById('resultTitle');
        const resultMessage = document.getElementById('resultMessage');
        const confidenceFill = document.getElementById('confidenceFill');
        const confidencePercent = document.getElementById('confidencePercent');
        
        if (result.isPhishing) {
            resultDiv.classList.add('phishing');
            resultTitle.textContent = 'Phishing Email Detected';
            resultMessage.textContent = 'This email shows characteristics commonly found in phishing attempts. Do not click any links or download attachments.';
        } else {
            resultDiv.classList.add('safe');
            resultTitle.textContent = 'Email Appears Safe';
            resultMessage.textContent = 'This email does not show obvious signs of phishing. However, always stay cautious with unexpected requests.';
        }
        
        confidenceFill.style.width = result.confidence + '%';
        confidencePercent.textContent = result.confidence + '%';
        
        resultDiv.classList.remove('hidden');
    }
});