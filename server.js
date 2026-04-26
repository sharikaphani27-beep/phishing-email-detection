const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'static')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'static', 'index.html'));
});

app.post('/analyze', (req, res) => {
    const { text, url } = req.body;
    
    let score = 0;
    const factors = [];
    const lowerText = text?.toLowerCase() || '';
    const lowerUrl = url?.toLowerCase() || '';
    
    if (/click here|verify|urgent|account.*suspended|password|bank.*update|confirm.*identity/i.test(lowerText)) {
        score += 25;
        factors.push('Contains urgent pressuring language');
    }
    
    if (/http:\/\/\d+\.\d+.\d+.\d/.test(lowerUrl)) {
        score += 30;
        factors.push('URL contains IP address');
    }
    
    if (lowerUrl.length > 50) {
        score += 15;
        factors.push('Unusually long URL');
    }
    
    const suspiciousDomains = ['.xyz', '.top', '.club', '.win', '.info', 'secure-', 'login-'];
    for (const domain of suspiciousDomains) {
        if (lowerUrl.includes(domain)) {
            score += 20;
            factors.push('Suspicious URL pattern');
            break;
        }
    }
    
    const confidence = Math.min(Math.max(score, 10), 100);
    
    res.json({
        isPhishing: score >= 50,
        confidence,
        factors
    });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});