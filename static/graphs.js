// ---------- MAIN ENTRY ----------
window.addEventListener("DOMContentLoaded", () => {
    const cveData = window.cveData || [];
    if (!cveData.length) {
        document.querySelectorAll('.graph-container').forEach(div => {
            div.innerHTML = '<p class="no-data">No CVE data available. Please <a href="/stream-cves">fetch CVEs</a> first.</p>';
        });
        return;
    }
    updateGraphs(cveData);
});

function updateGraphs(cveData) {
    renderScoreDistribution(cveData);
    renderSeverityBar(cveData);
    renderScatterRegression(cveData);
    renderWordCloud(cveData);
}

// ---------- HELPERS ----------
function prepareBins(scores, step = 0.1, max = 10) {
    const bins = Array.from({ length: Math.floor(max / step) + 1 }, (_, i) => +(i * step).toFixed(1));
    const counts = Array(bins.length).fill(0);
    scores.forEach(score => {
        if (score != null && score !== "") {
            const idx = Math.round(score / step);
            if (idx >= 0 && idx < counts.length) counts[idx]++;
        }
    });
    return { bins, counts };
}

function countSeverities(cveData, field, severities) {
    return cveData.reduce((acc, d) => {
        const sev = d[field];
        if (sev && severities.includes(sev)) acc[sev] = (acc[sev] || 0) + 1;
        return acc;
    }, {});
}

function addJitter(values, amount = 0.05) {
    return values.map(v => v + (Math.random() - 0.5) * amount);
}

function linearRegression(x, y) {
    const n = x.length;
    const sumX = x.reduce((a, b) => a + b, 0);
    const sumY = y.reduce((a, b) => a + b, 0);
    const sumXY = x.reduce((a, b, i) => a + b * y[i], 0);
    const sumX2 = x.reduce((a, b) => a + b * b, 0);
    const m = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    const b = (sumY - m * sumX) / n;
    return { m, b };
}

function getColor(avg) {
    if (avg < 2) return 'teal';
    if (avg < 3) return 'lightblue';
    if (avg < 4) return 'blue';
    if (avg < 5) return 'green';
    if (avg < 7) return 'orange';
    if (avg < 8) return 'yellow';
    if (avg < 9) return 'red';
    return 'darkred';
}

function calculateAverageScores(cveData) {
    return cveData.map(d => (parseFloat(d.cvss_v3_score) + parseFloat(d.cvss_v2_score)) / 2);
}
// Filter out CVEs without scores
function filterValidCVEs(data) {
    return data.filter(d => d.cvss_v3_score && d.cvss_v2_score);
}

// Convert scores to float
function parseScores(data, field) {
    return data.map(d => parseFloat(d[field]));
}

// Add small jitter to avoid overlapping points
function addJitter(values, amount = 0.05) {
    return values.map(v => v + (Math.random() - 0.5) * amount);
}

// Calculate linear regression
function calculateRegression(x, y) {
    const n = x.length;
    const sumX = x.reduce((a, b) => a + b, 0);
    const sumY = y.reduce((a, b) => a + b, 0);
    const sumXY = x.reduce((a, b, i) => a + b * y[i], 0);
    const sumX2 = x.reduce((a, b) => a + b * b, 0);
    const m = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    const b = (sumY - m * sumX) / n;
    return {
        m,
        b,
        xRange: [Math.min(...x), Math.max(...x)],
        yRange: [Math.min(...x), Math.max(...x)].map(xVal => m * xVal + b)
    };
}

// Calculate average CVSS score for coloring
function calculateAverageScores(data) {
    return data.map(d => (parseFloat(d.cvss_v3_score) + parseFloat(d.cvss_v2_score)) / 2);
}

// Create Plotly traces for scatter and regression line
function createScatterTraces(scatterData, x, y, avgScores, colors, regression) {
    return [
        {
            type: 'scatter',
            mode: 'markers',
            x,
            y,
            text: scatterData.map((d, i) => `CVE: ${d.id}<br>Avg: ${avgScores[i].toFixed(2)}`),
            textposition: 'top center',
            marker: { size: 10, color: colors, opacity: 1, line: { color: 'black', width: 0.5 } },
            hovertemplate: '%{text}<br> v3: %{x}<br> v2: %{y}<extra></extra>',
            name: 'CVEs'
        },
        {
            type: 'scatter',
            mode: 'lines',
            x: regression.xRange,
            y: regression.yRange,
            line: { color: 'black', width: 2, dash: 'dash' },
            name: `Regression (y=${regression.m.toFixed(2)}x+${regression.b.toFixed(2)})`
        }
    ];
}

// Create layout for scatter plot
function createScatterLayout() {
    return {
        title: { text: 'CVSS v3 vs. v2 Scores', font: { size: 18 } },
        xaxis: { title: 'CVSS v3 Score', range: [0, 10.5], dtick: 1, gridcolor: '#ddd' },
        yaxis: { title: 'CVSS v2 Score', range: [0, 10.5], dtick: 1, gridcolor: '#ddd' },
        margin: { t: 50, b: 70, l: 50, r: 50 },
        plot_bgcolor: '#f8f9fa',
        paper_bgcolor: '#f8f9fa',
        responsive: true,
        hovermode: 'closest'
    };
}

function prepareWordCloudData(cveData, topN = 25) {
    const stopWords = ['the','and','or','of','in','to','with','a','for','on','by','from','this','when','could','gold','that'];
    const allText = cveData.map(d => d.description || '').join(' ');

    const words = allText.toLowerCase()
        .replace(/[.,/#!$%^&*;:{}=\-_`~()]/g, "")
        .split(/\s+/)
        .filter(w => w.length > 2 && !stopWords.includes(w) && !/^\d+$/.test(w));

    const wordFreq = {};
    words.forEach(w => wordFreq[w] = (wordFreq[w] || 0) + 1);

    return Object.entries(wordFreq)
        .sort((a, b) => b[1] - a[1])
        .slice(0, topN);
}


// ---------- PLOTTING ----------
function renderScoreDistribution(cveData) {
    const step = 0.1;
    const v3Scores = cveData.map(d => parseFloat(d.cvss_v3_score)).filter(s => !isNaN(s));
    const v2Scores = cveData.map(d => parseFloat(d.cvss_v2_score)).filter(s => !isNaN(s));
    const { bins, counts: v3Counts } = prepareBins(v3Scores, step);
    const { counts: v2Counts } = prepareBins(v2Scores, step);

    Plotly.newPlot('cvss-v3-histogram', [
        { type: 'scatter', mode: 'lines+markers', x: bins, y: v3Counts, name: 'CVSS v3', line: { color: 'blue' } },
        { type: 'scatter', mode: 'lines+markers', x: bins, y: v2Counts, name: 'CVSS v2', line: { color: 'red' } }
    ], {
        title: { text: 'Distribution of CVSS v2 vs CVSS v3 Scores', font: { size: 18 } },
        xaxis: { title: 'CVSS Score', dtick: 0.5, range: [0, 10] },
        yaxis: { title: 'Count' },
        margin: { t: 50, b: 50, l: 50, r: 50 },
        plot_bgcolor: '#f8f9fa', paper_bgcolor: '#f8f9fa', responsive: true
    });
}

function renderSeverityBar(cveData) {
    const severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const v3Counts = severities.map(sev => countSeverities(cveData, 'cvss_v3_severity', severities)[sev] || 0);
    const v2Counts = severities.map(sev => countSeverities(cveData, 'cvss_v2_severity', severities)[sev] || 0);

    Plotly.newPlot('severity-bar', [
        { type: 'bar', x: severities, y: v3Counts, name: 'CVSS v3', marker: { color: '#1f77b4' }, text: v3Counts, textposition: 'outside', hovertemplate: 'Severity: %{x}<br>CVSS v3 Count: %{y}<extra></extra>' },
        { type: 'bar', x: severities, y: v2Counts, name: 'CVSS v2', marker: { color: '#ff7f0e' }, text: v2Counts, textposition: 'outside', hovertemplate: 'Severity: %{x}<br>CVSS v2 Count: %{y}<extra></extra>' }
    ], {
        title: { text: 'CVSS v2 and v3 Severity Counts', font: { size: 18 } },
        xaxis: { title: 'Severity' }, yaxis: { title: 'Count' },
        margin: { t: 50, b: 50, l: 50, r: 50 }, barmode: 'group',
        plot_bgcolor: '#f8f9fa', paper_bgcolor: '#f8f9fa', responsive: true
    }, { displayModeBar: false });
}


function renderScatterRegression(cveData) {
    const scatterData = filterValidCVEs(cveData);
    if (!scatterData.length) return;

    const xVals = parseScores(scatterData, 'cvss_v3_score');
    const yVals = parseScores(scatterData, 'cvss_v2_score');

    const jitteredX = addJitter(xVals);
    const jitteredY = addJitter(yVals);

    const regression = calculateRegression(xVals, yVals);

    const avgScores = calculateAverageScores(scatterData);
    const colors = avgScores.map(getColor);

    const traces = createScatterTraces(scatterData, jitteredX, jitteredY, avgScores, colors, regression);

    const layout = createScatterLayout();

    Plotly.newPlot('score-scatter', traces, layout, { displayModeBar: false });
}



function renderWordCloud(cveData) {
    const wordArray = prepareWordCloudData(cveData, 25);
    const container = document.getElementById('wordcloud');

    WordCloud(container, {
        list: wordArray,
        gridSize: Math.round(16 * container.offsetWidth / 1024),
        weightFactor: size => Math.log(size + 1) * 10,
        color: 'random-dark',
        rotateRatio: 0.5,
        backgroundColor: '#f8f9fa',
        minSize: 10
    });
}



