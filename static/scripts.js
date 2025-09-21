const tableBody = document.getElementById("cve-table-body");
const loadingDiv = document.getElementById("loading");
const referencesModal = document.getElementById("references-modal");
const descriptionModal = document.getElementById("description-modal");
const referencesList = document.getElementById("references-list");
const descriptionText = document.getElementById("description-text");
const referencesClose = document.getElementById("modal-close");
const descriptionClose = document.getElementById("description-close");

let sortedRows = [];
let currentSort = { column: null, direction: 'asc' };

// Modal logic for references
function openReferencesModal(urls) {
    referencesList.innerHTML = '';
    if (urls) {
        const urlArray = urls.split(",");
        urlArray.forEach(url => {
            if (url) {
                const li = document.createElement("li");
                const a = document.createElement("a");
                a.href = url;
                a.textContent = url;
                a.target = "_blank";
                li.appendChild(a);
                referencesList.appendChild(li);
            }
        });
    } else {
        referencesList.innerHTML = '<li>No references available</li>';
    }
    referencesModal.style.display = "flex";
}

// Modal logic for description
function openDescriptionModal(text) {
    descriptionText.textContent = text || "No description available";
    descriptionModal.style.display = "flex";
}

referencesClose.addEventListener('click', () => referencesModal.style.display = "none");
descriptionClose.addEventListener('click', () => descriptionModal.style.display = "none");

referencesModal.addEventListener('click', (e) => {
    if (e.target === referencesModal) referencesModal.style.display = "none";
});
descriptionModal.addEventListener('click', (e) => {
    if (e.target === descriptionModal) descriptionModal.style.display = "none";
});

// Sorting
document.querySelectorAll('th.sortable').forEach(th => {
    th.addEventListener('click', () => {
        const column = th.getAttribute('data-column');
        const direction = currentSort.column === column && currentSort.direction === 'asc' ? 'desc' : 'asc';
        currentSort = { column, direction };

        document.querySelectorAll('th.sortable').forEach(h => {
            h.classList.remove('sort-asc', 'sort-desc');
            if (h.getAttribute('data-column') === column) {
                h.classList.add(`sort-${direction}`);
            }
        });

        sortTable(column, direction);
    });
});

function sortTable(column, direction) {
    sortedRows.sort((a, b) => {
        let valA = a[column];
        let valB = b[column];

        if (valA == null || valA === '') valA = direction === 'asc' ? Infinity : -Infinity;
        if (valB == null || valB === '') valB = direction === 'asc' ? Infinity : -Infinity;

        if (column.includes('score')) {
            valA = parseFloat(valA) || 0;
            valB = parseFloat(valB) || 0;
            return direction === 'asc' ? valA - valB : valB - valA;
        }

        if (column.includes('severity')) {
            return direction === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
        }

        return 0;
    });

    tableBody.innerHTML = '';
    sortedRows.forEach(rowData => createRow(rowData));
}

// Create table row
function createRow(cve) {
    const row = document.createElement("tr");
    const fields = [
        cve.id || "",
        cve.published || "",
        cve.last_modified || "",
        cve.description || "", // Used for button logic, not displayed directly
        cve.cvss_v3_score || "",
        cve.cvss_v3_severity || "",
        cve.cvss_v2_score || "",
        cve.cvss_v2_severity || "",
        cve.reference_urls || ""
    ];

    fields.forEach((field, index) => {
        const cell = document.createElement("td");
        if (index === 8) { // References
            const btn = document.createElement("button");
            btn.className = "references-btn";
            btn.textContent = "References";
            btn.disabled = !field;
            if (field) btn.onclick = () => openReferencesModal(field);
            cell.appendChild(btn);
        } else if (index === 3) { // Description
            const btn = document.createElement("button");
            btn.className = "description-btn";
            btn.textContent = "View Description";
            btn.disabled = !field;
            if (field) btn.onclick = () => openDescriptionModal(field);
            cell.appendChild(btn);
        } else {
            cell.textContent = field;
        }
        row.appendChild(cell);
    });

    tableBody.appendChild(row);
    return row;
}

const source = new EventSource("/stream-cves");
source.onmessage = function(event) {
    const cves = JSON.parse(event.data);
    if (cves.error) {
        console.error("Error:", cves.error);
        loadingDiv.textContent = "Error: " + cves.error;
        source.close();
        return;
    }

    cves.forEach(cve => {
        sortedRows.push(cve);
        createRow(cve);
    });

    if (currentSort.column) {
        sortTable(currentSort.column, currentSort.direction);
    }

    loadingDiv.style.display = "none";
};

source.onerror = function() {
    console.error("SSE connection error");
    loadingDiv.textContent = "Error: Failed to connect to server";
    source.close();
};

// Loading dots animation
const loadingEl = document.getElementById("loading");
let dots = 1;
setInterval(() => {
    dots = (dots % 3) + 1;
    loadingEl.textContent = "Loading CVEs" + ".".repeat(dots);
}, 500);