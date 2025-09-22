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
            if (url.trim()) {
                const li = document.createElement("li");
                const a = document.createElement("a");
                a.href = url.trim();
                a.textContent = url.trim();
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

// Initialize sortedRows from server-rendered table
function initializeSortedRows() {
    sortedRows = [];
    const rows = tableBody.querySelectorAll("tr");
    rows.forEach(row => {
        const cells = row.querySelectorAll("td");
        const descriptionBtn = cells[3].querySelector(".description-btn");
        const referencesBtn = cells[8].querySelector(".references-btn");
        sortedRows.push({
            id: cells[0].textContent,
            published: cells[1].textContent,
            last_modified: cells[2].textContent,
            description: descriptionBtn ? descriptionBtn.getAttribute("data-description") : "",
            cvss_v3_score: cells[4].textContent || null,
            cvss_v3_severity: cells[5].textContent,
            cvss_v2_score: cells[6].textContent || null,
            cvss_v2_severity: cells[7].textContent,
            references: referencesBtn ? referencesBtn.getAttribute("data-references") : ""
        });
    });
}

// Attach event listeners to server-rendered buttons
function attachButtonListeners() {
    const descriptionButtons = document.querySelectorAll(".description-btn");
    const referencesButtons = document.querySelectorAll(".references-btn");

    descriptionButtons.forEach(btn => {
        btn.disabled = !btn.getAttribute("data-description");
        btn.onclick = () => openDescriptionModal(btn.getAttribute("data-description"));
    });

    referencesButtons.forEach(btn => {
        btn.disabled = !btn.getAttribute("data-references");
        btn.onclick = () => openReferencesModal(btn.getAttribute("data-references"));
    });
}

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

    // Re-render table with sorted rows
    tableBody.innerHTML = '';
    sortedRows.forEach(rowData => {
        const row = document.createElement("tr");
        const fields = [
            rowData.id || "",
            rowData.published || "",
            rowData.last_modified || "",
            rowData.description || "",
            rowData.cvss_v3_score || "",
            rowData.cvss_v3_severity || "",
            rowData.cvss_v2_score || "",
            rowData.cvss_v2_severity || "",
            rowData.references || ""
        ];

        fields.forEach((field, index) => {
            const cell = document.createElement("td");
            if (index === 8) { // References
                const btn = document.createElement("button");
                btn.className = "references-btn";
                btn.textContent = "References";
                btn.disabled = !field;
                btn.setAttribute("data-references", field);
                btn.onclick = () => openReferencesModal(field);
                cell.appendChild(btn);
            } else if (index === 3) { // Description
                const btn = document.createElement("button");
                btn.className = "description-btn";
                btn.textContent = "View Description";
                btn.disabled = !field;
                btn.setAttribute("data-description", field);
                btn.onclick = () => openDescriptionModal(field);
                cell.appendChild(btn);
            } else {
                cell.textContent = field;
            }
            row.appendChild(cell);
        });

        tableBody.appendChild(row);
    });

    // Re-attach button listeners after re-rendering
    attachButtonListeners();
}

// Initialize for /display-stored
if (window.location.pathname === "/display-stored") {
    initializeSortedRows();
    attachButtonListeners();
    if (sortedRows.length > 0) {
        loadingDiv.style.display = "none";
    } else {
        loadingDiv.style.display = "block";
        loadingDiv.textContent = "No CVEs found in database.";
    }
}

// Handle streaming CVEs for /display
if (window.location.pathname === "/display") {
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
            const row = document.createElement("tr");
            const fields = [
                cve.id || "",
                cve.published || "",
                cve.last_modified || "",
                cve.description || "",
                cve.cvss_v3_score || "",
                cve.cvss_v3_severity || "",
                cve.cvss_v2_score || "",
                cve.cvss_v2_severity || "",
                cve.references || cve.reference_urls || ""
            ];

            fields.forEach((field, index) => {
                const cell = document.createElement("td");
                if (index === 8) { // References
                    const btn = document.createElement("button");
                    btn.className = "references-btn";
                    btn.textContent = "References";
                    btn.disabled = !field;
                    btn.setAttribute("data-references", field);
                    btn.onclick = () => openReferencesModal(field);
                    cell.appendChild(btn);
                } else if (index === 3) { // Description
                    const btn = document.createElement("button");
                    btn.className = "description-btn";
                    btn.textContent = "View Description";
                    btn.disabled = !field;
                    btn.setAttribute("data-description", field);
                    btn.onclick = () => openDescriptionModal(field);
                    cell.appendChild(btn);
                } else {
                    cell.textContent = field;
                }
                row.appendChild(cell);
            });

            tableBody.appendChild(row);
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
}


// Loading dots animation
const loadingEl = document.getElementById("loading");
let dots = 1;
setInterval(() => {
    dots = (dots % 3) + 1;
    loadingEl.textContent = "Loading CVEs" + ".".repeat(dots);
}, 400);