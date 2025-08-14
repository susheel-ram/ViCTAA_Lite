let charts = {}; // Store chart instances globally

function fetchUserInsights() {
    let userId = document.getElementById("user-select").value;
    if (!userId) {
        alert("Please select a user");
        return;
    }

    let csrfToken = document.querySelector('input[name="csrf_token"]').value;

    fetch("/get-user-insights", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken
        },
        body: JSON.stringify({ user_id: userId })
    })
    .then(response => response.json())
    .then(data => {
        console.log("📊 Received Data:", data);
        if (data.error) {
            alert(data.error);
            return;
        }
        renderCharts(data);
    })
    .catch(error => {
        console.error("❌ Fetch Error:", error);
        alert(`Error fetching user data: ${error.message}`);
    });
}

function renderCharts(data) {
    let labels = data.map(entry => 
        entry.last_check_timestamp ? new Date(entry.last_check_timestamp).toLocaleString() : "N/A"
    );

    let threats = data.map(entry => entry.threats_count || 0);
    let vulnerabilities = data.map(entry => entry.vulnerabilities_count || 0);
    let software = data.map(entry => entry.software_count || 0);
    let usbOpen = data.map(entry => entry.usb_device_open || 0);
    let usbClosed = data.map(entry => entry.usb_device_closed || 0);

    function handleChartClick(event, chart, datasetLabel) {
        let points = chart.getElementsAtEventForMode(event, 'nearest', { intersect: true }, true);
        if (points.length) {
            let index = points[0].index;
            let clickedData = data[index];

            let modalTitle = datasetLabel;
            let modalContent = "";

            if (datasetLabel === "Missing Patches") {
                let detectedThreats = clickedData.detected_threats ? JSON.parse(clickedData.detected_threats) : [];
                modalContent = detectedThreats.length ? detectedThreats.map(t => `⚠️ ${t}`).join("<br>") : "No threats detected.";
            } 
            else if (datasetLabel === "USB Devices") {
                let usbDevices = clickedData.usb_device_id ? JSON.parse(clickedData.usb_device_id) : [];
                modalContent = usbDevices.length 
                    ? usbDevices.map(usb => `🔌 Port: ${usb.port} - Status: ${usb.status}`).join("<br>") 
                    : "No USB devices detected.";
            }

            showPopup(modalTitle, modalContent);
        }
    }

    function createChart(ctx, label, dataset, color) {
        if (charts[label] instanceof Chart) {
            charts[label].destroy();
        }

        let chart = new Chart(ctx, {
            type: "bar",
            data: { 
                labels, 
                datasets: [{ label, data: dataset, backgroundColor: color }] 
            },
            options: { 
                responsive: true, 
                maintainAspectRatio: false,
                scales: {
                    x: {
                        ticks: {
                            display: false // Hide X-axis labels (timestamps)
                        }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1,
                            callback: function(value) {
                                if (Number.isInteger(value)) return value;
                                return null;
                            }
                        }
                    }
                },
                plugins: {
                    tooltip: {
                        callbacks: {
                            label: function(tooltipItem) {
                                let index = tooltipItem.dataIndex;
                                let timestamp = data[index].last_check_timestamp 
                                    ? new Date(data[index].last_check_timestamp).toLocaleString() 
                                    : "No Timestamp";
                                return `Count: ${tooltipItem.raw}, Time: ${timestamp}`;
                            }
                        }
                    }
                }
            }
            
        });

        ctx.canvas.onclick = (event) => handleChartClick(event, chart, label);
        charts[label] = chart;
    }

    // Create & update charts
    createChart(document.getElementById("threatChart").getContext("2d"), "Missing Patches", threats, "red");
    createChart(document.getElementById("vulnerabilityChart").getContext("2d"), "Vulnerabilities", vulnerabilities, "orange");
    createChart(document.getElementById("softwareChart").getContext("2d"), "Installed Software", software, "purple");

    // USB Devices Chart - Now shows both open and closed ports
    if (usbOpen.length || usbClosed.length) {
        if (charts["USB Devices"] instanceof Chart) {
            charts["USB Devices"].destroy();
        }

        let usbChart = new Chart(document.getElementById("usbChart").getContext("2d"), {
            type: "bar",
            data: {
                labels,
                datasets: [
                    { label: "USB Open", data: usbOpen, backgroundColor: "green" },
                    { label: "USB Closed", data: usbClosed, backgroundColor: "red" }
                ]
            },
            options: { 
                responsive: true, 
                maintainAspectRatio: false,
                scales: {
                    x: {
                        ticks: {
                            display: false // Hide X-axis labels (timestamps)
                        }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1,
                            callback: function(value) {
                                if (Number.isInteger(value)) return value;
                                return null;
                            }
                        }
                    }
                },
                plugins: {
                    tooltip: {
                        callbacks: {
                            label: function(tooltipItem) {
                                let index = tooltipItem.dataIndex;
                                let timestamp = data[index].last_check_timestamp 
                                    ? new Date(data[index].last_check_timestamp).toLocaleString() 
                                    : "No Timestamp";
                                return `Count: ${tooltipItem.raw}, Time: ${timestamp}`;
                            }
                        }
                    }
                }
            }
            
        });

        document.getElementById("usbChart").onclick = (event) => handleChartClick(event, usbChart, "USB Devices");
        charts["USB Devices"] = usbChart;
    }
}

// Function to show a popup modal
function showPopup(title, content) {
    let existingPopup = document.getElementById("dataPopup");
    if (existingPopup) {
        existingPopup.remove();
    }

    let popup = document.createElement("div");
    popup.id = "dataPopup";
    popup.innerHTML = `
        <div class="popup-overlay">
            <div class="popup-content">
                <span class="popup-close" onclick="closePopup()">&times;</span>
                <h2>${title}</h2>
                <p>${content}</p>
            </div>
        </div>
    `;

    document.body.appendChild(popup);
}

// Function to close the popup
function closePopup() {
    let popup = document.getElementById("dataPopup");
    if (popup) {
        popup.remove();
    }
}

// Inject CSS dynamically
const popupStyles = `
.popup-overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 999;
}
.popup-content {
    background: white;
    padding: 20px;
    border-radius: 8px;
    width: 400px;
    text-align: center;
    box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.3);
    position: relative;
}
.popup-close {
    position: absolute;
    top: 10px;
    right: 15px;
    font-size: 20px;
    cursor: pointer;
}
`;

// Append CSS to document head
let styleSheet = document.createElement("style");
styleSheet.type = "text/css";
styleSheet.innerText = popupStyles;
document.head.appendChild(styleSheet);

// Sample dummy data for default charts
// document.addEventListener("DOMContentLoaded", function () {
//     const sampleData = Array(6).fill().map((_, i) => ({
//         last_check_timestamp: new Date().toISOString(),
//         threats_count: 2,
//         vulnerabilities_count: 0,
//         software_count: 725,
//         usb_device_open: 0,
//         usb_device_closed: 2,
//         detected_threats: JSON.stringify(["Sample Threat 1", "Sample Threat 2"]),
//         usb_device_id: JSON.stringify([{ port: "USB1", status: "Closed" }, { port: "USB2", status: "Closed" }])
//     }));

//     renderCharts(sampleData);
// });

document.addEventListener("DOMContentLoaded", function () {
    const emptyData = Array(6).fill().map(() => ({
        last_check_timestamp: null,
        threats_count: 0,
        vulnerabilities_count: 0,
        software_count: 0,
        usb_device_open: 0,
        usb_device_closed: 0,
        detected_threats: JSON.stringify([]),
        usb_device_id: JSON.stringify([])
    }));

    renderCharts(emptyData);
});
