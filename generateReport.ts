// export const generateHTML = (scanData: any, aiAnalysis: any,) => {
//     const htmlReport = `
// <!DOCTYPE html>
// <html>
// <head>
//     <title>Security Scan Analysis Report</title>
//     <style>
//         body {
//             font-family: Arial, sans-serif;
//             line-height: 1.6;
//             max-width: 1200px;
//             margin: 0 auto;
//             padding: 20px;
//         }
//         h1, h2 {
//             color: #2c3e50;
//         }
//         .summary {
//             background-color: #f8f9fa;
//             padding: 20px;
//             border-radius: 5px;
//             margin-bottom: 20px;
//         }
//         table {
//             width: 100%;
//             border-collapse: collapse;
//             margin: 20px 0;
//         }
//         th, td {
//             border: 1px solid #ddd;
//             padding: 12px;
//             text-align: left;
//         }
//         th {
//             background-color: #f8f9fa;
//             color: #2c3e50;
//         }
//     </style>
// </head>
// <body>
//     <h1>Security Scan Analysis Report</h1>
    
//     <div class="summary">
//         <h2>Scan Summary</h2>
//         <p>Total Requests: ${scanData.totalRequests}</p>
//         <p>Status Codes Distribution:</p>
//         <ul>
//             ${Object.entries(scanData.statusCodes)
//             .map(([code, count]) => `<li>Status ${code}: ${count} requests</li>`)
//             .join('\n')}
//         </ul>
//     </div>

//     <h2>AI Security Analysis</h2>
//     ${aiAnalysis}

//     <h2>Detailed Findings</h2>
//     <table border="1">
//         <tr>
//             <th>URL</th>
//             <th>Status</th>
//             <th>Content Length</th>
//             <th>Content Type</th>
//         </tr>
//         ${scanData.findings
//             .map((finding: any) => `
//                 <tr>
//                     <td>${finding.url}</td>
//                     <td>${finding.status}</td>
//                     <td>${finding.contentLength}</td>
//                     <td>${finding.contentType || 'N/A'}</td>
//                 </tr>
//             `)
//             .join('\n')}
//     </table>
// </body>
// </html>`;

//     return htmlReport;
// }   
   



export const generateHTML = (scanData: any, aiAnalysis: any) => {
    const htmlReport = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Analysis Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: auto; padding: 20px; }
        h1, h2 { color: #2c3e50; }
        .summary, .key-findings, .detailed-results, .recommendations { margin-bottom: 40px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f8f9fa; color: #2c3e50; }
        .high-risk { background-color: #ffcccc; } /* Red */
        .medium-risk { background-color: #ffecb3; } /* Yellow */
        .low-risk { background-color: #d9f7be; } /* Green */
        .collapsible { cursor: pointer; padding: 10px; background: #eee; border: none; text-align: left; width: 100%; font-size: 16px; }
        .content { display: none; padding: 10px; border-left: 2px solid #ccc; }
    </style>
</head>
<body>

    <h1>Security Scan Analysis Report</h1>

    <div class="summary">
        <h2>Scan Summary</h2>
        <p><strong>Total Requests:</strong> ${scanData.totalRequests}</p>
        <p><strong>Status Code Distribution:</strong></p>
        <canvas id="statusChart"></canvas>
    </div>

    <div class="key-findings">
        <h2>Key Findings</h2>
        ${aiAnalysis}
    </div>

    <h2>Detailed Findings</h2>
    <button class="collapsible">Show Findings</button>
    <div class="content">
        <table>
            <thead>
                <tr>
                    <th>Finding Type</th>
                    <th>Risk Level</th>
                    <th>Affected URL</th>
                    <th>Evidence</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
                ${scanData.findings.map((finding: any) => {
                    let riskClass = "low-risk";
                    let riskLevel = "Low";

                    if (finding.status === 403) { riskClass = "medium-risk"; riskLevel = "Medium"; }
                    if (finding.status === 200 && finding.url.includes("admin")) { riskClass = "high-risk"; riskLevel = "High"; }

                    return `
                        <tr class="${riskClass}">
                            <td>Exposed Endpoint</td>
                            <td>${riskLevel}</td>
                            <td>${finding.url}</td>
                            <td>${finding.contentLength}</td>
                            <td>Restrict access, implement authentication</td>
                        </tr>
                    `;
                }).join("\n")}
            </tbody>
        </table>
    </div>

    <script>
        // Status Code Chart
        const ctx = document.getElementById('statusChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ${JSON.stringify(Object.keys(scanData.statusCodes))},
                datasets: [{
                    label: 'Status Codes',
                    data: ${JSON.stringify(Object.values(scanData.statusCodes))},
                    backgroundColor: ['green', 'blue', 'orange', 'red']
                }]
            }
        });

        // Collapsible Section
        document.querySelector(".collapsible").addEventListener("click", function() {
            this.classList.toggle("active");
            const content = this.nextElementSibling;
            content.style.display = content.style.display === "block" ? "none" : "block";
        });
    </script>

</body>
</html>`;

    return htmlReport;
};
