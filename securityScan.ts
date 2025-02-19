
import dotenv from 'dotenv';
import axios from 'axios';
import * as fs from 'fs';
import * as path from 'path';
import { exec, execSync } from 'child_process';
import unzipper from 'unzipper';
import * as readline from 'readline';
import { generateHTML } from '../nilgiriSecurity/generateReport';

dotenv.config();

const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
// const OPENAI_API_ENDPOINT = process.env.OPENAI_API_ENDPOINT;
const OPENAI_API_ENDPOINT = process.env.OPENAI_API_ENDPOINT!;

// Create readline interface
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

// Promisify readline question
const question = (query: string): Promise<string> => {
    return new Promise((resolve) => {
        rl.question(query, (answer) => {
            resolve(answer);
        });
    });
};

// Function to get OpenAI GPT Response
async function getGPTResponse(systemPrompt: string, userPrompt: string) {
    try {
        const response = await axios.post(
            OPENAI_API_ENDPOINT,  
            {
                messages: [
                    { role: "system", content: systemPrompt },
                    { role: "user", content: userPrompt }
                ],
                temperature: 0.3,
                // model: "gpt-4" // Update with the appropriate model
            },
            {
                headers: {
                    "Content-Type": "application/json",
                    "api-key": `${OPENAI_API_KEY}`,
                    "Region": "eastus2"
                }
            }
        );
        return response.data.choices[0].message.content.trim();
    } catch (error) {
        if (axios.isAxiosError(error)) {
            console.error("Error while calling OpenAI API:", error.response ? error.response.data : error.message);
        } else {
            console.error("General error:", error instanceof Error ? error.message : 'Unknown error');
        }
        throw error; 
    }
}

// Function to parse and clean JSON data
function parseJsonFile(filePath: string) {
    try {
        const fileContent = fs.readFileSync(filePath, 'utf8');
        
        // Clean the JSON content
        const cleanedContent = fileContent
            .split('\n')
            .filter(line => line.trim().startsWith('{'))
            .map(line => {
                try {
                    JSON.parse(line);
                    return line;
                } catch {
                    return null;
                }
            })
            .filter(line => line !== null)
            .join('\n');

        // Parse each line as a separate JSON object
        const results = cleanedContent
            .split('\n')
            .map(line => JSON.parse(line))
            .filter(item => item !== null);

        // Create a summary object
        const summary = {
            totalRequests: results.length,
            statusCodes: {} as Record<string, number>,
            findings: results.map(result => ({
                url: result.url || result.target,
                status: result.status_code || result.status,
                contentLength: result.content_length || result.length,
                contentType: result.content_type || result.type
            }))
        };

        // Count status codes
        results.forEach(result => {
            const status = result.status_code || result.status;
            summary.statusCodes[status] = (summary.statusCodes[status] || 0) + 1;
        });

        return summary;
    } catch (error) {
        console.error('Error parsing JSON file:', error);
        // Return a basic structure if parsing fails
        return {
            totalRequests: 0,
            statusCodes: {},
            findings: []
        };
    }
}

async function analyzeWithOpenAI(scanData: any) {
    try {
        const systemPrompt = 'You are a security expert specializing in analyzing vulnerability scan reports and generating human-readable summaries. Focus on identifying the most relevant findings, categorizing them by severity, and highlighting critical security risks. The output should be in an HTML report format that is visually structured and easy to understand, with sections like Summary, Key Findings, Detailed Results, and Recommendations.';
        
        const userPrompt = `Please analyze the following Feroxbuster scan results and generate a meaningful HTML report. Include the following sections:

                            Scan Summary:

                            Total number of requests
                            Distribution of status codes (200, 403, 404, etc.)
                            Common content types found
                            Key Findings:

                            Notable URLs with status codes like 200 (successful requests) and 403 (forbidden)
                            Potential sensitive files or directories discovered (e.g., admin panels, backup files)
                            Duplicate or common patterns in the results
                            Detailed Results:

                            A table listing discovered URLs with their status codes, content length, and content type.
                            Recommendations:

                            Suggestions for improving security based on the findings.
                            Example Input: Feroxbuster scan results in JSON format.
                            Example Output: Clean, organized HTML report with meaningful insights and actionable recommendations.
            Total Requests: ${scanData.totalRequests}
            Status Code Distribution: ${JSON.stringify(scanData.statusCodes)}
            Notable Findings: ${scanData.findings.length > 0 ? JSON.stringify(scanData.findings.slice(0, 5)) : 'None'}`;

        return await getGPTResponse(systemPrompt, userPrompt);
    } catch (error) {
        console.error('Error analyzing with OpenAI:', error);
        return `<table border="1">
                  <tr>
                    <th>Error</th>
                    <td>Failed to generate AI analysis. Please check the logs.</td>
                  </tr>
                </table>`;
    }
}

async function downloadFeroxbuster() {
    console.log("Downloading Feroxbuster...");
    const url = "https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-windows-feroxbuster.exe.zip";
    const response = await axios.get(url, { responseType: 'arraybuffer' });
    fs.writeFileSync("feroxbuster.zip", response.data);
    console.log("Download complete!");
}

// Unzip Feroxbuster
async function unzipFeroxbuster() {
    console.log("Unzipping Feroxbuster...");
    return new Promise<void>((resolve) => {
        fs.createReadStream("feroxbuster.zip")
            .pipe(unzipper.Extract({ path: "feroxbuster" }))
            .on('close', () => {
                console.log("Unzipping complete!");
                resolve();
            });
    });
}

// Run Feroxbuster
function runFeroxbuster(url: string, wordlistPath: string) {
    const feroxbusterPath = path.join("feroxbuster", "feroxbuster.exe");
    const jsonReportPath = "feroxbuster_report.json";

    // Delete old JSON report if it exists
    if (fs.existsSync(jsonReportPath)) {
        console.log("Deleting old report...");
        fs.unlinkSync(jsonReportPath);
    }

    const command = `${feroxbusterPath} -u ${url} -w ${wordlistPath} --json -o ${jsonReportPath}`;
    console.log(`Running Feroxbuster: ${command}`);

    execSync(command, { stdio: 'inherit' });

    // Ensure file exists after execution
    if (!fs.existsSync(jsonReportPath)) {
        throw new Error("Feroxbuster did not generate the expected JSON report.");
    }
}

// Generate Reports
async function generateReports() {
    const jsonReportPath = "feroxbuster_report.json";
    const securityReportPath = "security_analysis.html";

    if (!fs.existsSync(jsonReportPath)) {
        console.error("Error: JSON report file not found!");
        return;
    }

    // Parse the JSON data
    console.log("Parsing scan results...");
    const scanData = parseJsonFile(jsonReportPath);

    // Get AI analysis
    console.log("Analyzing results with OpenAI...");
    const aiAnalysis = await analyzeWithOpenAI(scanData);
    console.log("AI Analysis Response:", aiAnalysis);


    // Generate HTML Report
    const htmlReport = generateHTML(scanData, aiAnalysis);
    
    fs.writeFileSync(securityReportPath, htmlReport);
    console.log(`Security analysis report generated: ${securityReportPath}`);
}

// Main execution
async function main() {
    try {
        if (!OPENAI_API_KEY || !OPENAI_API_ENDPOINT) {
            throw new Error('OPENAI_API_KEY or OPENAI_API_ENDPOINT environment variable is not set');
        }

        // Check if Feroxbuster exists
        if (!fs.existsSync("feroxbuster")) {
            await downloadFeroxbuster();
            await unzipFeroxbuster();
        }

        const url = await question("Enter the URL of the website to scan: ");
        
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            throw new Error('Invalid URL. Please include http:// or https://');
        }

        // Download wordlist
        const wordlistUrl = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt";
        const wordlistPath = "common.txt";

        if (!fs.existsSync(wordlistPath)) {
            console.log("Downloading wordlist...");
            const response = await axios.get(wordlistUrl);
            fs.writeFileSync(wordlistPath, response.data);
            console.log("Wordlist downloaded.");
        }

        // Run Feroxbuster
        runFeroxbuster(url, wordlistPath);

        // Generate reports
        await generateReports();

    } catch (error) {
        console.error("An error occurred:", error instanceof Error ? error.message : String(error));
    } finally {
        rl.close();
    }
}

main();