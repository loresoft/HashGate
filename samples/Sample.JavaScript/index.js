import { HmacClient } from './hmac-client.js';
import readline from 'readline';
import dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

/**
 * Interactive console application demonstrating HMAC authentication
 */
class SampleApp {
    constructor() {
        // Validate required environment variables
        this.validateEnvironmentVariables();

        // Configuration from environment variables
        this.client = new HmacClient(
            process.env.HMAC_CLIENT_ID,
            process.env.HMAC_SECRET,
            process.env.API_BASE_URL
        );

        this.rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        this.commands = new Map([
            ['0', { description: 'Hello World [GET /]', action: () => this.helloCommand() }],
            ['1', { description: 'Get Weather [GET /weather]', action: () => this.weatherCommand() }],
            ['2', { description: 'Get Users [GET /users]', action: () => this.usersCommand() }],
            ['3', { description: 'Post User [POST /users]', action: () => this.postUserCommand() }],
            ['4', { description: 'Get Addresses [GET /addresses]', action: () => this.addressesCommand() }],
            ['5', { description: 'Post Address [POST /addresses]', action: () => this.postAddressCommand() }],
        ]);
    }

    /**
     * Validates that all required environment variables are set
     */
    validateEnvironmentVariables() {
        const requiredVars = ['HMAC_CLIENT_ID', 'HMAC_SECRET', 'API_BASE_URL'];
        const missingVars = requiredVars.filter(varName => !process.env[varName]);

        if (missingVars.length > 0) {
            console.error('Error: Missing required environment variables:');
            missingVars.forEach(varName => {
                console.error(`  - ${varName}`);
            });
            console.error('\nPlease ensure you have a .env file with the required variables.');
            console.error('See .env.example for the expected format.');
            process.exit(1);
        }
    }

    /**
     * Starts the interactive console application
     */
    async start() {
        console.log('Starting JavaScript HMAC Authentication Sample Client...\n');
        console.log(`Client ID: ${process.env.HMAC_CLIENT_ID}`);
        console.log(`API Base URL: ${process.env.API_BASE_URL}\n`);

        // Disable TLS certificate validation for development if configured
        if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
            console.log('Warning: TLS certificate validation is disabled for development\n');
        }

        await this.showMenu();
    }

    /**
     * Displays the menu and handles user input
     */
    async showMenu() {
        while (true) {
            console.log('Test HTTP Client');
            console.log('');

            for (const [key, cmd] of this.commands) {
                console.log(`  ${key} ${cmd.description}`);
            }

            console.log('  Q Quit');
            console.log('');

            const input = await this.prompt('Enter command: ');

            if (input.toLowerCase() === 'q') {
                console.log('Goodbye!');
                this.rl.close();
                process.exit(0);
            }

            await this.runCommand(input);
            console.log(''); // Add spacing
        }
    }

    /**
     * Executes a command based on user input
     * @param {string} input - User input
     */
    async runCommand(input) {
        try {
            const command = this.commands.get(input);
            if (command) {
                await command.action();
            } else {
                console.log(`Unknown Command '${input}'`);
            }
        } catch (error) {
            console.error('Error: ' + error.message);
            console.error(error.stack);
        }
    }

    /**
     * Prompts user for input
     * @param {string} question - Question to ask
     * @returns {Promise<string>} User input
     */
    prompt(question) {
        return new Promise((resolve) => {
            this.rl.question(question, resolve);
        });
    }

    /**
     * Outputs response details
     * @param {Response} response - Fetch response
     */
    async outputResponse(response) {
        console.log(`${response.status} ${response.statusText}`);

        const contentType = response.headers.get('content-type');
        let responseText = await response.text();

        if (contentType && contentType.includes('application/json') && responseText) {
            try {
                const jsonData = JSON.parse(responseText);
                console.log(JSON.stringify(jsonData, null, 2));
            } catch {
                console.log(responseText);
            }
        } else {
            console.log(responseText || '(empty response)');
        }
    }

    /**
     * Command: Hello World
     */
    async helloCommand() {
        console.log('Making GET request to /...');
        const response = await this.client.get('/');
        await this.outputResponse(response);
    }

    /**
     * Command: Get Weather
     */
    async weatherCommand() {
        console.log('Making GET request to /weather...');
        const response = await this.client.get('/weather');
        await this.outputResponse(response);
    }

    /**
     * Command: Get Users (requires authentication)
     */
    async usersCommand() {
        console.log('Making GET request to /users (authenticated)...');
        const response = await this.client.get('/users');
        await this.outputResponse(response);
    }

    /**
     * Command: Post User (requires authentication)
     */
    async postUserCommand() {
        console.log('Making POST request to /users (authenticated)...');

        const sampleUser = {
            first: 'John',
            last: 'Doe',
            email: 'john.doe@example.com'
        };

        const response = await this.client.post('/users', sampleUser);
        await this.outputResponse(response);
    }

    /**
     * Command: Get Addresses (requires authentication)
     */
    async addressesCommand() {
        console.log('Making GET request to /addresses (authenticated)...');
        const response = await this.client.get('/addresses');
        await this.outputResponse(response);
    }

    /**
     * Command: Post Address (requires authentication)
     */
    async postAddressCommand() {
        console.log('Making POST request to /addresses (authenticated)...');

        const sampleAddress = {
            line1: '123 Main Street',
            line2: 'Apt 4B',
            city: 'New York',
            state: 'NY',
            zipcode: '10001'
        };

        const response = await this.client.post('/addresses', sampleAddress);
        await this.outputResponse(response);
    }
}

// Start the application
const app = new SampleApp();
app.start().catch(console.error);
