import { HmacClient } from './hmac-client.js';

/**
 * Simple demonstration of HMAC authentication client
 * This example shows how to make authenticated requests to the Sample.MinimalApi
 *
 * Prerequisites:
 * 1. Start the Sample.MinimalApi project: cd samples/Sample.MinimalApi && dotnet run
 * 2. Run this demo: node demo.js
 */

async function demonstrateHmacAuthentication() {
    console.log('HMAC Authentication Demo\n');

    // Disable TLS certificate validation for development
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

    // Create HMAC client with sample configuration
    const client = new HmacClient(
        'SampleClient',                    // Client ID (matches server config)
        'sample-client-secret',            // Secret key (matches server config)
        'https://localhost:7134'           // API base URL
    );

    try {
        console.log('1. Testing public endpoint (Hello World)...');
        const helloResponse = await client.get('/');
        const helloText = await helloResponse.text();
        console.log(`   Status: ${helloResponse.status}`);
        console.log(`   Response: ${helloText}\n`);

        console.log('2. Testing public endpoint (Weather data)...');
        const weatherResponse = await client.get('/weather');
        const weatherData = await weatherResponse.json();
        console.log(`   Status: ${weatherResponse.status}`);
        console.log(`   Weather count: ${weatherData.length} items\n`);

        console.log('3. Testing authenticated endpoint (Users)...');
        const usersResponse = await client.get('/users');

        if (usersResponse.status === 200) {
            const usersData = await usersResponse.json();
            console.log(`   Status: ${usersResponse.status} (Authentication successful!)`);
            console.log(`   Users count: ${usersData.length} items\n`);
        } else {
            console.log(`   Status: ${usersResponse.status} (Authentication failed)`);
            const errorText = await usersResponse.text();
            console.log(`   Error: ${errorText}\n`);
        }

        console.log('4. Testing authenticated POST endpoint (Create User)...');
        const newUser = {
            first: 'Demo',
            last: 'User',
            email: 'demo.user@example.com'
        };

        const createUserResponse = await client.post('/users', newUser);

        if (createUserResponse.status === 200) {
            const createdUser = await createUserResponse.json();
            console.log(`   Status: ${createUserResponse.status} (Authentication successful!)`);
            console.log(`   Created user: ${createdUser.firstName} ${createdUser.lastName}\n`);
        } else {
            console.log(`   Status: ${createUserResponse.status} (Authentication failed)`);
            const errorText = await createUserResponse.text();
            console.log(`   Error: ${errorText}\n`);
        }
    } catch (error) {
        console.error('Demo failed:', error.message);

        if (error.code === 'ECONNREFUSED') {
            console.error('\nMake sure the Sample.MinimalApi is running:');
            console.error('   cd samples/Sample.MinimalApi');
            console.error('   dotnet run');
        }
    }

    console.log('Demo completed!');
    console.log('\nFor interactive testing, run: npm start');
}

// Run the demonstration
demonstrateHmacAuthentication();
