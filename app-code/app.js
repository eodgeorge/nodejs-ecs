require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const client = require('prom-client');

const { CloudWatchClient, PutMetricDataCommand } = require('@aws-sdk/client-cloudwatch');  //modular AWS SDK (v3)
const { 
    CloudWatchLogsClient, 
    CreateLogGroupCommand, 
    CreateLogStreamCommand, 
    PutLogEventsCommand, 
    DescribeLogGroupsCommand, 
    DescribeLogStreamsCommand 
} = require('@aws-sdk/client-cloudwatch-logs');
// const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');

const cloudWatchClient = new CloudWatchClient({
    region: process.env.AWS_REGION || 'eu-west-2',
    // credentials: {
    //     accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    //     secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    // },    
});

const app = express();
app.use(bodyParser.json());

// ==============================
const winston = require('winston');
require('winston-cloudwatch');
const { Transport } = require('winston');

const cloudWatchLogsClient = new CloudWatchLogsClient({
    region: process.env.AWS_REGION || 'eu-west-2',
    // credentials: {
    //     accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    //     secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    // },    
});

const logGroupName = process.env.LOG_GROUP_NAME || 'MyAppLogs';
const logStreamName = 'MyAppStream';

const ensureLogGroupAndStream = async () => {
    try {
        await cloudWatchLogsClient.send(new CreateLogGroupCommand({ logGroupName })); //// Create log group if not exists
        console.log(`Log group ${logGroupName} created.`); 
    } catch (err) {
        if (err.name !== 'ResourceAlreadyExistsException') {
            console.error('Error creating log group:', err);
            throw err;
        }
        console.log(`Log group ${logGroupName} already exists.`);
    }

    try {
        await cloudWatchLogsClient.send(new CreateLogStreamCommand({ logGroupName, logStreamName }));   // Create log stream if not exists
        console.log(`Log stream ${logStreamName} created.`);
    } catch (err) {
        if (err.name !== 'ResourceAlreadyExistsException') {
            console.error('Error creating log stream:', err);
            throw err;
        }
        console.log(`Log stream ${logStreamName} already exists.`);
    }
};

// Custom CloudWatch Transport for Winston
class CloudWatchTransport extends Transport {
    constructor(opts) {
        super(opts);
        this.cloudWatchLogsClient = opts.cloudWatchLogsClient;
        this.logGroupName = opts.logGroupName;
        this.logStreamName = opts.logStreamName;
        this.sequenceToken = null;  // For sequence token management
    }

    log(info, callback) {
        setImmediate(() => this.emit('logged', info)); // Ensure log event is emitted
        callback(); // Mark logging as done

        // Log message format
        const logMessage = {
            timestamp: new Date().toISOString(),
            message: info.message,
        };

        // Send log to CloudWatch
        this.sendToCloudWatch(logMessage);
    }

    // Send logs to CloudWatch Logs
    async sendToCloudWatch(logMessage) {
        try {
            const params = {
                logGroupName: this.logGroupName,
                logStreamName: this.logStreamName,
                logEvents: [
                    {
                        timestamp: Date.now(),
                        message: logMessage.message,
                    },
                ],
                sequenceToken: this.sequenceToken, // Sequence token is managed here
            };

            // Send log events to CloudWatch
            const { nextSequenceToken } = await this.cloudWatchLogsClient.send(new PutLogEventsCommand(params));
            this.sequenceToken = nextSequenceToken;  // Update the sequence token
        } catch (err) {
            console.error('Error sending logs to CloudWatch:', err);
        }
    }
}

// Initialize logger with CloudWatch transport
const logger = winston.createLogger({
    level: 'info',
    transports: [
        new winston.transports.Console({ format: winston.format.json() }),
        new CloudWatchTransport({
            cloudWatchLogsClient: cloudWatchLogsClient,
            logGroupName: logGroupName,
            logStreamName: logStreamName,
        }),
    ],
});

// Ensure log group and stream exist before logging
ensureLogGroupAndStream()
    .then(() => {
        console.log('Logger is ready!');
        // Now logging is ready and can be used
    })
    .catch((err) => {
        console.error('Logger initialization failed:', err);
    });
// ===============================

app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = (Date.now() - start) / 1000;
        const logMessage = `[${new Date().toISOString()}] ${req.method} ${req.path} - ${res.statusCode} (${duration}s)`;
        
        if (process.env.LOGGING_ENABLED === 'true') {
            logToFile(logMessage);
        }
    });
    next();
});

// ===================

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASS,
    port: process.env.DB_PORT,
});

const collectDefaultMetrics = client.collectDefaultMetrics;
collectDefaultMetrics();

const httpRequestCounter = new client.Counter({
    name: 'http_requests_total',
    help: 'Total number of HTTP requests',
    labelNames: ['method', 'route', 'status'],
});

const httpRequestDuration = new client.Histogram({
    name: 'http_request_duration_seconds',
    help: 'Duration of HTTP requests in seconds',
    labelNames: ['method', 'route', 'status'],
    buckets: [0.1, 0.5, 1, 2, 5], 
});

const dbQueryDuration = new client.Histogram({
    name: 'db_query_duration_seconds',
    help: 'Duration of database queries',
    labelNames: ['query'],
    buckets: [0.01, 0.1, 0.5, 1, 2, 5],
});

app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = (Date.now() - start) / 1000;
        httpRequestCounter.inc({ method: req.method, route: req.path, status: res.statusCode });
        httpRequestDuration.observe({ method: req.method, route: req.path, status: res.statusCode }, duration);

        if (process.env.LOGGING_ENABLED === 'true') {
            logger.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - ${res.statusCode} (${duration}s)`);
        }
    });
    next();
});

const queryWithMetrics = async (query, params) => {
    const start = Date.now();
    try {
        return await pool.query(query, params);
    } finally {
        const duration = (Date.now() - start) / 1000;
        dbQueryDuration.observe({ query }, duration);
    }
};

const checkDatabaseConnection = async () => {
    try {
        await pool.query('SELECT 1'); 
        logger.log('info', 'Database is ready!');
    } catch (err) {
        logger.error('Database connection failed:');
        process.exit(1);
    }
};

const initializeDatabase = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS data (
                id SERIAL PRIMARY KEY,
                value TEXT NOT NULL
            );
        `);
        console.log('Table checked/created successfully.');
    } catch (err) {
        console.error('Error ensuring table existence:', err);
        process.exit(1);
    }
};
//         logger.log({ message: 'Table checked/created successfully.' });
//     } catch (err) {
//         logger.error('Error ensuring table existence:', err);
//         process.exit(1);
//     }
// }; ({ message: 'Table checked/created successfully.' });

app.use(async (req, res, next) => {
    try {
        await pool.query('SELECT 1');
        next();
    } catch (err) {
        logger.error('Database health check failed:', err);
        res.status(503).json({ error: 'Database unavailable' });
    }
});

app.get('/data', async (req, res) => {
    const start = Date.now();
    try {
        const result = await pool.query('SELECT * FROM data');
        res.json(result.rows);
    } catch (err) {
        logger.error("Database error:", err);
        res.status(500).json({ error: err.message });
    } finally {
        const duration = (Date.now() - start) / 1000;
        dbQueryDuration.observe({ query: 'SELECT * FROM data' }, duration);
    }
});

app.post('/data', async(req, res) => {
    try {
        const { value } = req.body;
        if (!value) {
            return res.status(400).json({ error: 'Missing required field: value' });
        }
        await pool.query('INSERT INTO data (value) VALUES ($1)', [value]);
        res.status(201).json({ message: 'Data inserted successfully' });
    } catch (err) {
        logger.error('Database error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.status(200).json({ status: 'OK' });
    } catch (err) {
        res.status(503).json({ error: 'Database unavailable' });
    }
});

app.get('/metrics', async (req, res) => {
    res.set('Content-Type', client.register.contentType);
    res.end(await client.register.metrics());
});

// ========================
const logMetricsToCloudWatch = async () => {
    const metrics = [
        {
            MetricName: 'TotalHttpRequests',
            Dimensions: [{ Name: 'Application', Value: 'MyApp' }],
            Unit: 'Count',
            Value: httpRequestCounter.hashMap['method:GET,route:/data,status:200']?.value || 0,
        },
        {
            MetricName: 'DatabaseQueryDuration',
            Dimensions: [{ Name: 'Application', Value: 'MyApp' }],
            Unit: 'Seconds',
            Value: dbQueryDuration.hashMap['query:SELECT * FROM data']?.value || 0,
        },
    ];

    try {
        await cloudWatchClient.send(new PutMetricDataCommand({
            Namespace: 'ApplicationMetrics',
            MetricData: metrics,
        }));
        logger.info({ message: "Metrics pushed to CloudWatch" });
    } catch (error) {
        logger.error({ message:'Error pushing metrics to CloudWatch:', error });
    }
};

setInterval(logMetricsToCloudWatch, 60000);

const startServer = async () => {
    await checkDatabaseConnection();
    await initializeDatabase();
    
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, '0.0.0.0', () => {
        logger.log('info', `Server running on port ${PORT}`);
    });
};

startServer();



// app.listen(3000, '0.0.0.0', () => console.log('Server running'));
