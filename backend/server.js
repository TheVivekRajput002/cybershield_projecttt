const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('rate-limiter-flexible');
const winston = require('winston');
require('dotenv').config({ path: path.join(__dirname, '../.env') });
const { v4: uuidv4 } = require('uuid');

// Import custom modules
const APKAnalyzer = require('./services/apkAnalyzer');
const SecurityScanner = require('./services/securityScanner');
const DatabaseService = require('./services/database');
const ThreatIntelligence = require('./services/threatIntelligence');

const app = express();
const PORT = process.env.PORT || 3000;

// Logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console()
  ]
});

// Rate limiting
const rateLimiter = new rateLimit.RateLimiterMemory({
  keyPrefix: 'apk_scan',
  points: 10, // 10 requests
  duration: 60, // per 60 seconds
});

// Rate limiting middleware
const rateLimitMiddleware = async (req, res, next) => {
  try {
    await rateLimiter.consume(req.ip);
    next();
  } catch (rejRes) {
    return res.status(429).json({
      error: 'Too many requests',
      retryAfter: Math.round(rejRes.msBeforeNext) || 1000
    });
  }
};

// CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  methods: ['GET', 'POST'],
  maxAge: 86400
}));

// Body parsing middleware - IMPORTANT: Order matters!
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Security middleware
app.use(helmet());

// File upload configuration - Fixed paths and error handling
const uploadDir = path.join(__dirname, 'uploads');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1E9)}.apk`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 230686720, // 220MB
    files: 1
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/vnd.android.package-archive' ||
        file.originalname.toLowerCase().endsWith('.apk')) {
      cb(null, true);
    } else {
      cb(new Error('Only APK files are allowed'), false);
    }
  }
});

// Initialize services
let apkAnalyzer, securityScanner, threatIntel;

async function initializeServices() {
  try {
    await fs.mkdir(uploadDir, { recursive: true });
    await fs.mkdir('logs', { recursive: true });
    await fs.mkdir('data', { recursive: true });

    apkAnalyzer = new APKAnalyzer();
    securityScanner = new SecurityScanner();
    threatIntel = new ThreatIntelligence();

    await threatIntel.initialize();

    logger.info('All services initialized successfully');
  } catch (error) {
    logger.error('Failed to initialize services:', error);
    process.exit(1);
  }
}

// Error handling middleware for multer
const handleUploadError = (error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({
        success: false,
        error: 'File too large',
        message: 'APK file must be smaller than 220MB'
      });
    }
    if (error.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({
        success: false,
        error: 'Invalid file',
        message: 'Only APK files are allowed'
      });
    }
  }
  
  if (error.message === 'Only APK files are allowed') {
    return res.status(400).json({
      success: false,
      error: 'Invalid file type',
      message: 'Only APK files are allowed'
    });
  }

  return res.status(500).json({
    success: false,
    error: 'Upload failed',
    message: error.message
  });
};

// Risk calculation function
function calculateRiskLevel(scanResult) {
  const { basic, security, banking, threats, ml } = scanResult.analysis;
  let riskScore = 0;
  let confidence = 0;
  let detectedThreats = [];
  let recommendations = [];

  // Basic APK analysis scoring
  if (basic?.isDebuggable) riskScore += 10;
  if (basic?.allowBackup) riskScore += 5;
  if (basic?.hasNativeCode) riskScore += 5;

  // Security analysis scoring
  if (security?.maliciousPermissions > 0) riskScore += security.maliciousPermissions * 15;
  if (security?.suspiciousStrings > 0) riskScore += security.suspiciousStrings * 10;
  if (security?.obfuscated) riskScore += 20;
  if (security?.packedExecutables > 0) riskScore += security.packedExecutables * 25;

  // Banking characteristics scoring
  if (banking?.imitatesBankingApp) {
    riskScore += 50;
    detectedThreats.push('Banking app impersonation detected');
  }
  if (banking?.hasPhishingIndicators) {
    riskScore += 40;
    detectedThreats.push('Phishing indicators found');
  }
  if (banking?.suspiciousNetworking) {
    riskScore += 30;
    detectedThreats.push('Suspicious network behavior');
  }

  // Threat intelligence scoring
  if (threats?.knownMalware) {
    riskScore += 100;
    detectedThreats.push('Known malware signature detected');
  }
  if (threats?.suspiciousDomains > 0) {
    riskScore += threats.suspiciousDomains * 20;
    detectedThreats.push('Communicates with suspicious domains');
  }

  // ML detection scoring (if available)
  if (ml && ml.malwareProbability > 0.7) {
    riskScore += ml.malwareProbability * 50;
    detectedThreats.push('AI-based malware detection triggered');
  }

  // Determine risk level and fake status
  let level, isFake;
  if (riskScore >= 80) {
    level = 'critical';
    isFake = true;
    confidence = Math.min(95, 70 + riskScore * 0.3);
  } else if (riskScore >= 50) {
    level = 'high';
    isFake = riskScore >= 60;
    confidence = Math.min(85, 60 + riskScore * 0.4);
  } else if (riskScore >= 25) {
    level = 'medium';
    isFake = false;
    confidence = Math.min(75, 50 + riskScore * 0.5);
  } else if (riskScore >= 10) {
    level = 'low';
    isFake = false;
    confidence = Math.min(65, 40 + riskScore * 0.6);
  } else {
    level = 'minimal';
    isFake = false;
    confidence = Math.min(60, 30 + riskScore);
  }

  // Generate recommendations
  if (isFake) {
    recommendations.push('DO NOT INSTALL - This appears to be a fake banking application');
    recommendations.push('Report this APK to your bank and security authorities');
  }
  if (security?.maliciousPermissions > 0) {
    recommendations.push('Review app permissions carefully before installation');
  }
  if (banking?.suspiciousNetworking) {
    recommendations.push('This app may transmit sensitive data to unauthorized servers');
  }

  return {
    level,
    isFake,
    confidence: Math.round(confidence),
    threats: detectedThreats,
    recommendations
  };
}

function generateScanSummary(scanResult) {
  const { riskLevel, isFake, threats } = scanResult;

  if (isFake) {
    return `DANGER: This APK appears to be a fake banking application with ${riskLevel} risk level. ${threats.length} threats detected.`;
  } else {
    return `This APK appears legitimate with ${riskLevel} risk level. ${threats.length} potential issues found.`;
  }
}

// Fixed APK scanning endpoint
app.post('/api/scan-apk', rateLimitMiddleware, (req, res, next) => {
  upload.single('apk')(req, res, (err) => {
    if (err) {
      return handleUploadError(err, req, res, next);
    }
    next();
  });
}, async (req, res) => {
  const scanId = uuidv4();
  let filePath = null;
  
  try {
    // Check if services are ready
    if (!apkAnalyzer || !securityScanner || !threatIntel) {
      return res.status(503).json({
        success: false,
        error: 'Services not ready',
        message: 'Server is still initializing. Please try again in a moment.'
      });
    }

    // Check if file was uploaded
    if (!req.file) {
      return res.status(400).json({ 
        success: false,
        error: 'No APK file provided',
        message: 'Please select an APK file to upload'
      });
    }

    filePath = req.file.path;
    const filename = req.file.originalname;
    
    logger.info(`Starting APK scan - ID: ${scanId}, File: ${filename}, Path: ${filePath}`);

    // Verify file exists
    try {
      await fs.access(filePath);
    } catch (accessError) {
      logger.error(`File not accessible: ${filePath}`, accessError);
      return res.status(400).json({
        success: false,
        error: 'File upload failed',
        message: 'Uploaded file is not accessible'
      });
    }

    // Initialize scan result
    const scanResult = {
      scanId,
      filename: filename,
      timestamp: new Date(),
      riskLevel: 'unknown',
      isFake: false,
      confidence: 0,
      threats: [],
      analysis: {},
      recommendations: []
    };

    // Step 1: Basic APK Analysis
    logger.info(`${scanId}: Starting basic APK analysis`);
    const apkInfo = await apkAnalyzer.analyzeAPK(filePath);
    scanResult.analysis.basic = apkInfo;

    // Step 2: Security Scanning
    logger.info(`${scanId}: Starting security scan`);
    const securityResults = await securityScanner.scanAPK(filePath, apkInfo);
    scanResult.analysis.security = securityResults;

    // Step 3: Banking App Detection
    logger.info(`${scanId}: Checking banking app characteristics`);
    const bankingAnalysis = await apkAnalyzer.analyzeBankingCharacteristics(filePath, apkInfo);
    scanResult.analysis.banking = bankingAnalysis;

    // Step 4: Threat Intelligence Check
    logger.info(`${scanId}: Running threat intelligence checks`);
    const threatResults = await threatIntel.checkAPK(apkInfo);
    scanResult.analysis.threats = threatResults;

    // Step 5: Machine Learning Detection (if available)
    if (process.env.ML_DETECTION_ENABLED === 'true') {
      logger.info(`${scanId}: Running ML detection`);
      try {
        const mlResults = await securityScanner.mlDetection(filePath, apkInfo);
        scanResult.analysis.ml = mlResults;
      } catch (mlError) {
        logger.warn(`${scanId}: ML detection failed:`, mlError);
        scanResult.analysis.ml = { error: 'ML detection unavailable' };
      }
    }

    // Calculate final risk assessment
    const riskAssessment = calculateRiskLevel(scanResult);
    scanResult.riskLevel = riskAssessment.level;
    scanResult.isFake = riskAssessment.isFake;
    scanResult.confidence = riskAssessment.confidence;
    scanResult.threats = riskAssessment.threats;
    scanResult.recommendations = riskAssessment.recommendations;

    logger.info(`${scanId}: Scan completed - Risk: ${scanResult.riskLevel}, Fake: ${scanResult.isFake}`);

    // Send response before cleanup
    res.json({
      success: true,
      scanId,
      result: {
        riskLevel: scanResult.riskLevel,
        isFake: scanResult.isFake,
        confidence: scanResult.confidence,
        threats: scanResult.threats,
        recommendations: scanResult.recommendations,
        summary: generateScanSummary(scanResult)
      },
      metadata: {
        apkInfo,
        securityResults,
        threatResults,
        timestamp: new Date()
      }
    });

    // Cleanup after response is sent
    setImmediate(async () => {
      try {
        await fs.unlink(filePath);
        logger.info(`${scanId}: Cleanup completed`);
      } catch (cleanupError) {
        logger.error(`${scanId}: Failed to cleanup file:`, cleanupError);
      }
    });

  } catch (error) {
    logger.error(`${scanId}: Scan failed:`, error);

    // Cleanup on error (if file exists)
    if (filePath) {
      setImmediate(async () => {
        try {
          await fs.access(filePath);
          await fs.unlink(filePath);
        } catch (cleanupError) {
          // File might not exist, which is fine
          logger.debug(`${scanId}: File cleanup not needed or failed:`, cleanupError.message);
        }
      });
    }

    // Only send error response if headers haven't been sent
    if (!res.headersSent) {
      res.status(500).json({
        success: false,
        scanId,
        error: 'Scan failed',
        message: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
      });
    }
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date(),
    services: {
      threatIntel: threatIntel ? 'initialized' : 'not initialized'
    }
  });
});

// Global error handling middleware
app.use((error, req, res, next) => {
  logger.error('Unhandled error:', error);
  
  // Only send response if headers haven't been sent
  if (!res.headersSent) {
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Serve frontend at root path
app.get('/', (req, res) => {
  const frontendPath = path.join(__dirname, '..', 'frontend', 'cryptera-frontend.html');
  res.sendFile(frontendPath, (err) => {
    if (err) {
      logger.error('Failed to serve frontend:', err);
      res.status(404).json({
        success: false,
        error: 'Frontend not found',
        message: 'Frontend file not available'
      });
    }
  });
});

// 404 handler - Using safer route pattern
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found'
  });
});

// Start server
async function startServer() {
  try {
    await initializeServices();

    app.listen(PORT, () => {
      logger.info(`APK Security Scanner running on port ${PORT}`);
      logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
      logger.info(`Upload directory: ${uploadDir}`);
    });
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  process.exit(0);
});

startServer().catch(error => {
  logger.error('Failed to start server:', error);
  process.exit(1);
});

module.exports = app;