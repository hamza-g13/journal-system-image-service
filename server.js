const express = require('express');
const multer = require('multer');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || '5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437';

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

const dbFile = path.join(__dirname, 'uploads', 'images-db.json');
let imagesDB = [];

if (fs.existsSync(dbFile)) {
    try {
        imagesDB = JSON.parse(fs.readFileSync(dbFile, 'utf8'));
    } catch (err) {
        console.error('Error loading database:', err);
        imagesDB = [];
    }
}

const saveDB = () => {
    fs.writeFileSync(dbFile, JSON.stringify(imagesDB, null, 2));
};

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only images are allowed'));
        }
    }
});

const jwksClient = require('jwks-rsa');

// Keycloak Configuration
const client = jwksClient({
    jwksUri: process.env.JWKS_URI || 'http://keycloak:8080/realms/journal-realm/protocol/openid-connect/certs'
});

function getKey(header, callback) {
    client.getSigningKey(header.kid, function (err, key) {
        if (err) {
            console.error("Error retrieving signing key:", err);
            return callback(err);
        }
        const signingKey = key.getPublicKey();
        callback(null, signingKey);
    });
}

// --- AUTH MIDDLEWARES ---

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'No token provided' });

    jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
        if (err) {
            console.error("Token verification failed:", err.message);
            return res.status(403).json({ message: 'Invalid token' });
        }

        // Map Keycloak claims to user object
        // Keycloak roles are in realm_access.roles
        const roles = (decoded.realm_access && decoded.realm_access.roles) ? decoded.realm_access.roles : [];

        // Determine primary role for backward compatibility if needed, or just usage roles array
        // Existing code uses req.user.role (singular). We can try to map back or update authorizeRoles.
        // Let's update authorizeRoles to handle array.

        req.user = {
            username: decoded.preferred_username,
            userId: decoded.sub,
            roles: roles,
            ...decoded
        };
        next();
    });
};

const authorizeRoles = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user || !req.user.roles) {
            return res.status(403).json({ message: 'Access denied. Insufficient permissions.' });
        }

        const hasRole = req.user.roles.some(role => allowedRoles.includes(role.toUpperCase())); // Keycloak roles might be lowercase, check logic
        // Actually Keycloak roles in my realm are usually lowercase? "doctor", "patient". 
        // Existing code used "DOCTOR", "STAFF". I should probably check case-insensitive.

        const hasRoleCaseInsensitive = req.user.roles.some(role => allowedRoles.includes(role.toUpperCase()));

        // Check if I need to map my Keycloak roles (admin, doctor, etc) to these caps roles.
        // Assuming Keycloak roles: 'doctor', 'staff', 'admin', 'patient'.
        // Allowed roles in code: 'DOCTOR', 'STAFF', 'ADMIN'.

        const userRolesUpper = req.user.roles.map(r => r.toUpperCase());
        const isAuthorized = userRolesUpper.some(r => allowedRoles.includes(r));

        if (!isAuthorized) {
            return res.status(403).json({ message: 'Access denied. Insufficient permissions.' });
        }
        next();
    };
};

// --- ROUTES ---

app.post('/api/images/upload', authenticateToken, authorizeRoles('DOCTOR', 'STAFF', 'ADMIN'), upload.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
    }

    const patientId = req.body.patientId || req.query.patientId;
    if (!patientId) {
        fs.unlinkSync(req.file.path);
        return res.status(400).json({ message: 'Patient ID is required' });
    }

    const format = path.extname(req.file.filename).substring(1);

    const imageRecord = {
        id: Date.now(),
        patientId: parseInt(patientId),
        filename: req.file.filename,
        originalName: req.file.originalname,
        format: format,
        uploadDate: new Date().toISOString(),
        size: req.file.size,
        uploadedBy: req.user.username
    };

    imagesDB.push(imageRecord);
    saveDB();

    res.status(201).json({
        id: imageRecord.id,
        patientId: imageRecord.patientId,
        filename: imageRecord.filename,
        message: "Image uploaded successfully"
    });
});

app.get('/api/images/patient/:patientId', authenticateToken, (req, res) => {
    const patientId = parseInt(req.params.patientId);

    const patientImages = imagesDB.filter(img => img.patientId === patientId);

    // Read image files and convert to base64
    const imagesWithData = patientImages.map(img => {
        const filePath = path.join(__dirname, 'uploads', img.filename);
        let imageData = null;

        if (fs.existsSync(filePath)) {
            const fileBuffer = fs.readFileSync(filePath);
            imageData = fileBuffer.toString('base64');
        }

        return {
            id: img.id,
            patientId: img.patientId,
            imageData: imageData,
            format: img.format,
            uploadDate: img.uploadDate,
            uploadedBy: img.uploadedBy,
            size: img.size
        };
    });

    res.json(imagesWithData);
});

app.get('/api/images/:id', authenticateToken, (req, res) => {
    const imageId = parseInt(req.params.id);
    const image = imagesDB.find(img => img.id === imageId);

    if (!image) {
        return res.status(404).json({ message: 'Image not found' });
    }

    const filePath = path.join(__dirname, 'uploads', image.filename);

    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
    } else {
        res.status(404).json({ message: 'Image file missing on server' });
    }
});

app.put('/api/images/:id', authenticateToken, authorizeRoles('DOCTOR', 'STAFF', 'ADMIN'), upload.single('image'), (req, res) => {
    const imageId = parseInt(req.params.id);
    const imageIndex = imagesDB.findIndex(img => img.id === imageId);

    if (imageIndex === -1) {
        return res.status(404).json({ message: 'Image not found' });
    }

    if (req.file) {
        const oldPath = path.join(__dirname, 'uploads', imagesDB[imageIndex].filename);
        if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);

        imagesDB[imageIndex].filename = req.file.filename;
        imagesDB[imageIndex].size = req.file.size;
        imagesDB[imageIndex].lastModified = new Date().toISOString();

        saveDB();
        return res.json({ message: 'Image updated with new file' });
    }

    if (req.body.imageData) {
        const base64Data = req.body.imageData.replace(/^data:image\/\w+;base64,/, "");
        const buffer = Buffer.from(base64Data, 'base64');

        const filePath = path.join(__dirname, 'uploads', imagesDB[imageIndex].filename);
        fs.writeFileSync(filePath, buffer);

        imagesDB[imageIndex].lastModified = new Date().toISOString();
        saveDB();

        return res.json({ message: 'Image updated from Base64 data' });
    }

    res.status(400).json({ message: 'No image data provided' });
});


app.delete('/api/images/:id', authenticateToken, authorizeRoles('ADMIN', 'DOCTOR'), (req, res) => {
    const imageId = parseInt(req.params.id);
    const imageIndex = imagesDB.findIndex(img => img.id === imageId);

    if (imageIndex === -1) {
        return res.status(404).json({ message: 'Image not found' });
    }

    if (req.user.roles.map(r => r.toUpperCase()).includes('DOCTOR')) { // Modified to check roles array
        const image = imagesDB[imageIndex];

        if (image.uploadedBy !== req.user.username) {
            return res.status(403).json({ message: 'Access denied. Insufficient permissions.' });
        }
    }

    const filename = imagesDB[imageIndex].filename;
    const filePath = path.join(__dirname, 'uploads', filename);
    if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
    }

    imagesDB.splice(imageIndex, 1);
    saveDB();
    res.json({ message: 'Image deleted successfully' });
});

app.get('/health', (req, res) => {
    res.json({ status: 'UP', imagesCount: imagesDB.length });
});

app.listen(PORT, () => {
    console.log(`Image Service running on port ${PORT}`);
});
