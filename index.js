import express from 'express';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import cors from 'cors';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import axios from 'axios'
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { Server } from 'socket.io';
import multer from 'multer';
import xlsx from 'xlsx';
import { readdir, unlink, rmdir } from 'fs/promises';
import cron from 'node-cron';
import admin from 'firebase-admin';
import { initializeApp, applicationDefault, cert } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { readFile } from 'fs/promises';
import { ObjectId } from "mongodb";


// Get the current directory
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load the service account key JSON file
const serviceAccount = JSON.parse(await readFile(new URL('./pocketsms-c0493-firebase-adminsdk-r4cz1-240ef6a66d.json', import.meta.url), 'utf-8'));

// Initialize Firebase Admin SDK
initializeApp({
    credential: cert(serviceAccount),
});

dotenv.config();

const app = express();
app.use(bodyParser.json());
app.use(cookieParser())
app.use('/public', express.static(path.join(__dirname, 'public')));

// Configure CORS
const allowedOrigin = 'https://resilient-daifuku-553c3f.netlify.app'
app.use(cors({
    origin: allowedOrigin,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true // Allow credentials (cookies) to be sent
}));

// Connect to MongoDB Atlas
mongoose.connect(process.env.MONGO_URI, { dbName: 'PocketSms' })
    .then(() => {
        console.log('Connected to MongoDB Atlas');
    })
    .catch((err) => {
        console.error('Error connecting to MongoDB Atlas:', err);
    });

// Define Admin Schema
const adminSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: true }
});

// Middleware to hash the password before saving
adminSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();

    try {
        const hashedPassword = await bcrypt.hash(this.password, 10);
        this.password = hashedPassword;
        next();
    } catch (err) {
        next(err);
    }
});

const Admin = mongoose.model('Admin', adminSchema);

// Define Employee Schema
const employeeSchema = new mongoose.Schema({
    name: { type: String, required: true },
    designation: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, required: true },
    businessId: { type: String, required: true }
});

// Middleware to hash the password before saving
employeeSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();

    try {
        const hashedPassword = await bcrypt.hash(this.password, 10);
        this.password = hashedPassword;
        next();
    } catch (err) {
        next(err);
    }
});

const Employee = mongoose.model('Employee', employeeSchema);

const userSchema = new mongoose.Schema({
    businessName: { type: String, required: true },
    ownerName: { type: String, required: true },
    platformRole: { type: String, default: 'business owner' },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },  // Add this line if missing
    businessAccountId: { type: String, default: '' },
    longToken: { type: String, default: '' },
    credentialsStatus: { type: Boolean, default: false },
});

// Ensure the password field is selected when querying the user
userSchema.set('toJSON', {
    transform: function (doc, ret) {
        delete ret.password;
        return ret;
    },
    selectPopulatedPaths: true
});

// Set up a cron job to delete contents of the public folder every hour
cron.schedule('0 * * * *', async () => {
    await deletePublicFolder();
});


// Middleware to hash the password before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();

    try {
        const hashedPassword = await bcrypt.hash(this.password, 10);
        this.password = hashedPassword;
        next();
    } catch (err) {
        next(err);
    }
});

const User = mongoose.model('User', userSchema);

const whatsappConfigSchema = new mongoose.Schema({
    businessId: { type: String, required: true },
    displayPhoneNumber: { type: String, required: true },
    phoneNumberId: { type: String, required: true }
});

const WhatsAppConfig = mongoose.model('WhatsAppConfig', whatsappConfigSchema);

const SupportSchema = new mongoose.Schema({
    subject: String,
    description: String,
    businessId: String,
    email: String,
    timestamp: { type: Date, default: Date.now }
});

const Support = mongoose.model('Support', SupportSchema);

// API endpoint to get all support requests
app.get('/api/all/support', async (req, res) => {
    try {
        const supportRequests = await Support.find();
        res.json(supportRequests);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.get('/api/employees/count', async (req, res) => {
    try {
        const { businessId } = req.query;

        if (!businessId) {
            return res.status(400).json({ error: 'businessId is required' });
        }

        const count = await Employee.countDocuments({ businessId });

        res.status(200).json({ count });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/users/:id', async (req, res) => {
    const { id } = req.params;
    const { businessAccountId, longToken, credentialsStatus } = req.body;

    try {
        const updatedUser = await User.findByIdAndUpdate(
            id,
            {
                businessAccountId,
                longToken,
                credentialsStatus
            },
            { new: true }  // Return the updated document
        );

        if (!updatedUser) {
            return res.status(404).send('User not found');
        }

        res.json(updatedUser);
    } catch (error) {
        res.status(500).send('Server error');
    }
});

// API endpoint to handle form submission
app.post('/api/support', async (req, res) => {
    try {
        const { subject, description, businessId, email } = req.body;

        const newSupport = new Support({
            subject,
            description,
            businessId,
            email
        });

        await newSupport.save();
        res.status(201).send('Support request saved successfully');
    } catch (error) {
        res.status(500).send('Error saving support request');
    }
});

// Utility function to generate JWT
const generateToken = (user) => {
    return jwt.sign({
        id: user._id,
        email: user.email,
        businessName: user.businessName,
        ownerName: user.ownerName,
        platformRole: user.platformRole
    }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

// Utility function to generate JWT Admin
const generateTokenAdmin = (user) => {
    return jwt.sign({
        id: user._id,
        email: user.email,
        platformRole: 'admin'
    }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

// Utility function to generate JWT Employee
const generateTokenEmployee = (user) => {
    return jwt.sign({
        id: user._id,
        email: user.email,
        platformRole: user.designation,
        businessId: user.businessId,
        name: user.name,
    }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

const tokenSchema = new mongoose.Schema({
    token: {
        type: String,
        required: true,
        unique: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: '30d' // Optional: Automatically delete documents older than 30 days
    }
});

const Token = mongoose.mongoose.model('Token', tokenSchema);

// Route to save FCM token
app.post('/api/save-fcm/tokens', async (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(400).json({ error: 'Token is required' });
    }

    try {
        // Check if token already exists
        let existingToken = await Token.findOne({ token });
        if (existingToken) {
            return res.status(200).json({ message: 'Token already exists' });
        }

        // Save new token
        const newToken = new Token({ token });
        await newToken.save();

        res.status(201).json({ message: 'Token saved successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Register API for Admin
app.post('/api/admin/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const newAdmin = new Admin({ email, password });
        await newAdmin.save();

        // Generate token
        const token = generateTokenAdmin(newAdmin);

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 3600000,
            sameSite: 'None',
            // sameSite: 'None',
        });

        res.status(201).json({ message: 'Admin registered successfully' });
    } catch (err) {
        console.log(err)
        res.status(500).json({ error: err.message });
    }
});

// Register API for Employee
app.post('/api/employee/register', async (req, res) => {
    const { name, designation, email, password, role, businessId } = req.body;

    if (!name || !designation || !email || !password || !role || !businessId) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const newEmployee = new Employee({ name, designation, email, password, role, businessId });
        await newEmployee.save();

        // Generate token
        const token = generateTokenEmployee(newEmployee);

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 3600000,
            sameSite: 'None',
            // sameSite: 'None',
        });

        res.status(201).json({ message: 'Employee registered successfully' });
    } catch (err) {
        console.log(err)
        res.status(500).json({ error: err.message });
    }
});

// Register API
app.post('/api/register', async (req, res) => {
    const { businessName, ownerName, email, password } = req.body;

    if (!businessName || !ownerName || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const newUser = new User({ businessName, ownerName, email, password });
        await newUser.save();

        // Generate token
        const token = generateToken(newUser);

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 3600000,
            sameSite: 'None',
            // sameSite: 'None',
        });

        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        console.log(err)
        res.status(500).json({ error: err.message });
    }
});

// Login API
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Generate token
        const token = generateToken(user);

        res.cookie('token', token, {
            httpOnly: true, // Secure against XSS attacks, but inaccessible via JavaScript
            secure: process.env.NODE_ENV === 'production', // Ensure this matches your environment (HTTPS only in production)
            maxAge: 3600000, // Cookie expiration time: 1 hour
            sameSite: 'None',
            // sameSite: 'None',
        });

        res.status(200).json({ message: 'Login successful' });
    } catch (err) {
        console.log(err)
        res.status(500).json({ error: err.message });
    }
});

// Login API
app.post('/api/login-admin', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const user = await Admin.findOne({ email });

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);


        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Generate token
        const token = generateTokenAdmin(user);

        res.cookie('token', token, {
            httpOnly: true, // Secure against XSS attacks, but inaccessible via JavaScript
            secure: process.env.NODE_ENV === 'production', // Ensure this matches your environment (HTTPS only in production)
            maxAge: 3600000, // Cookie expiration time: 1 hour
            sameSite: 'None',
            // sameSite: 'None',
        });

        res.status(200).json({ message: 'Login successful' });
    } catch (err) {
        console.log(err)
        res.status(500).json({ error: err.message });
    }
});

// Login API
app.post('/api/login-employee', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const user = await Employee.findOne({ email });

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Generate token
        const token = generateTokenEmployee(user);

        res.cookie('token', token, {
            httpOnly: true, // Secure against XSS attacks, but inaccessible via JavaScript
            secure: process.env.NODE_ENV === 'production', // Ensure this matches your environment (HTTPS only in production)
            maxAge: 3600000, // Cookie expiration time: 1 hour
            sameSite: 'None',
            // sameSite: 'None',
        });

        res.status(200).json({ message: 'Login successful' });
    } catch (err) {
        console.log(err)
        res.status(500).json({ error: err.message });
    }
});

// Update API for clients
app.put('/api/clients/:id', async (req, res) => {
    const { id } = req.params;
    const { ownerName, email, password, businessName } = req.body;

    if (!ownerName || !email || !businessName) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const user = await User.findById(id);

        if (!user) {
            return res.status(404).json({ error: 'Employee not found' });
        }

        // Update user data
        if (password == '') {
            console.log('dont edit password')
        } else {
            user.password = password; // Consider hashing if not already hashed
        }
        user.name = ownerName;
        user.email = email;
        user.businessName = businessName

        await user.save();
        res.status(200).json({ message: 'User updated successfully', user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// Delete API for User
app.delete('/api/user/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const user = await User.findByIdAndDelete(id);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json({ message: 'User deleted successfully' });
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: err.message });
    }
});


// Update API for Employee
app.put('/api/employee/:id', async (req, res) => {
    const { id } = req.params;
    const { name, designation, email, password, role, businessId } = req.body;

    if (!name || !designation || !email || !role || !businessId) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const employee = await Employee.findById(id);

        if (!employee) {
            return res.status(404).json({ error: 'Employee not found' });
        }

        // Update employee data
        if (password == '') {
            console.log('dont edit password')
        } else {
            employee.password = password; // Consider hashing if not already hashed
        }
        employee.name = name;
        employee.email = email;
        employee.role = role;

        await employee.save();
        res.status(200).json({ message: 'Employee updated successfully', employee });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete API for Employee
app.delete('/api/employee/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const employee = await Employee.findByIdAndDelete(id);

        if (!employee) {
            return res.status(404).json({ error: 'Employee not found' });
        }

        res.status(200).json({ message: 'Employee deleted successfully' });
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: err.message });
    }
});

// Get All Employees by Business ID API
app.get('/api/employees', async (req, res) => {
    const { businessId } = req.query;

    if (!businessId) {
        return res.status(400).json({ error: 'Business ID is required' });
    }

    try {
        const employees = await Employee.find({ businessId });

        if (employees.length === 0) {
            return res.status(404).json({ error: 'No employees found for this business' });
        }

        res.status(200).json(employees);
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: err.message });
    }
});

// Get All User by Business ID API
app.get('/api/users', async (req, res) => {
    try {
        const users = await User.find();

        if (users.length === 0) {
            return res.status(404).json({ error: 'No users found' });
        }

        res.status(200).json(users);
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: err.message });
    }
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) return res.status(401).json({ error: 'Access denied' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Define the API endpoint that returns the user information
app.get('/api/me', authenticateToken, (req, res) => {
    res.status(200).json({ user: req.user });
});


app.post('/api/verify-whatsapp', async (req, res) => {
    const { longTermToken, businessAccountId } = req.body;

    if (!longTermToken || !businessAccountId) {
        return res.status(400).json({ message: 'Long-Term Token and Business Account ID are required.' });
    }

    try {
        // Make a request to the WhatsApp Cloud API to get phone numbers
        const response = await axios.get(`https://graph.facebook.com/v16.0/${businessAccountId}/phone_numbers`, {
            params: { access_token: longTermToken }
        });


        // Check if the response contains phone numbers
        if (response.data && response.data.data && response.data.data.length > 0) {
            const phoneNumbers = response.data.data.map((phone) => ({
                id: phone.id,
                display_phone_number: phone.display_phone_number,
                verified_name: phone.verified_name,
                code_verification_status: phone.code_verification_status,
                quality_rating: phone.quality_rating,
                platform_type: phone.platform_type,
                throughput: phone.throughput,
                webhook_configuration: phone.webhook_configuration,
            }));

            return res.status(200).json({
                message: 'Credentials are correct.',
                phoneNumbers: phoneNumbers
            });
        } else {
            return res.status(400).json({ message: 'Verification failed. No phone numbers found for this account.' });
        }
    } catch (error) {
        console.error('Error details:', error.response ? error.response.data : error);

        return res.status(500).json({
            message: 'An error occurred while verifying the credentials.',
            error: error.response ? error.response.data : error.message,
        });
    }
});

app.put('/api/users/false/:id', async (req, res) => {
    const { id } = req.params;

    try {
        // Find the user by ID
        const user = await User.findById(id);

        if (!user) {
            return res.status(404).send('User not found');
        }

        // Update the credentialsStatus to false
        user.credentialsStatus = false;
        const updatedUser = await user.save();

        res.json(updatedUser);
    } catch (error) {
        console.error(error); // Log the error for debugging
        res.status(500).send('Server error');
    }
});


// Endpoint to save or update WhatsApp configuration
app.post('/api/save-phone-no', async (req, res) => {
    const { businessId, phoneNumbers } = req.body;

    console.log(phoneNumbers)

    try {
        // Process each phone number and save/update in the database
        for (const phone of phoneNumbers) {
            const { display_phone_number, id } = phone;

            // Find and update the document if it exists, otherwise create a new one
            await WhatsAppConfig.findOneAndUpdate(
                { businessId }, // Find criteria
                {
                    businessId,
                    displayPhoneNumber: display_phone_number,
                    phoneNumberId: id
                },
                { upsert: true, new: true, setDefaultsOnInsert: true } // Create new if doesn't exist
            );
        }
        res.status(200).json({ message: 'Configuration saved/updated successfully!' });
    } catch (error) {
        console.error('Error saving/updating configuration:', error);
        res.status(500).json({ message: 'Error saving/updating configuration.' });
    }
});

app.get('/api/get/user/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const user = await User.findById(id, '-password');
        if (!user) {
            console.log('User not found');
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/get/employee/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const employee = await Employee.findById(id, '-password');
        if (!employee) {
            console.log('Employee not found');
            return res.status(404).json({ message: 'Employee not found' });
        }
        res.json(employee);
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});


// Home API
app.get("/", (req, res) => {
    // Emit a Socket.IO event to notify clients
    io.emit('message', { id: '66cb4bdf03a29f0544ac946e', to: '923122302146' });

    res.status(200).send("Hello, this is webhook setup");
});

// Initialize HTTP server and Socket.IO
const server = app.listen(process.env.PORT || 3000, () => {
    console.log(`Server is listening on port ${process.env.PORT || 3000}`);
});

const io = new Server(server, {
    cors: {
        origin: 'https://resilient-daifuku-553c3f.netlify.app',
        methods: ['GET', 'POST', 'HEAD', 'PUT', 'PATCH', 'DELETE'],
        credentials: true
    }
});



// Webhook Configuration
const messageSchema = new mongoose.Schema({
    conversationId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'Conversation' },
    businessId: { type: String, default: '' },
    isTemplate: { type: Boolean, default: false },
    messageOwner: { type: String, default: '' },
    phone_no_id: { type: String, default: '' },
    from: { type: String, default: '' },
    to: { type: String, default: '' },
    message_id: { type: String, default: '' },
    timestamp: { type: String, default: '' },
    type: { type: String, default: '' },
    status: { type: String, default: '' },
    nodeId: { type: String, default: '' },
    flowData: {
        type: Array,
        default: []
    },
    buttons: {
        type: Array, // Array of buttons associated with the message
        default: []
    },
    content: {
        body: { type: String, default: '' },
        caption: { type: String, default: '' },
        mime_type: { type: String, default: '' },
        media_id: { type: String, default: '' }
    },
    metadata: {
        sender_id: { type: String, default: '' },
        designation: { type: String, default: '' },
    },
    ourData: {
        messageType: { type: String, default: '' },
        text: { type: String, default: '' },
        path: { type: String, default: '' },
    },
    received_at: { type: Date, default: Date.now },
    reply_to: { type: String, default: null }
});

const Message = mongoose.model('Message', messageSchema);

// Updated conversationSchema to include the last message details
const conversationSchema = new mongoose.Schema({
    participants: { type: String, required: true, unique: true },
    businessId: { type: String, default: '' },
    lastMessageTime: { type: Date, default: Date.now },
    messageCount: { type: Number, default: 0 },
    status: { type: String, default: '' },
    content: {
        body: { type: String, default: '' },
        caption: { type: String, default: '' },
        mime_type: { type: String, default: '' },
        media_id: { type: String, default: '' }
    },
    labels: {
        type: [String],
        default: [],
    },
    lastMessageSender: { type: String, default: '' }
});

const Conversation = mongoose.model('Conversation', conversationSchema);

const labelSchema = new mongoose.Schema({
    businessId: {
        type: String,
        required: true,
        unique: true, // Ensuring each conversationId is unique
    },
    labels: {
        type: [String], // Array of labels
        default: ['Important', 'Follow Up', 'Lead'],
    },
}, {
    timestamps: true, // Automatically add createdAt and updatedAt timestamps
});

const Label = mongoose.model('Label', labelSchema);

// Get labels for a conversation
app.get('/getLabels/conversation/:conversationId', async (req, res) => {
    const { conversationId } = req.params;
    try {
        const conversation = await Conversation.findById(conversationId);
        if (!conversation) {
            return res.status(404).json({ message: 'Conversation not found' });
        }
        res.status(200).json({ labels: conversation.labels });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Add label to conversation
app.post('/addLabel/conversation', async (req, res) => {
    const { conversationId, label } = req.body;
    try {
        const conversation = await Conversation.findById(conversationId);
        if (!conversation) {
            return res.status(404).json({ message: 'Conversation not found' });
        }

        if (!conversation.labels.includes(label)) {
            conversation.labels.push(label);
            await conversation.save();
            res.status(200).json({ message: 'Label added successfully' });
        } else {
            res.status(400).json({ message: 'Label already exists' });
        }
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Remove label from conversation
app.post('/removeLabel/conversation', async (req, res) => {
    const { conversationId, label } = req.body;
    try {
        const conversation = await Conversation.findById(conversationId);
        if (!conversation) {
            return res.status(404).json({ message: 'Conversation not found' });
        }

        const labelIndex = conversation.labels.indexOf(label);
        if (labelIndex !== -1) {
            conversation.labels.splice(labelIndex, 1);
            await conversation.save();
            res.status(200).json({ message: 'Label removed successfully' });
        } else {
            res.status(400).json({ message: 'Label does not exist' });
        }
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// POST route to create a new label document
app.post('/labels', async (req, res) => {
    try {
        const { businessId } = req.body;

        // Ensure that businessId is provided
        if (!businessId) {
            return res.status(400).json({ message: 'Business ID is required' });
        }

        // Create a new label document
        const newLabel = new Label({ businessId });

        // Save the document to the database
        await newLabel.save();

        res.status(201).json({ message: 'Label created successfully', newLabel });
    } catch (error) {
        console.error('Error creating label:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// POST route to add a new label to an existing label document
app.post('/labels/add', async (req, res) => {
    try {
        const { businessId, label } = req.body;

        // Ensure that businessId and label are provided
        if (!businessId || !label) {
            return res.status(400).json({ message: 'Business ID and label are required' });
        }

        // Find the label document for the given businessId
        const labelDocument = await Label.findOne({ businessId });

        if (!labelDocument) {
            return res.status(404).json({ message: 'Label document not found' });
        }

        // Add the new label if it doesn't already exist
        if (!labelDocument.labels.includes(label)) {
            labelDocument.labels.push(label);
            await labelDocument.save();
            res.status(200).json({ message: 'Label added successfully', labelDocument });
        } else {
            res.status(400).json({ message: 'Label already exists' });
        }

    } catch (error) {
        console.error('Error adding label:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// DELETE route to remove a label from an existing label document
app.delete('/labels/delete', async (req, res) => {
    try {
        const { businessId, label } = req.body;

        // Ensure that businessId and label are provided
        if (!businessId || !label) {
            return res.status(400).json({ message: 'Business ID and label are required' });
        }

        // Find the label document for the given businessId
        const labelDocument = await Label.findOne({ businessId });

        if (!labelDocument) {
            return res.status(404).json({ message: 'Label document not found' });
        }

        // Remove the label if it exists
        const labelIndex = labelDocument.labels.indexOf(label);
        if (labelIndex > -1) {
            labelDocument.labels.splice(labelIndex, 1);
            await labelDocument.save();
            res.status(200).json({ message: 'Label deleted successfully', labelDocument });
        } else {
            res.status(400).json({ message: 'Label not found' });
        }

    } catch (error) {
        console.error('Error deleting label:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// GET route to retrieve labels for a given businessId
app.get('/labels/:businessId', async (req, res) => {
    try {
        const { businessId } = req.params;

        // Ensure that businessId is provided
        if (!businessId) {
            return res.status(400).json({ message: 'Business ID is required' });
        }

        // Find the label document by businessId
        const labelDocument = await Label.findOne({ businessId });

        // Check if the label document exists
        if (!labelDocument) {
            return res.status(404).json({ message: 'Label document not found' });
        }

        // Return the labels associated with the businessId
        res.status(200).json({ labels: labelDocument.labels });

    } catch (error) {
        console.error('Error retrieving labels:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});


const mytoken = process.env.MYTOKEN;

async function getBusinessIdByPhoneNumberId(phoneNumberId) {
    try {
        const config = await WhatsAppConfig.findOne({ phoneNumberId: phoneNumberId }).exec();
        if (config) {
            return config.businessId;
        } else {
            return null; // No document found
        }
    } catch (error) {
        console.error('Error fetching businessId:', error);
        throw new Error('Error fetching businessId');
    }
}

app.get("/webhook", (req, res) => {
    const mode = req.query["hub.mode"];
    const challenge = req.query["hub.challenge"];
    const token = req.query["hub.verify_token"];

    if (mode && token && mode === "subscribe" && token === mytoken) {
        res.status(200).send(challenge);
    } else {
        res.status(403).send("Forbidden");
    }
});

app.post("/webhook", (request, response) => {
    console.log('Incoming webhook: ' + JSON.stringify(request.body));
    const changes = request.body.entry?.[0]?.changes?.[0]?.value;

    if (!changes) {
        return response.sendStatus(400);
    }

    if (changes.messages) {
        handleReceivedMessage(JSON.stringify(request.body));
    } else if (changes.statuses) {
        changes.statuses.forEach(status => {
            handleStatusMessage(status);
        });
    } else {
        console.log('Unknown webhook content:', JSON.stringify(changes));
    }

    response.sendStatus(200);
});









// 1. Check if the flow is active for the given businessId
async function checkFlowStatus(businessId) {
    console.log(`Checking flow status for business ID: ${businessId}`);
    const flow = await Flow.findOne({ businessId, status: 'active' });
    if (!flow) {
        console.log(`Flow for business ${businessId} is inactive.`);
        return false;
    }
    console.log(`Flow for business ${businessId} is active.`);
    return true;
}

// 2. Get the last message sent by us in the conversation
async function getLastMessage(conversationId) {
    console.log(`Getting last message for conversation ID: ${conversationId}`);
    const lastMessage = await Message.findOne({
        conversationId,
        status: { $in: ['sent', 'delivered', 'read'] } // We are checking for the last message we sent
    }).sort({ received_at: -1 });

    if (!lastMessage) {
        // Customer initiated conversation, start the flow
        console.log(`No sent message found. Starting flow for conversation ${conversationId}`);
        return null; // Indicates starting flow from the first node
    }
    console.log(`Last message found: ${lastMessage.content.body}`);
    return lastMessage;
}

function filterById(data, idToFind) {
    return data.filter(item => item._id.equals(idToFind));
}

// 3. Process the message to determine if it's part of the flow and what to do next
async function processNodeMessage(lastMessage, conversationId, businessId, newMessage) {
    console.log(`Processing message for conversation ID: ${conversationId}`);
    
    if (!lastMessage) {
        // Start the flow with the first node
        console.log(`No last message. Starting flow for business ID: ${businessId}`);
        const flow = await Flow.findOne({ businessId, status: 'active' });
        const firstNode = flow?.nodes[0]; // Assuming the first node starts the flow
        if (firstNode) {
            await sendNodeMessage(firstNode, conversationId, newMessage, businessId);
            console.log(`Sent first node message: ${firstNode.content}`);
        }
        return;
    }

    // If the last message is part of a flow node
    const nodeId = lastMessage?.nodeId; // Assuming we store nodeId in ourData
    console.log(`Last message's nodeId: ${nodeId}`);
    if (nodeId) {
        const flow = await Flow.findOne({ businessId, status: 'active' });
        console.log('selected flow', flow.nodes)
        // const node = flow?.nodes.find(n => n._id === nodeId);
        
        const node = filterById(flow, new ObjectId(`${nodeId}`));
        console.log(`Current node: ${JSON.stringify(node)}`);

        // Determine the next step
        if (node?.buttons && node.buttons.length > 1) {
            console.log(`Node has multiple buttons. Handling node with buttons.`); 
            await handleNodeWithButtons(node, conversationId, newMessage, businessId);
        } else {
            console.log(`Node has one or no buttons. Sending next node automatically.`);
            await sendNextNodeAutomatically(node, conversationId, businessId, newMessage);
        }
    } else {
        // Start the flow with the first node
        console.log(`last message. Starting flow for business ID: ${businessId} doesn't have a node Id`);
        const flow = await Flow.findOne({ businessId, status: 'active' });
        const firstNode = flow?.nodes[0]; // Assuming the first node starts the flow
        if (firstNode) {
            await sendNodeMessage(firstNode, conversationId, newMessage, businessId);
            console.log(`Sent first node message: ${firstNode.content}`);
        }
        return;
    }
}

// 4. Handle node with multiple buttons, match response and proceed
async function handleNodeWithButtons(node, conversationId, newMessage, businessId) {
    console.log(`Handling node with buttons for conversation ID: ${conversationId}`);
    const customerMessage = await Message.findOne({
        conversationId,
        status: 'received',
        received_at: { $gt: node.received_at }
    }).sort({ received_at: 1 }); // Find the first customer reply after the node was sent

    if (customerMessage) {
        const buttonResponse = customerMessage?.content?.body;
        console.log(`Customer response received: ${buttonResponse}`);
        const matchedButton = node.buttons.find(button => button.label === buttonResponse);

        if (matchedButton) {
            const nextNodeId = matchedButton.target;
            console.log(`Matched button. Sending next node ID: ${nextNodeId}`);
            await sendNodeMessage(nextNodeId, conversationId, newMessage, businessId);
        } else {
            console.log(`No matching button for response: ${buttonResponse}`);
        }
    } else {
        console.log('Waiting for customer response...');
    }
}

// 5. Handle nodes with no or one button, send the next node automatically
async function sendNextNodeAutomatically(node, conversationId, businessId, newMessage) {
    console.log(`Sending next node automatically for node ID: ${node.id}`);
    const flow = await Flow.findOne({ businessId, status: 'active' });
    const nextNode = flow?.nodes.find(n => n.id === node.connections[0]?.target);

    if (nextNode) {
        await sendNodeMessage(nextNode, conversationId, newMessage, businessId);
        console.log(`Sent next node message: ${nextNode.content}`);
    } else {
        console.log('No next node found.');
    }
}


// Utility function to fetch WhatsApp API token based on businessID
async function getWhatsAppApiToken(businessId) {
    const business = await User.findById(businessId);
    if (!business || !business.longToken) {
        throw new Error(`WhatsApp API token not found for business ID: ${businessId}`);
    }
    return business.longToken;
};

// Helper function to send node message using WhatsApp Cloud API
async function sendNodeMessage(node, conversationId, recentMessage, businessId) {
    let messageData;

    // Prepare message content from the node schema
    const content = {
        header: node.header || '',
        body: node.body || '',
        footer: node.footer || ''
    };

    // Prepare buttons if available
    let buttons = [];
    if (node.buttons && node.buttons.length > 0) {
        buttons = node.buttons.map(button => ({
            type: 'reply',
            reply: {
                id: button.label, // Button label as id
                title: button.label
            }
        }));
    }

    // Get the WhatsApp API token dynamically based on businessId
    const apiToken = await getWhatsAppApiToken(businessId);

    // Build the payload for WhatsApp Cloud API
    const payload = {
        messaging_product: "whatsapp",
        to: recentMessage.from, // Send to the client who sent the message
        type: buttons.length > 0 ? "interactive" : "text", // Use interactive message if buttons exist
        text: content.body ? { body: content.body } : undefined, // Only include text if body exists
        interactive: buttons.length > 0 ? {
            type: "button",
            body: { text: content.body || "Choose an option:" },
            action: {
                buttons
            }
        } : undefined // Only include interactive if buttons are present
    };

    try {
        // Send message using WhatsApp Cloud API
        const response = await axios.post(
            `https://graph.facebook.com/v15.0/${recentMessage.phone_no_id}/messages`,
            payload,
            {
                headers: {
                    'Authorization': `Bearer ${apiToken}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        console.log('Message sent successfully:', response.data);

        // Priority-based logging for non-empty fields
        if (content.header) {
            console.log('Header:', content.header);
            messageData = content.header;
        } else if (content.body) {
            console.log('Body:', content.body);
            messageData = content.body;
        } else if (content.footer) {
            console.log('Footer:', content.footer);
            messageData = content.footer;
        }

        if (buttons.length > 0) {
            console.log('Buttons:', buttons.map(btn => btn.reply.title));
            messageData = 'Message with buttons....';
        }

        // Update the status count of message
        updateConversationMessageCount(recentMessage.from, messageData, businessId, '')

        // Save the message in the database
        const newMessage = new Message({
            conversationId,
            businessId,
            messageOwner: 'System',
            phone_no_id: recentMessage.phone_no_id,
            from: recentMessage.to, // System sending the message to the client
            to: recentMessage.from, // Client receiving the message
            message_id: response.data.messages[0].id, // WhatsApp message ID
            timestamp: new Date(),
            type: buttons.length > 0 ? 'interactive' : 'text',
            status: 'sent',
            flowData: content,
            nodeId: node._id,  // Save the nodeId
            buttons: buttons.length > 0 ? buttons.map(btn => btn.reply.title) : [],
            received_at: new Date()
        });

        await newMessage.save();
        console.log('Node message saved:', newMessage);
    } catch (error) {
        console.error('Failed to send message:', error.response?.data || error.message);
    }
}








// Handle Received Messages
async function handleReceivedMessage(message) {
    console.log('Received Message:', message);

    try {
        const parsedMessage = JSON.parse(message);
        const entry = parsedMessage.entry?.[0];
        const changes = entry?.changes?.[0]?.value;
        const metadata = changes?.metadata;
        const contact = changes?.contacts?.[0];
        const messageData = changes?.messages?.[0];
        const type = messageData?.type;
        const client = messageData.from;
        const businessID = await getBusinessIdByPhoneNumberId(metadata?.phone_number_id)

        let content = {};
        if (type === 'text') {
            content.body = messageData?.text?.body || '';
        } else if (type === 'image') {
            content = {
                mime_type: messageData?.image?.mime_type || '',
                caption: messageData?.image?.caption || '',
                media_id: messageData?.image?.id || '',
            };
        } else if (type === 'video') {
            content = {
                mime_type: messageData?.video?.mime_type || '',
                media_id: messageData?.video?.id || '',
                caption: messageData?.video?.caption || '',
            };
        } else if (type === 'audio') {
            content = {
                mime_type: messageData?.audio?.mime_type || '',
                media_id: messageData?.audio?.id || '',
            };
        } else if (type === 'document') {
            content = {
                mime_type: messageData?.document?.mime_type || '',
                media_id: messageData?.document?.id || '',
                filename: messageData?.document?.filename || '',
            };
        } else {
            content.body = messageData?.interactive?.button_reply?.title || '';
            console.log('message type:', type);
            return;
        }

        // Extract context if available
        const contextId = messageData?.context?.id;

        // Ensure the participants variable is properly defined
        const participants = client;

        // Search for an existing conversation with the client as a participant
        let conversation = await Conversation.findOneAndUpdate(
            { participants: client },
            {
                lastMessageTime: new Date(),
                $inc: { messageCount: 1 },
                businessId: businessID,
                content: content,
                lastMessageSender: contact?.profile?.name || 'Client',
                status: 'received',
            },
            { new: true }
        );

        // If no conversation is found, create a new one
        if (!conversation) {
            conversation = new Conversation({
                participants: client,
                businessId: businessID,
                lastMessageTime: new Date(),
                messageCount: 1,
                content: content,
                lastMessageSender: contact?.profile?.name || 'Client',
                status: 'received',
            });
            await conversation.save();
            console.log('New conversation created:', conversation);
        } else {
            console.log('Conversation updated:', conversation);
        }

        // Ensure conversationId is not null before saving the message
        if (!conversation._id) {
            throw new Error('Failed to retrieve conversation ID.');
        }

        // Save the received message
        const newMessage = new Message({
            conversationId: conversation._id,
            businessId: businessID,
            messageOwner: contact?.profile?.name || 'Client',
            phone_no_id: metadata?.phone_number_id,
            from: messageData?.from,
            to: metadata?.display_phone_number,
            message_id: messageData?.id,
            timestamp: messageData?.timestamp,
            type: messageData?.type,
            status: 'received',
            content: content,
            received_at: new Date(),
            reply_to: contextId || null
        });

        await newMessage.save();

        // You will integrate here
        const flowStatus = checkFlowStatus(businessID)
        if (flowStatus) {
            console.log('flow active')
            const ourLastMessage = await getLastMessage(conversation._id)
            const handleMessage = await processNodeMessage(ourLastMessage, conversation._id, businessID, newMessage)
            console.log(handleMessage)
        }

        // Emit a Socket.IO event to notify clients
        io.emit('message', { id: conversation._id, to: newMessage.from });
    } catch (err) {
        console.error('Error handling message:', err);
    }
}

async function handleStatusMessage(status) {
    console.log('Received status update:', status);

    const message_id = status.id;
    const timestamp = status.timestamp;
    const Status = status.status;
    const recipientId = status.recipient_id;

    try {
        // Search for the message using the message_id
        const existingMessage = await Message.findOne({ message_id: message_id });

        if (existingMessage) {
            // If the message is found, update it with the new data
            existingMessage.timestamp = timestamp;
            existingMessage.status = Status;

            await existingMessage.save();

            // Search for an existing conversation with the client as a participant
            let conversation = await Conversation.findOneAndUpdate(
                { participants: recipientId },
                {
                    status: Status,
                },
                { new: true }
            );

            // Emit a Socket.IO event to notify clients
            io.emit('message', { id: existingMessage.conversationId, to: recipientId, status: 'status' });
        } else {
            console.log('Message not found with message_id:', message_id);
        }
    } catch (err) {
        console.error('Error handling status update:', err);
    }
}

app.get('/conversations', async (req, res) => {
    try {
        const { businessId } = req.query;

        // Ensure businessId is provided
        if (!businessId) {
            return res.status(400).send('Business ID is required');
        }

        // Query conversations based on businessId
        const conversations = await Conversation.find({ businessId })
            .sort({ lastMessageTime: -1 })

        res.json(conversations);
    } catch (err) {
        console.error('Error retrieving conversations:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/messages/:phoneNumber', async (req, res) => {
    try {
        const { phoneNumber } = req.params;
        const { businessId } = req.query;

        // Ensure businessId is provided
        if (!businessId) {
            return res.status(400).send('Business ID is required');
        }

        const messages = await Message.find({
            $and: [
                { businessId }, // Match the businessId
                {
                    $or: [{ from: phoneNumber }, { to: phoneNumber }]
                }
            ]
        })
            .sort({ received_at: -1 })

        res.json(messages);
    } catch (err) {
        console.error('Error retrieving messages:', err);
        res.status(500).send('Internal Server Error');
    }
});


// Function to fetch media metadata (URL and MIME type)
async function fetchMediaMetadata(mediaId, token) {
    const GRAPH_API_URL = `https://graph.facebook.com/v20.0/${mediaId}/`;

    try {
        const response = await axios.get(GRAPH_API_URL, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        // Return both the media URL and the MIME type
        return {
            url: response.data.url, // Adjust based on actual response structure
            mimeType: response.data.mime_type // Adjust based on actual response structure
        };
    } catch (error) {
        console.error('Error fetching media metadata:', error);
        throw error;
    }
}

// Function to determine file extension based on MIME type
function getFileExtension(mimeType) {
    switch (mimeType) {
        case 'image/jpeg':
            return 'jpg';
        case 'image/png':
            return 'png';
        case 'application/pdf':
            return 'pdf';
        case 'audio/mpeg':
            return 'mp3';
        case 'audio/ogg':
            return 'mp3';
        case 'video/mp4':
            return 'mp4';
        case 'text/plain':
            return 'txt';
        case 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
            return 'docx'; // Handle Word documents
        // Add other MIME types as needed
        default:
            console.warn(`Unrecognized MIME type: ${mimeType}`);
            return ''; // Return an empty string if the MIME type is not recognized
    }
}

async function downloadMedia(mediaUrl, mimeType, fileName, folderPath, token) {
    try {
        const response = await axios({
            method: 'get',
            url: mediaUrl,
            responseType: 'stream',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        const extension = getFileExtension(mimeType);
        const filePath = path.join(folderPath, `${fileName}.${extension}`); // Adjusted path construction
        const writer = fs.createWriteStream(filePath);

        response.data.pipe(writer);

        return new Promise((resolve, reject) => {
            writer.on('finish', () => resolve(`${fileName}.${extension}`));
            writer.on('error', (err) => reject(err));
        });
    } catch (error) {
        console.error('Error downloading media:', error);
        throw error;
    }
}

// API endpoint to download and save media
app.post('/download-media', async (req, res) => {
    const { id, mediaId, fileName, token } = req.body;

    if (!id || !mediaId || !fileName || !token) {
        return res.status(400).json({ error: 'Missing required parameters: id, mediaId, or fileName' });
    }

    const folderPath = path.join(__dirname, 'public', id);

    // Ensure the directory exists
    if (!fs.existsSync(folderPath)) {
        fs.mkdirSync(folderPath, { recursive: true });
    }

    try {
        const mediaMetadata = await fetchMediaMetadata(mediaId, token);
        if (mediaMetadata && mediaMetadata.url) {
            const savedFileName = await downloadMedia(mediaMetadata.url, mediaMetadata.mimeType, fileName, folderPath, token);
            res.json({ fileName: savedFileName });
        } else {
            res.status(404).json({ error: 'No media metadata found.' });
        }
    } catch (error) {
        console.log(error)
        res.status(500).json({ error: 'Error in downloading media.' });
    }
});

// Send Message

const updateConversationMessageCount = async (client, messageBody, businessId, templateName) => {
    let messageInfo;

    if (messageBody !== '' && templateName == '') {
        messageInfo = messageBody
    } else {
        messageInfo = templateName
    }

    let conversation = await Conversation.findOneAndUpdate(
        { participants: client, businessId: businessId },
        {
            lastMessageTime: new Date(),
            $inc: { messageCount: 1 },
            content: {
                body: messageInfo
            },
        },
        { new: true }
    );

    if (!conversation) {
        conversation = new Conversation({
            businessId: businessId,
            participants: client,
            lastMessageTime: new Date(),
            messageCount: 1,
            content: {
                body: messageBody
            },
        });
        await conversation.save();
        return conversation._id;
    } else {
        return conversation._id;
    }
};

const updateConversationMessageCountBulk = async (client, messageBody, businessId, templateName, labels) => {
    let messageInfo;

    if (messageBody !== '' && templateName == '') {
        messageInfo = messageBody
    } else {
        messageInfo = templateName
    }

    let conversation = await Conversation.findOneAndUpdate(
        { participants: client, businessId: businessId },
        {
            lastMessageTime: new Date(),
            $inc: { messageCount: 1 },
            content: {
                body: messageInfo
            },
            labels: labels,
        },
        { new: true }
    );

    if (!conversation) {
        conversation = new Conversation({
            businessId: businessId,
            participants: client,
            lastMessageTime: new Date(),
            messageCount: 1,
            content: {
                body: messageBody
            },
            labels: labels,
        });
        await conversation.save();
        return conversation._id;
    } else {
        return conversation._id;
    }
};

const sendMessage = async (recipientPhoneNumber, senderId, designation, conversationId, messageBody, businessId, phon_no_id, phon_no, token) => {
    try {
        const response = await axios({
            method: "POST",
            url: `https://graph.facebook.com/v20.0/${phon_no}/messages`,
            params: {
                access_token: token
            },
            data: {
                messaging_product: "whatsapp",
                to: recipientPhoneNumber,
                text: {
                    body: messageBody
                }
            },
            headers: {
                "Content-Type": "application/json"
            }
        });

        console.log(response.data, 'message sent')

        const messageId = response.data.messages[0].id;

        const message = new Message({
            conversationId: conversationId,
            businessId, businessId,
            phone_no_id: phon_no,
            from: phon_no_id,
            to: recipientPhoneNumber,
            message_id: messageId,
            type: 'text',
            metadata: {
                sender_id: senderId,
                designation: designation,
            },
            ourData: {
                messageType: 'text',
                text: messageBody
            }
        });

        await message.save();
    } catch (error) {
        console.error("Error sending message:", error);
    }
}

// Function to send a template message
async function sendTemplateMessage(recipientPhoneNumber, senderId, designation, conversationId, businessId, templateName, phon_no_id, phon_no, token) {
    try {
        const response = await axios.post(
            `https://graph.facebook.com/v17.0/${phon_no}/messages`,
            {
                messaging_product: 'whatsapp',
                to: recipientPhoneNumber,
                type: 'template',
                template: {
                    name: templateName,
                    language: {
                        code: 'en_US', // Change this to the language code of your template
                    },
                    // Add components if your template has parameters
                }
            },
            {
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'application/json',
                }
            }
        );


        const messageId = response.data.messages[0].id;

        const message = new Message({
            conversationId: conversationId,
            businessId, businessId,
            isTemplate: true,
            phone_no_id: phon_no,
            from: phon_no_id,
            to: recipientPhoneNumber,
            message_id: messageId,
            type: 'text',
            metadata: {
                sender_id: senderId,
                designation: designation,
            },
            ourData: {
                messageType: 'text',
                text: templateName
            }
        });

        await message.save();

    } catch (error) {
        console.log(error)
        console.error('Error sending message:', error.response ? error.response.data : error.message);
    }
}

// API endpoint to send a message
app.post('/send-message', async (req, res) => {
    const { recipientPhoneNumber, senderId, designation, messageBody, businessId, templateName, phon_no, phon_no_id, token } = req.body;

    if (!recipientPhoneNumber || !senderId || !designation || (messageBody !== '' && templateName !== '') || !businessId || !phon_no || !phon_no_id || !token) {
        return res.status(400).send('Missing required fields');
    }

    try {
        const conversationId = await updateConversationMessageCount(recipientPhoneNumber, messageBody, businessId, templateName);
        if (templateName == '' && messageBody !== '') {
            await sendMessage(recipientPhoneNumber, senderId, designation, conversationId, messageBody, businessId, phon_no, phon_no_id, token);
            io.emit('message', { id: conversationId, to: recipientPhoneNumber });

            res.status(200).send('Message sent and saved successfully');
        } else if (templateName !== '' && messageBody == '') {
            await sendTemplateMessage(recipientPhoneNumber, senderId, designation, conversationId, businessId, templateName, phon_no, phon_no_id, token);
            io.emit('message', { id: conversationId, to: recipientPhoneNumber });

            res.status(200).send('Template Message sent and saved successfully');
        }
    } catch (error) {
        console.log(error)
        res.status(500).send('Error sending message');
    }
});


async function sendWhatsAppMessageDirect(recipientPhoneNumber, senderId, designation, conversationId, businessId, templateName, phon_no, phon_no_id, token, payload) {
    console.log(recipientPhoneNumber, senderId, designation, conversationId, businessId, templateName, phon_no, phon_no_id, token, payload)

    try {
        const response = await axios.post(`https://graph.facebook.com/v17.0/${phon_no_id}/messages`, payload, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });

        console.log('Message sent successfully:', response.data);

        const messageId = response.data.messages[0].id;
        const message = new Message({
            conversationId: conversationId,
            businessId: businessId,
            isTemplate: true,
            phone_no_id: phon_no,
            from: phon_no_id,
            to: recipientPhoneNumber,
            message_id: messageId,
            type: 'text',
            metadata: {
                sender_id: senderId,
                designation: designation,
            },
            ourData: {
                messageType: 'text',
                text: templateName
            }
        });

        await message.save();
    } catch (error) {
        console.error('Error sending message:', error.response ? error.response.data : error.message);
    }
}


app.post('/direct-template-send-message-alone', async (req, res) => {
    const { recipientPhoneNumber, senderId, designation, businessId, templateName, phon_no, phon_no_id, token, payload } = req.body;

    if (!recipientPhoneNumber || !senderId || !designation || templateName == '' || !businessId || !phon_no || !phon_no_id || !token || !payload) {
        return res.status(400).send('Missing required fields');
    }

    try {
        const conversationId = await updateConversationMessageCount(recipientPhoneNumber, '', businessId, templateName);
        await sendWhatsAppMessageDirect(recipientPhoneNumber, senderId, designation, conversationId, businessId, templateName, phon_no, phon_no_id, token, payload);
        io.emit('message', { id: conversationId, to: recipientPhoneNumber });

        res.status(200).send('Template Message sent and saved successfully');
    } catch (error) {
        console.log(error)
        res.status(500).send('Error sending message');
    }
});

// API endpoint to send a message
app.post('/direct-template-send-message', async (req, res) => {
    const { recipientPhoneNumber, senderId, designation, businessId, templateName, phon_no, phon_no_id, token, payload, labels } = req.body;

    if (!recipientPhoneNumber || !senderId || !designation || templateName == '' || !businessId || !phon_no || !phon_no_id || !token || !payload || !labels) {
        return res.status(400).send('Missing required fields');
    }

    try {
        const conversationId = await updateConversationMessageCountBulk(recipientPhoneNumber, '', businessId, templateName, labels);
        await sendWhatsAppMessageDirect(recipientPhoneNumber, senderId, designation, conversationId, businessId, templateName, phon_no, phon_no_id, token, payload);
        io.emit('message', { id: conversationId, to: recipientPhoneNumber });

        res.status(200).send('Template Message sent and saved successfully');
    } catch (error) {
        console.log(error)
        res.status(500).send('Error sending message');
    }
});

// API endpoint to get displayPhoneNumber and phoneNumberId by businessId 
app.get('/api/whatsapp-config/:businessId', async (req, res) => {
    try {
        const { businessId } = req.params;

        // Find the document based on businessId
        const config = await WhatsAppConfig.findOne({ businessId });

        if (!config) {
            return res.status(404).json({ error: 'Configuration not found' });
        }

        // Return the displayPhoneNumber as phon_no and phoneNumberId as phon_no_id
        res.json({
            phon_no: config.displayPhoneNumber,
            phon_no_id: config.phoneNumberId
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Route to get the number of documents that don't have status "received" or "read"
app.get('/api/messages/status-count/:conversationId', async (req, res) => {
    try {
        const { conversationId } = req.params;

        // Validate conversationId
        if (!mongoose.Types.ObjectId.isValid(conversationId)) {
            return res.status(400).json({ error: 'Invalid conversationId' });
        }

        const count = await Message.countDocuments({
            conversationId,
            status: { $in: 'received' },
            'ourData.messageType': { $eq: '' },
            'ourData.text': { $eq: '' },
            'ourData.path': { $eq: '' }
        });

        res.status(200).json({ conversationId, count });
    } catch (error) {
        console.error('Error fetching message status count:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Route to get the number of documents that don't have status "received" or "read"
app.get('/api/messages/all/status-count/:businessId', async (req, res) => {
    try {
        const { businessId } = req.params;

        // Validate conversationId
        if (!mongoose.Types.ObjectId.isValid(businessId)) {
            return res.status(400).json({ error: 'Invalid businessId' });
        }

        const count = await Message.countDocuments({
            businessId,
            status: { $in: 'received' },
            'ourData.messageType': { $eq: '' },
            'ourData.text': { $eq: '' },
            'ourData.path': { $eq: '' }
        });

        res.status(200).json({ count });
    } catch (error) {
        console.error('Error fetching message status count:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Route to update the status of messages to "read"
app.put('/api/messages/update-status/:conversationId/:recepient', async (req, res) => {
    try {
        const { conversationId, recepient } = req.params;

        // Validate conversationId
        if (!mongoose.Types.ObjectId.isValid(conversationId)) {
            return res.status(400).json({ error: 'Invalid conversationId' });
        }

        const count = await Message.countDocuments({
            conversationId,
            status: 'received',
            'ourData.messageType': '',
            'ourData.text': '',
            'ourData.path': ''
        });

        if (count > 0) {
            // Update the status of these messages to "readed"
            const updateResult = await Message.updateMany(
                {
                    conversationId,
                    status: 'received',
                    'ourData.messageType': '',
                    'ourData.text': '',
                    'ourData.path': ''
                },
                { $set: { status: 'readed' } }
            );

            io.emit('message', { id: conversationId, to: recepient });

            res.status(200).json({ conversationId, count, updated: updateResult.modifiedCount });
        } else {
            res.status(200).json({ status: 'nothing to update' });
        }
    } catch (error) {
        console.error('Error updating message status:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Route to update the status of messages to "read"
app.put('/first-time/api/messages/update-status/:conversationId/:recepient', async (req, res) => {
    try {
        const { conversationId, recepient } = req.params;

        // Validate conversationId
        if (!mongoose.Types.ObjectId.isValid(conversationId)) {
            return res.status(400).json({ error: 'Invalid conversationId' });
        }

        const count = await Message.countDocuments({
            conversationId,
            status: 'received',
            'ourData.messageType': '',
            'ourData.text': '',
            'ourData.path': ''
        });


        // Update the status of these messages to "readed"
        const updateResult = await Message.updateMany(
            {
                conversationId,
                status: 'received',
                'ourData.messageType': '',
                'ourData.text': '',
                'ourData.path': ''
            },
            { $set: { status: 'readed' } }
        );

        io.emit('message', { id: conversationId, to: recepient });

        res.status(200).json({ conversationId, count, updated: updateResult.modifiedCount });

    } catch (error) {
        console.error('Error updating message status:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Dashboard

// API endpoint to get total number of messages by businessId
app.get('/api/messages/count', async (req, res) => {
    const { businessId } = req.query;

    if (!businessId) {
        return res.status(400).json({ error: 'Business ID is required' });
    }

    try {
        const messageCount = await Message.countDocuments({ businessId });
        return res.status(200).json({ totalMessages: messageCount });
    } catch (error) {
        console.error('Error counting messages:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

// API endpoint to get total message count per month by businessId with alternating colors
app.get('/api/messages/count/monthly', async (req, res) => {
    const { businessId } = req.query;

    if (!businessId) {
        return res.status(400).json({ error: 'Business ID is required' });
    }

    try {
        const monthlyMessageCount = await Message.aggregate([
            {
                $match: {
                    businessId,
                    $or: [
                        { 'ourData.messageType': { $ne: '' } },
                        { 'ourData.text': { $ne: '' } }
                    ]
                }
            },
            {
                $project: {
                    month: { $dateToString: { format: "%Y-%m", date: "$received_at" } }
                }
            },
            {
                $group: {
                    _id: "$month",
                    count: { $sum: 1 }
                }
            },
            { $sort: { _id: 1 } }
        ]);

        // Prepare the response with alternating colors
        const response = monthlyMessageCount.map((item, index) => {
            const monthNames = [
                "January", "February", "March", "April", "May", "June",
                "July", "August", "September", "October", "November", "December"
            ];

            const yearMonth = item._id.split('-');
            const year = yearMonth[0];
            const monthIndex = parseInt(yearMonth[1], 10) - 1;
            const monthName = `${monthNames[monthIndex]} ${year}`;

            const formattedItem = {
                amount: item.count.toLocaleString(),
                month: monthName,
                color: index % 2 === 0 ? 'bg-[#E3F5FF]' : 'bg-[#E5ECF6]'
            };

            return formattedItem;
        });

        return res.status(200).json(response);
    } catch (error) {
        console.error('Error counting messages per month:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

// API endpoint to get total message count per month for each sender_id by businessId with alternating colors
app.get('/api/messages/count/employees', async (req, res) => {
    const { businessId } = req.query;

    if (!businessId) {
        return res.status(400).json({ error: 'Business ID is required' });
    }

    try {
        const monthlyMessageCount = await Message.aggregate([
            {
                $match: {
                    businessId,
                    $or: [
                        { 'ourData.messageType': { $ne: '' } },
                        { 'ourData.text': { $ne: '' } }
                    ]
                }
            },
            {
                $group: {
                    _id: {
                        month: { $dateToString: { format: "%Y-%m", date: "$received_at" } },
                        sender_id: "$metadata.sender_id"
                    },
                    count: { $sum: 1 }
                }
            },
            { $sort: { "_id.month": 1, "_id.sender_id": 1 } }
        ]);

        // Prepare the response with alternating colors and employeeId
        const response = monthlyMessageCount.map((item, index) => {
            const monthNames = [
                "January", "February", "March", "April", "May", "June",
                "July", "August", "September", "October", "November", "December"
            ];

            const yearMonth = item._id.month.split('-');
            const year = yearMonth[0];
            const monthIndex = parseInt(yearMonth[1], 10) - 1;
            const monthName = `${monthNames[monthIndex]} ${year}`;

            const formattedItem = {
                amount: item.count.toLocaleString(),
                month: monthName,
                color: index % 2 === 0 ? 'bg-[#E3F5FF]' : 'bg-[#E5ECF6]',
                employeeId: item._id.sender_id
            };

            return formattedItem;
        });

        return res.status(200).json(response);
    } catch (error) {
        console.error('Error counting messages per month:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Admin
app.get('/api/messages/count-empty-ourData', async (req, res) => {
    try {
        const count = await Message.countDocuments({
            $or: [
                { 'ourData.messageType': { $ne: '' } },
                { 'ourData.text': { $ne: '' } }
            ]
        });

        res.status(200).json({
            success: true,
            count,
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error occurred while counting messages',
            error: error.message
        });
    }
});

app.get('/api/messages/monthly-count-empty-ourData', async (req, res) => {
    try {
        const messageCounts = await Message.aggregate([
            {
                $match: {
                    $or: [
                        { 'ourData.messageType': { $ne: '' } },
                        { 'ourData.text': { $ne: '' } }
                    ]
                }
            },
            {
                $group: {
                    _id: {
                        month: { $dateToString: { format: "%Y-%m", date: "$received_at" } }
                    },
                    count: { $sum: 1 }
                }
            },
            { $sort: { "_id.month": 1 } }
        ]);

        // Prepare the response with alternating colors
        const response = messageCounts.map((item, index) => {
            const monthNames = [
                "January", "February", "March", "April", "May", "June",
                "July", "August", "September", "October", "November", "December"
            ];

            const yearMonth = item._id.month.split('-');
            const year = yearMonth[0];
            const monthIndex = parseInt(yearMonth[1], 10) - 1;
            const monthName = `${monthNames[monthIndex]} ${year}`;

            const formattedItem = {
                amount: item.count.toLocaleString(),
                month: monthName,
                color: index % 2 === 0 ? 'bg-[#E3F5FF]' : 'bg-[#E5ECF6]'
            };

            return formattedItem;
        });

        return res.status(200).json(response);
    } catch (error) {
        console.error('Error counting messages:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/messages/count-empty-ourData-by-business', async (req, res) => {
    try {
        const messageCounts = await Message.aggregate([
            {
                $match: {
                    $or: [
                        { 'ourData.messageType': { $ne: '' } },
                        { 'ourData.text': { $ne: '' } }
                    ]
                }
            },
            {
                $group: {
                    _id: "$businessId",
                    count: { $sum: 1 }
                }
            },
            { $sort: { "_id": 1 } }
        ]);

        // Prepare the response with alternating colors
        const response = messageCounts.map((item, index) => {
            const formattedItem = {
                amount: item.count.toLocaleString(),
                businessId: item._id,
                color: index % 2 === 0 ? 'bg-[#E3F5FF]' : 'bg-[#E5ECF6]'
            };

            return formattedItem;
        });

        return res.status(200).json(response);
    } catch (error) {
        console.error('Error counting messages:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/business/name', async (req, res) => {
    const { id } = req.query;  // Use 'id' instead of 'businessAccountId'

    if (!id) {
        return res.status(400).json({ error: 'User ID is required' });
    }

    try {
        const user = await User.findById(id);

        if (!user) {
            return res.status(404).json({ error: 'Business not found' });
        }

        return res.status(200).json({ businessName: user.businessName, id });
    } catch (error) {
        console.error('Error fetching business name:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

// News Letter
// Define the schema
const emailSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
});

const Email = mongoose.model('Email', emailSchema);

// Define routes
app.post('/subscribe', async (req, res) => {
    const { email } = req.body;

    try {
        // Check if the email is already in the database
        const existingEmail = await Email.findOne({ email });
        if (existingEmail) {
            return res.status(400).json({ message: 'Email already subscribed' });
        }

        // Save the email to the database
        const newEmail = new Email({ email });
        await newEmail.save();
        res.status(201).json({ message: 'Subscription successful' });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

app.get('/file-dataurl/:id/:fileName', (req, res) => {
    const { id, fileName } = req.params;

    const filePath = path.join(__dirname, 'public', id, fileName);

    // Check if file exists
    fs.access(filePath, fs.constants.F_OK, (err) => {
        if (err) {
            return res.status(404).send('File not found');
        }

        // Read the file
        fs.readFile(filePath, (err, data) => {
            if (err) {
                return res.status(500).send('Error reading file');
            }

            // Determine the file's MIME type (for example, 'image/jpeg')
            const mimeType = 'image/jpeg'; // Replace with actual MIME type detection if needed

            // Convert to Data URL
            const base64 = Buffer.from(data).toString('base64');
            const dataUrl = `data:${mimeType};base64,${base64}`;

            // Send the Data URL in the response
            res.send({ dataUrl });
        });
    });
});


app.get('/video/file-dataurl/:id/:fileName', (req, res) => {
    const { id, fileName } = req.params;

    const filePath = path.join(__dirname, 'public', id, fileName);

    // Check if file exists
    fs.access(filePath, fs.constants.F_OK, (err) => {
        if (err) {
            return res.status(404).send('File not found');
        }

        // Read the file
        fs.readFile(filePath, (err, data) => {
            if (err) {
                return res.status(500).send('Error reading file');
            }

            // Determine the file's MIME type (for example, 'image/jpeg')
            const mimeType = 'video/mp4'; // Replace with actual MIME type detection if needed

            // Convert to Data URL
            const base64 = Buffer.from(data).toString('base64');
            const dataUrl = `data:${mimeType};base64,${base64}`;

            // Send the Data URL in the response
            res.send({ dataUrl });
        });
    });
});

app.get('/audio/file-dataurl/:id/:fileName', (req, res) => {
    const { id, fileName } = req.params;

    const filePath = path.join(__dirname, 'public', id, fileName);

    // Check if file exists
    fs.access(filePath, fs.constants.F_OK, (err) => {
        if (err) {
            return res.status(404).send('File not found');
        }

        // Read the file
        fs.readFile(filePath, (err, data) => {
            if (err) {
                return res.status(500).send('Error reading file');
            }

            // Determine the file's MIME type (for example, 'image/jpeg')
            const mimeType = 'audio/mp3'; // Replace with actual MIME type detection if needed

            // Convert to Data URL
            const base64 = Buffer.from(data).toString('base64');
            const dataUrl = `data:${mimeType};base64,${base64}`;

            // Send the Data URL in the response
            res.send({ dataUrl });
        });
    });
});

const sendMessageMedia = async (recipientPhoneNumber, senderId, designation, conversationId, businessId, phon_no_id, phon_no, token, mediaId, type) => {
    let response;
    try {
        if (type == 'document') {
            response = await axios.post(
                `https://graph.facebook.com/v20.0/${phon_no_id}/messages`,
                {
                    messaging_product: 'whatsapp',
                    to: recipientPhoneNumber, // Recipient's phone number in international format
                    type: 'document',
                    document: { id: mediaId } // For sending document type
                },
                {
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                }
            );
        } else if (type == 'image') {
            response = await axios.post(
                `https://graph.facebook.com/v20.0/${phon_no_id}/messages`,
                {
                    messaging_product: 'whatsapp',
                    to: recipientPhoneNumber,
                    type: 'image', // Adjust based on the media type
                    image: { id: mediaId } // For other types, use 'document', 'video', etc.
                },
                {
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                }
            );
        } else if (type == 'video') {
            response = await axios.post(
                `https://graph.facebook.com/v20.0/${phon_no_id}/messages`,
                {
                    messaging_product: 'whatsapp',
                    to: recipientPhoneNumber,
                    type: 'video', // Adjust based on the media type
                    video: { id: mediaId } // For other types, use 'document', 'video', etc.
                },
                {
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                }
            );
        } else if (type == 'audio') {

            response = await axios.post(
                `https://graph.facebook.com/v20.0/${phon_no_id}/messages`,
                {
                    messaging_product: 'whatsapp',
                    recipient_type: "individual",
                    to: recipientPhoneNumber, // Recipient's phone number in international format
                    type: "audio",
                    audio: { id: mediaId } // For sending audio type
                },
                {
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                }
            );
        }

        const messageId = response.data.messages[0].id;

        const message = new Message({
            conversationId: conversationId,
            businessId, businessId,
            phone_no_id: phon_no,
            from: phon_no_id,
            to: recipientPhoneNumber,
            message_id: messageId,
            type: type,
            metadata: {
                sender_id: senderId,
                designation: designation,
            },
            ourData: {
                messageType: type,
                path: mediaId
            }
        });

        await message.save();
    } catch (error) {
        console.error("Error sending message:", error);
    }
}

const updateConversationMessageCountMedia = async (client, businessId, mediaId, type) => {

    let conversation = await Conversation.findOneAndUpdate(
        { participants: client, businessId: businessId },
        {
            lastMessageTime: new Date(),
            $inc: { messageCount: 1 },
            content: {
                mime_type: type,
                mediaId: mediaId
            },
        },
        { new: true }
    );

    if (!conversation) {
        conversation = new Conversation({
            businessId: businessId,
            participants: client,
            lastMessageTime: new Date(),
            messageCount: 1,
            content: {
                mime_type: type,
                mediaId: mediaId
            },
        });
        await conversation.save();
        return conversation._id;
    } else {
        return conversation._id;
    }
};

// API endpoint to send a message
app.post('/media/send-message', async (req, res) => {
    const { recipientPhoneNumber, senderId, designation, businessId, phon_no, phon_no_id, token, mediaId, type } = req.body;

    if (!recipientPhoneNumber || !senderId || !designation || !businessId || !phon_no || !phon_no_id || !token || !mediaId || !type) {
        return res.status(400).send('Missing required fields');
    }

    try {
        const conversationId = await updateConversationMessageCountMedia(recipientPhoneNumber, businessId, mediaId);
        await sendMessageMedia(recipientPhoneNumber, senderId, designation, conversationId, businessId, phon_no_id, phon_no, token, mediaId, type);
        io.emit('message', { id: conversationId, to: recipientPhoneNumber });

        res.status(200).send('Message sent and saved successfully');
    } catch (error) {
        console.log(error)
        res.status(500).send('Error sending message');
    }
});


app.post('/api/account', async (req, res) => {
    const { accessToken, accountId } = req.body;

    if (!accessToken || !accountId) {
        return res.status(400).send('Access token and Account ID are required.');
    }

    try {
        const response = await axios.get(`https://graph.facebook.com/v14.0/${accountId}`, {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });
        res.json(response.data);
    } catch (error) {
        console.error('Error fetching account info:', error);
        res.status(500).send('Error fetching account info');
    }
});

const businessSchema = new mongoose.Schema({
    name: {
        type: [String],
        required: true
    },
    businessId: {
        type: String,
        required: true,
    },
    contactNumbers: {
        type: [String],
        required: true
    }
}, {
    timestamps: true // This adds `createdAt` and `updatedAt` fields
});

const Business = mongoose.model('BulkImports', businessSchema);

app.post('/api/save-bulk-import/businesses', async (req, res) => {
    try {
        const { name, businessId, contactNumbers } = req.body;

        if (!name || !businessId || !contactNumbers || !Array.isArray(contactNumbers)) {
            return res.status(400).json({ message: 'Invalid input' });
        }

        const business = new Business({
            name,
            businessId,
            contactNumbers
        });

        await business.save();

        res.status(201).json({ message: 'Business saved successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});


// Route to fetch businesses by businessId
app.get('/api/data-bulk-import/:businessId', async (req, res) => {
    try {
        const { businessId } = req.params;
        const businesses = await Business.find({ businessId });

        if (!businesses.length) {
            return res.status(404).json({ message: 'No businesses found' });
        }
        res.json(businesses);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


// Delete business record
app.delete('/bulk-data-delete/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await Business.deleteOne({ businessId: id });
        if (result.deletedCount === 0) {
            return res.status(404).json({ message: 'Business not found' });
        }
        res.status(200).json({ message: 'Business deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
});

// Setup multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Bulk File Import
app.post('/import-bulk-contacts/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).send('No file uploaded.');
    }

    try {
        // Parse the uploaded file
        const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const data = xlsx.utils.sheet_to_json(sheet);

        // Extract contact numbers (assuming they are in a column named 'Contact Number')
        const contactNumbers = data.map(row => row['Contact Number']).filter(contact => contact);

        res.json({ contactNumbers });
    } catch (error) {
        res.status(500).send('Error processing the file.');
    }
});

const deleteFilesInDir = async (dir) => {
    const files = await readdir(dir);

    for (const file of files) {
        const filePath = path.join(dir, file);
        const stat = await fs.promises.lstat(filePath);
        if (stat.isDirectory()) {
            await deleteFilesInDir(filePath); // Recursively delete directory contents
            await rmdir(filePath); // Remove the empty directory
        } else {
            await unlink(filePath); // Remove the file
        }
    }
};

const deletePublicFolder = async () => {
    const publicDir = path.resolve('public');
    try {
        await deleteFilesInDir(publicDir);
    } catch (error) {
        console.error('Error deleting public folder contents:', error);
    }
};

// Define the schema for preDefinedMessages
const preDefinedMessageSchema = new mongoose.Schema({
    businessId: {
        type: String,
        required: true,
        trim: true,
    },
    name: {
        type: String,
        required: true,
        trim: true,
    },
    text: {
        type: String,
        required: true,
    },
}, { timestamps: true }); // Optionally add timestamps

// Create the model
const PreDefinedMessage = mongoose.model('PreDefinedMessage', preDefinedMessageSchema);

// Route to create a new pre-defined message
app.post('/pre-defined-messages', async (req, res) => {
    const { businessId, name, text } = req.body;

    // Validate request body
    if (!businessId || !name || !text) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const newMessage = new PreDefinedMessage({
            businessId,
            name,
            text,
        });

        await newMessage.save();
        res.status(201).json(newMessage);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Route to delete a pre-defined message by ID
app.delete('/pre-defined-messages/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const result = await PreDefinedMessage.findByIdAndDelete(id);

        if (!result) {
            return res.status(404).json({ message: 'Message not found' });
        }

        res.status(200).json({ message: 'Message deleted successfully' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Example route to get all predefined messages (previously defined)
app.get('/pre-defined-messages', async (req, res) => {
    try {
        const messages = await PreDefinedMessage.find();
        res.json(messages);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Example route to get all predefined messages (previously defined)
app.get('/pre-defined-messages/:businessId', async (req, res) => {
    try {
        const messages = await PreDefinedMessage.find();
        res.json(messages);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

const componentSchema = new mongoose.Schema({
    type: { type: String, required: true },
    text: { type: String },
    format: { type: String },
    buttons: [{
        type: { type: String },
        text: { type: String }
    }],
    example: {
        body_text: [[String]]
    },
    parameters: [{
        name: { type: String },
        type: { type: String }
    }],
    // Additional fields for specific component types
    header: {
        format: { type: String },
        text: { type: String }
    },
    body: {
        text: { type: String },
        example: {
            body_text: [[String]]
        }
    },
    footer: {
        text: { type: String }
    },
    buttons: [{
        type: { type: String },
        text: { type: String }
    }]
}, { _id: false });

const templateSchema = new mongoose.Schema({
    accountId: { type: String, required: true },
    templateName: { type: String, default: '' },
    templateId: { type: String, required: true, unique: true },
    name: { type: String },
    components: [componentSchema],
    language: { type: String },
    status: { type: String },
    category: { type: String }
}, { timestamps: true });

const Template = mongoose.model('Template', templateSchema);

app.post('/get-templates', async (req, res) => {
    const { business_id, token, accountId } = req.body;

    if (!business_id || !token || !accountId) {
        return res.status(400).json({ error: 'Business ID, token, and account ID are required' });
    }

    try {
        const response = await axios.get(`https://graph.facebook.com/v16.0/${business_id}/message_templates`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const templates = response.data.data;

        const savePromises = templates.map(async (template) => {
            const componentsWithParams = template.components.map(component => {
                const parameters = extractParameters(component.text || '');

                let componentDetails = {
                    type: component.type,
                    text: component.text,
                    format: component.format,
                    example: component.example,
                    parameters: parameters.length > 0 ? parameters : undefined
                };

                // Set specific fields based on component type
                if (component.type === 'HEADER') {
                    componentDetails.header = {
                        format: component.format,
                        text: component.text
                    };
                } else if (component.type === 'BODY') {
                    componentDetails.body = {
                        text: component.text,
                        example: component.example
                    };
                } else if (component.type === 'FOOTER') {
                    componentDetails.footer = {
                        text: component.text
                    };
                } else if (component.type === 'BUTTONS') {
                    componentDetails.buttons = component.buttons;
                }

                return componentDetails;
            });

            return Template.updateOne(
                { templateId: template.id, accountId },
                {
                    name: template.name,
                    components: componentsWithParams,
                    language: template.language,
                    status: template.status,
                    category: template.category
                },
                { upsert: true }
            );
        });

        await Promise.all(savePromises);

        res.json({ message: 'Templates processed and saved successfully' });
    } catch (error) {
        console.error('Error fetching or saving templates:', error);
        res.status(error.response?.status || 500).json({
            error: error.response?.data?.error?.message || 'Internal Server Error'
        });
    }
});

const extractParameters = (text) => {
    const parameterPattern = /{{(\d+)}}/g;
    const parameters = [];
    let match;

    while ((match = parameterPattern.exec(text)) !== null) {
        const paramName = `param_${match[1]}`;
        if (!parameters.find(param => param.name === paramName)) {
            parameters.push({
                name: paramName,
                type: 'string' // You might need a more sophisticated type inference mechanism
            });
        }
    }

    return parameters;
};


// Fetch all templates by accountId
app.get('/templates/:accountId', async (req, res) => {
    try {
        const { accountId } = req.params;
        const templates = await Template.find({ accountId });
        res.status(200).json(templates);
    } catch (error) {
        res.status(500).json({ message: 'Server Error', error });
    }
});

// Update the templateName of a template by ID
app.put('/templates/:id/update-name', async (req, res) => {
    const { id } = req.params;
    const { newTemplateName } = req.body;

    try {
        // Validate input
        if (!newTemplateName) {
            return res.status(400).json({ message: 'New template name is required' });
        }

        // Find the template by ID and update the name
        const updatedTemplate = await Template.findByIdAndUpdate(
            id,
            { templateName: newTemplateName },
            { new: true } // Return the updated document
        );

        if (!updatedTemplate) {
            return res.status(404).json({ message: 'Template not found' });
        }

        res.status(200).json(updatedTemplate);
    } catch (error) {
        res.status(500).json({ message: 'Server Error', error });
    }
});

app.get('/names-templates/:accountId', async (req, res) => {
    try {
        const accountId = req.params.accountId;
        const templates = await Template.find({ accountId }, 'name');
        const templateNames = templates.map(template => template.name);
        res.json(templateNames);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/template-details', async (req, res) => {
    const { name, accountId } = req.query;

    if (!name || !accountId) {
        return res.status(400).json({ error: 'Name and account ID are required' });
    }

    try {
        const template = await Template.findOne({ name: name, accountId });

        if (!template) {
            return res.status(404).json({ error: 'Template not found' });
        }

        res.json(template);
    } catch (error) {
        console.error('Error fetching template details:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Endpoint to send notifications to multiple device tokens
app.post('/send-notification', async (req, res) => {
    const { title, body, tokens } = req.body;

    if (!Array.isArray(tokens) || tokens.length === 0) {
        return res.status(400).json({ success: false, error: 'No tokens provided' });
    }

    const message = {
        notification: {
            title,
            body,
        },
        tokens, // This should be an array of tokens
    };

    try {
        // Send the notification to multiple tokens
        const response = await admin.messaging().sendMulticast(message);
        console.log('Notification sent successfully:', response);
        res.status(200).json({ success: true, response });
    } catch (error) {
        console.error('Error sending notification:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// API endpoint to return all tokens
app.get('/tokens-all-tokens', async (req, res) => {
    try {
        // Fetch all tokens from the collection
        const tokens = await Token.find().select('token -_id'); // Select only the 'token' field and exclude '_id'
        // Map the results to an array of token strings
        const tokenArray = tokens.map(doc => doc.token);
        res.status(200).json(tokenArray);
    } catch (error) {
        console.error('Error fetching tokens:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Flow
const ButtonSchema = new mongoose.Schema({
    label: { type: String, required: true },
    type: { type: String, required: true }
});

const ConnectionSchema = new mongoose.Schema({
    target: { type: String, required: true },
    label: { type: String, required: true }
});

const NodeSchema = new mongoose.Schema({
    id: { type: String, required: true },
    position: {
        x: { type: Number, required: true },
        y: { type: Number, required: true }
    },
    title: { type: String, required: true },
    body: { type: String, default: "" },
    footer: { type: String, default: "" },
    buttons: [ButtonSchema],
    connections: [ConnectionSchema]
});

const EdgeSchema = new mongoose.Schema({
    source: { type: String, required: true },
    target: { type: String, required: true },
    label: { type: String, required: true },
    animated: { type: Boolean, default: false },
    id: { type: String, required: true }
});

const FlowSchema = new mongoose.Schema({
    businessId: { type: String, required: true },
    flowName: { type: String, required: true },
    nodes: [NodeSchema],
    edges: [EdgeSchema],
    originalData: {
        nodes: { type: Array, required: true },
        edges: { type: Array, required: true }
    },
    status: { type: String, enum: ['active', 'inactive'], default: 'inactive' } // Add status field
});

const Flow = mongoose.model('Flow', FlowSchema);

// API to save flow data
app.post('/api/flows', async (req, res) => {
    try {
        const { flowName, nodes, edges, originalData, businessId } = req.body; // Destructure flowName
        const flowData = { flowName, nodes, edges, originalData, businessId }; // Prepare data to save
        const flow = new Flow(flowData);
        await flow.save();
        res.status(201).json({ message: 'Flow saved successfully', flow });
    } catch (error) {
        res.status(400).json({ message: 'Error saving flow', error: error.message });
    }
});

app.get('/api/flows/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const flows = await Flow.find({ businessId: id }); // Get all flows
        res.status(200).json(flows);
    } catch (error) {
        res.status(500).json({ message: 'Error retrieving flows', error: error.message });
    }
});

app.delete('/api/flows/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const flow = await Flow.findByIdAndDelete(id); // Delete flow by ID

        if (!flow) {
            return res.status(404).json({ message: 'Flow not found' });
        }

        res.status(200).json({ message: 'Flow deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error deleting flow', error: error.message });
    }
});

// API to update the status of a flow
app.patch('/api/flows/:id', async (req, res) => {
    try {
        const { status } = req.body;

        // Fetch the flow by ID
        const flow = await Flow.findById(req.params.id);

        if (!flow) {
            return res.status(404).json({ message: 'Flow not found' });
        }

        const { businessId, nodes, edges } = flow;

        // Validation: Only proceed if status is being set to 'active'
        if (status === 'active') {
            // Validation: There should be more than one node
            if (nodes.length <= 1) {
                return res.status(400).json({ message: 'Cannot activate flow: There must be more than one node.' });
            }

            // Validation: Each node must have at least one connection
            const connectedNodes = new Set();
            edges.forEach(edge => {
                connectedNodes.add(edge.source);
                connectedNodes.add(edge.target);
            });

            const unconnectedNodes = nodes.filter(node => !connectedNodes.has(node.id));
            if (unconnectedNodes.length > 0) {
                return res.status(400).json({ message: 'Cannot activate flow: Some nodes are not connected.' });
            }

            // Deactivate all other flows for the same businessId
            await Flow.updateMany(
                { businessId, _id: { $ne: flow._id } }, // Find all flows with the same businessId except the current one
                { status: 'inactive' } // Set their status to inactive
            );
        }

        // Update the current flow's status
        flow.status = status;
        await flow.save();

        res.status(200).json({ message: 'Flow status updated successfully', flow });
    } catch (error) {
        res.status(500).json({ message: 'Error updating flow status', error: error.message });
    }
});


// Update Flow by ID
app.put('/api/flows/edit/:id', async (req, res) => {
    const { id } = req.params;
    const updateData = req.body;

    try {
        // Find Flow by ID and update it with the new data
        const updatedFlow = await Flow.findByIdAndUpdate(id, updateData, {
            new: true, // return the updated document
            runValidators: true // validate against schema
        });

        if (!updatedFlow) {
            return res.status(404).json({ message: 'Flow not found' });
        }

        return res.status(200).json(updatedFlow);
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});
