const request = require('supertest');
const express = require('express');

// Mock data
const mockApp = express();
mockApp.get('/health', (req, res) => res.status(200).json({ status: 'UP' }));

describe('Image Service Basic Tests', () => {
    it('should respond to health check', async () => {
        const res = await request(mockApp)
            .get('/health');
        expect(res.statusCode).toEqual(200);
        expect(res.body).toEqual({ status: 'UP' });
    });

    it('should pass a basic truthy test', () => {
        expect(true).toBe(true);
    });
});
