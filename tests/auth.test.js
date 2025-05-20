const request = require('supertest');

const baseURL = 'http://alhost:8080';

describe('Auth & Task API Tests', () => {
  let accessToken = '';
  let refreshToken = '';

  // Sign-in
  describe('POST /auth/signin', () => {
    it('should return access and refresh tokens with valid credentials', async () => {
      const res = await request(baseURL)
        .post('/auth/signin')
        .send({ username: 'username', password: 'password' });

      expect(res.statusCode).toBe(200);
      expect(res.body).toHaveProperty('access_token');
      expect(res.body).toHaveProperty('refresh_token');

      accessToken = res.body.access_token;
      refreshToken = res.body.refresh_token;
    });

    it('should return 401 with invalid credentials', async () => {
      const res = await request(baseURL)
        .post('/auth/signin')
        .send({ username: 'wrong', password: 'wrong' });

      expect(res.statusCode).toBe(401);
      expect(res.body.message).toBe('Invalid credentials');
    });
  });

  // Token refresh
  describe('POST /auth/token', () => {
    it('should return new tokens with valid refresh token', async () => {
      const res = await request(baseURL)
        .post('/auth/token')
        .send({ refresh_token: refreshToken });

      expect(res.statusCode).toBe(201);
      expect(res.body).toHaveProperty('access_token');
      expect(res.body).toHaveProperty('refresh_token');

      accessToken = res.body.access_token;
      refreshToken = res.body.refresh_token;
    });

    it('should fail if refresh token is missing', async () => {
      const res = await request(baseURL)
        .post('/auth/token')
        .send({});

      expect(res.statusCode).toBe(400);
      expect(res.body.message).toBe('Missing refresh token');
    });

    it('should fail with invalid refresh token', async () => {
      const res = await request(baseURL)
        .post('/auth/token')
        .send({ refresh_token: 'invalid.token.here' });

      expect(res.statusCode).toBe(401);
      expect(res.body.message).toBe('Invalid or expired refresh token');
    });
  });

  // Task creation
  describe('POST /tasks/new', () => {
    it('should create a new task with valid token', async () => {
      const res = await request(baseURL)
        .post('/tasks/new')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ title: 'Write test cases' });

      expect(res.statusCode).toBe(201);
      expect(res.body).toHaveProperty('title', 'Write test cases');
      expect(res.body).toHaveProperty('created_by');
      expect(res.body).toHaveProperty('created_at');
    });

    it('should reject request without token', async () => {
      const res = await request(baseURL)
        .post('/tasks/new')
        .send({ title: 'No token' });

      expect(res.statusCode).toBe(403);
      expect(res.body.message).toBe('Missing token');
    });

    it('should reject request with invalid token', async () => {
      const res = await request(baseURL)
        .post('/tasks/new')
        .set('Authorization', 'Bearer fake.token.here')
        .send({ title: 'Bad token' });

      expect(res.statusCode).toBe(401);
      expect(res.body).toHaveProperty('message', 'Token error');
    });
  });

  // Sign-out
  describe('POST /auth/signout', () => {
    it('should sign out successfully', async () => {
      const res = await request(baseURL)
        .post('/auth/signout')
        .set('Authorization', `Bearer ${accessToken}`);

      expect(res.statusCode).toBe(200);
      expect(res.body.message).toBe('Logged out successfully');
    });

    it('should fail to sign out with missing token', async () => {
      const res = await request(baseURL)
        .post('/auth/signout');

      expect(res.statusCode).toBe(403);
      expect(res.body.message).toBe('Missing token');
    });

    it('should fail to sign out with invalid token', async () => {
      const res = await request(baseURL)
        .post('/auth/signout')
        .set('Authorization', 'Bearer fake.token.here');

      expect(res.statusCode).toBe(401);
      expect(res.body.message).toBe('Token error');
    });
  });
});
