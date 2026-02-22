require('dotenv').config();
const pool = require('./db');

async function setup() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS "session" (
      "sid" VARCHAR NOT NULL PRIMARY KEY,
      "sess" JSON NOT NULL,
      "expire" TIMESTAMP(6) NOT NULL
    );
    CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");

    CREATE TABLE IF NOT EXISTS "users" (
      "id" SERIAL PRIMARY KEY,
      "first_name" VARCHAR(100) NOT NULL,
      "last_name" VARCHAR(100) NOT NULL,
      "company_name" VARCHAR(200),
      "username" VARCHAR(100) NOT NULL UNIQUE,
      "password_hash" VARCHAR(255) NOT NULL,
      "ebay_token" TEXT,
      "google_vision_key" TEXT,
      "openai_api_key" TEXT,
      "openai_model" VARCHAR(50) DEFAULT 'gpt-5.2',
      "ebay_client_id" TEXT,
      "ebay_client_secret" TEXT,
      "created_at" TIMESTAMP DEFAULT NOW(),
      "updated_at" TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('Database tables created successfully.');
  await pool.end();
}

setup().catch((err) => {
  console.error('Setup failed:', err);
  process.exit(1);
});
