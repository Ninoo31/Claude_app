import type { Config } from 'drizzle-kit';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

if (!process.env.MASTER_DATABASE_URL) {
  throw new Error('MASTER_DATABASE_URL environment variable is required');
}

export default {
  schema: [
    './src/database/schemas/master.schema.ts',
    './src/database/schemas/tenant.schema.ts'
  ],
  out: './src/database/migrations',
  driver: 'pg',
  dbCredentials: {
    connectionString: process.env.MASTER_DATABASE_URL,
  },
  verbose: true,
  strict: true,
  migrations: {
    prefix: 'timestamp',
    table: 'migrations',
    schema: 'public',
  },
} satisfies Config;