import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { Client } from "pg";
import dotenv from "dotenv";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const schemaPath = path.resolve(__dirname, "../db/schema.sql");

const {
  DATABASE_URL,
  PGHOST,
  PGPORT,
  PGUSER,
  PGPASSWORD,
  PGDATABASE,
  PGSSLMODE,
} = process.env;

if (
  !DATABASE_URL &&
  !(PGHOST && PGPORT && PGUSER && PGPASSWORD && PGDATABASE)
) {
  console.error(
    "Database connection variables are missing. Provide DATABASE_URL or the PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE set.",
  );
  process.exit(1);
}

const dbConfig = DATABASE_URL
  ? {
      connectionString: DATABASE_URL,
      ssl:
        PGSSLMODE === "disable"
          ? false
          : {
              rejectUnauthorized: false,
            },
    }
  : {
      host: PGHOST,
      port: Number(PGPORT),
      user: PGUSER,
      password: PGPASSWORD,
      database: PGDATABASE,
      ssl:
        PGSSLMODE === "require"
          ? {
              rejectUnauthorized: false,
            }
          : false,
    };

async function applySchema() {
  const client = new Client(dbConfig);
  try {
    await client.connect();
    const schemaSql = fs.readFileSync(schemaPath, "utf8");
    await client.query(schemaSql);
    console.log("Database schema applied successfully.");
  } catch (error) {
    console.error("Failed to apply schema:", error.message);
    process.exitCode = 1;
  } finally {
    await client.end().catch(() => {});
  }
}

applySchema();
