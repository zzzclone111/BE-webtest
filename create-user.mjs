import bcrypt from "bcryptjs";
import pg from "pg";
import dotenv from "dotenv";

dotenv.config();

const { Pool } = pg;

const username = process.argv[2];
const password = process.argv[3];
const roleName = process.argv[4];

if (!username || !password || !roleName) {
  console.error(
    "Usage: node create-user.mjs <username> <password> <role>"
  );
  process.exit(1);
}

async function main() {
  const pool = new Pool({
    connectionString: process.env.DB_URI,
  });

  try {
    const roleResult = await pool.query(
      `
      SELECT id
      FROM roles
      WHERE name = $1
      `,
      [roleName]
    );

    if (roleResult.rows.length === 0) {
      throw new Error(`Role "${roleName}" không tồn tại`);
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `
      INSERT INTO users
        (username, password_hash, role_id)
      VALUES
        ($1, $2, $3)
      RETURNING id, username, role_id, is_active
      `,
      [
        username,
        passwordHash,
        roleResult.rows[0].id,
      ]
    );

    console.log("User created:");
    console.log(result.rows[0]);

  } catch (error) {
    if (error.code === "23505") {
      console.error("Username đã tồn tại");
      process.exitCode = 1;
    } else {
      console.error("Create user failed:", error.message);
      process.exitCode = 1;
    }
  } finally {
    await pool.end();
  }
}

main();
