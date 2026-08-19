import express from "express";
import cors from "cors";
import pg from "pg";
import redis from "redis";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import bcrypt from "bcryptjs";

dotenv.config();

const { Pool } = pg;

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(cookieParser());

if (!process.env.DB_URI) {
  console.error("ERROR: DB_URI chưa được cấu hình trong .env");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DB_URI,
});


let redisClient = null;

function connectRedis() {
  if (!process.env.REDIS_URL) {
    console.warn(
      "WARNING: REDIS_URL chưa được cấu hình. Redis cache sẽ bị tắt."
    );
    return;
  }

  try {
    redisClient = redis.createClient(
      process.env.REDIS_URL
    );

    redisClient.on("ready", () => {
      console.log("Redis connected");
    });

    redisClient.on("error", (err) => {
      console.error(
        "Redis error:",
        err.message
      );
    });

    redisClient.on("end", () => {
      console.log("Redis connection closed");
    });

  } catch (error) {
    console.error(
      "Redis initialization failed:",
      error.message
    );

    redisClient = null;
  }
}

const PRODUCT_CACHE_PREFIX = "products:";

const SESSION_PREFIX = "session:";
const SESSION_TTL = 60 * 60 * 8; // 8 giờ

function createSession(user) {
  return new Promise((resolve, reject) => {
    if (!redisClient) {
      return reject(new Error("Redis is not available"));
    }

    const sessionId = crypto.randomBytes(32).toString("hex");

    const sessionData = {
      userId: user.id,
      username: user.username,
      role: user.role,
    };

    redisClient.setex(
      `${SESSION_PREFIX}${sessionId}`,
      SESSION_TTL,
      JSON.stringify(sessionData),
      (err) => {
        if (err) {
          reject(err);
          return;
        }

        resolve(sessionId);
      }
    );
  });
}

function getSession(sessionId) {
  return new Promise((resolve) => {
    if (!redisClient || !sessionId) {
      resolve(null);
      return;
    }

    redisClient.get(
      `${SESSION_PREFIX}${sessionId}`,
      (err, value) => {
        if (err || !value) {
          resolve(null);
          return;
        }

        try {
          resolve(JSON.parse(value));
        } catch {
          resolve(null);
        }
      }
    );
  });
}

async function requireAuth(req, res, next) {
  try {
    const sessionId = req.cookies.session_id;

    if (!sessionId) {
      return res.status(401).json({
        error: "Bạn chưa đăng nhập",
      });
    }

    const session = await getSession(sessionId);

    if (!session) {
      return res.status(401).json({
        error: "Phiên đăng nhập không hợp lệ hoặc đã hết hạn",
      });
    }

    req.user = session;

    next();
  } catch (error) {
    console.error("Authentication error:", error);

    res.status(500).json({
      error: "Không thể xác thực người dùng",
    });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: "Bạn chưa đăng nhập",
      });
    }

    if (req.user.role !== role) {
      return res.status(403).json({
        error: "Bạn không có quyền thực hiện thao tác này",
      });
    }

    next();
  };
}

function clearProductCache() {
  return new Promise((resolve) => {
    if (!redisClient) {
      resolve();
      return;
    }

    redisClient.keys(
      `${PRODUCT_CACHE_PREFIX}*`,
      (err, keys) => {

        if (err) {
          console.error(
            "Redis KEYS error:",
            err.message
          );

          resolve();
          return;
        }

        if (!keys || keys.length === 0) {
          resolve();
          return;
        }

        redisClient.del(
          keys,
          (deleteErr) => {

            if (deleteErr) {
              console.error(
                "Redis DEL error:",
                deleteErr.message
              );
            } else {
              console.log(
                `Redis cache cleared: ${keys.length} key(s)`
              );
            }

            resolve();
          }
        );
      }
    );
  });
}

function getRedisCache(key) {
  return new Promise((resolve) => {

    if (!redisClient) {
      resolve(null);
      return;
    }

    redisClient.get(
      key,
      (err, value) => {

        if (err) {
          console.error(
            "Redis GET error:",
            err.message
          );

          resolve(null);
          return;
        }

        resolve(value);
      }
    );
  });
}


function setRedisCache(key, value) {
  return new Promise((resolve) => {

    if (!redisClient) {
      resolve();
      return;
    }

    // Cache tồn tại 60 giây
    redisClient.setex(
      key,
      60,
      JSON.stringify(value),
      (err) => {

        if (err) {
          console.error(
            "Redis SET error:",
            err.message
          );
        } else {
          console.log(
            `Redis cache SET: ${key}`
          );
        }

        resolve();
      }
    );
  });
}


app.get("/api/health", async (req, res) => {

  let database = "unknown";
  let redisStatus = "disabled";

  // PostgreSQL
  try {
    await pool.query("SELECT 1");
    database = "ok";
  } catch (error) {
    database = "error";
  }

  // Redis
  if (redisClient) {

    try {

      const redisPing = await new Promise(
        (resolve, reject) => {

          redisClient.ping(
            (err, result) => {

              if (err) {
                reject(err);
              } else {
                resolve(result);
              }

            }
          );

        }
      );

      if (redisPing === "PONG") {
        redisStatus = "ok";
      } else {
        redisStatus = "error";
      }

    } catch (error) {

      redisStatus = "error";

    }
  }

  res.json({
    status: "ok",
    database,
    redis: redisStatus,
  });
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error: "Vui lòng nhập username và password",
      });
    }

    const result = await pool.query(
      `
      SELECT
        u.id,
        u.username,
        u.password_hash,
        u.is_active,
        r.name AS role
      FROM users u
      JOIN roles r ON r.id = u.role_id
      WHERE u.username = $1
      `,
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Username hoặc password không đúng",
      });
    }

    const user = result.rows[0];

    if (!user.is_active) {
      return res.status(403).json({
        error: "Tài khoản đã bị khóa",
      });
    }

    const passwordValid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordValid) {
      return res.status(401).json({
        error: "Username hoặc password không đúng",
      });
    }

    const sessionId = await createSession(user);

    res.cookie("session_id", sessionId, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: SESSION_TTL * 1000,
    });

    res.json({
      message: "Đăng nhập thành công",
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
    });

  } catch (error) {
    console.error("POST /api/login error:", error);

    res.status(500).json({
      error: "Không thể đăng nhập",
    });
  }
});

app.get("/api/me", async (req, res) => {
  try {
    const sessionId = req.cookies.session_id;

    const session = await getSession(sessionId);

    if (!session) {
      return res.status(401).json({
        error: "Chưa đăng nhập",
      });
    }

    res.json({
      user: session,
    });

  } catch (error) {
    console.error("GET /api/me error:", error);

    res.status(500).json({
      error: "Không thể kiểm tra phiên đăng nhập",
    });
  }
});

app.post("/api/logout", async (req, res) => {
  try {
    const sessionId = req.cookies.session_id;

    if (redisClient && sessionId) {
      redisClient.del(`${SESSION_PREFIX}${sessionId}`);
    }

    res.clearCookie("session_id");

    res.json({
      message: "Đăng xuất thành công",
    });

  } catch (error) {
    console.error("POST /api/logout error:", error);

    res.status(500).json({
      error: "Không thể đăng xuất",
    });
  }
});

app.get("/api/products", requireAuth, async (req, res) => {
  try {

    let page = parseInt(
      req.query.page,
      10
    ) || 1;

    let limit = parseInt(
      req.query.limit,
      10
    ) || 10;

    if (page < 1) {
      page = 1;
    }

    if (limit < 1) {
      limit = 10;
    }

    if (limit > 100) {
      limit = 100;
    }


    const offset =
      (page - 1) * limit;


    const cacheKey =
      `${PRODUCT_CACHE_PREFIX}page=${page}:limit=${limit}`;


    const cached =
      await getRedisCache(cacheKey);


    if (cached) {

      console.log(
        `Redis cache HIT: ${cacheKey}`
      );

      try {

        return res.json(
          JSON.parse(cached)
        );

      } catch (error) {

        console.error(
          "Redis JSON parse error:",
          error.message
        );

      }
    }


    console.log(
      `Redis cache MISS: ${cacheKey}`
    );


    const countResult =
      await pool.query(
        "SELECT COUNT(*) FROM products"
      );


    const total =
      parseInt(
        countResult.rows[0].count,
        10
      );


    const result =
      await pool.query(
        `
        SELECT
          id,
          sku,
          name,
          category,
          quantity,
          unit,
          price,
          description,
          created_at,
          updated_at
        FROM products
        ORDER BY id DESC
        LIMIT $1
        OFFSET $2
        `,
        [
          limit,
          offset
        ]
      );


    const totalPages =
      total === 0
        ? 0
        : Math.ceil(
            total / limit
          );


    const responseData = {

      data: result.rows,

      pagination: {
        page,
        limit,
        total,
        totalPages,
      },

    };


    await setRedisCache(
      cacheKey,
      responseData
    );


    res.json(responseData);

  } catch (error) {

    console.error(
      "GET /api/products error:",
      error
    );

    res.status(500).json({
      error:
        "Không thể lấy danh sách sản phẩm",
    });

  }

});


app.get(
  "/api/products/:id",
  requireAuth,
  async (req, res) => {

    try {

      const { id } = req.params;


      const result =
        await pool.query(
          `
          SELECT *
          FROM products
          WHERE id = $1
          `,
          [id]
        );


      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          error:
            "Không tìm thấy sản phẩm",
        });

      }


      res.json(
        result.rows[0]
      );

    } catch (error) {

      console.error(
        "GET /api/products/:id error:",
        error
      );

      res.status(500).json({
        error:
          "Không thể lấy sản phẩm",
      });

    }

  }
);

app.post(
  "/api/products",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {

    try {

      const {
        sku,
        name,
        category,
        quantity,
        unit,
        price,
        description,
      } = req.body;


      if (
        !sku ||
        !name ||
        !category ||
        quantity === undefined ||
        !unit ||
        price === undefined
      ) {

        return res.status(400).json({
          error:
            "Vui lòng nhập đầy đủ thông tin sản phẩm",
        });

      }

      const result =
        await pool.query(
          `
          INSERT INTO products
          (
            sku,
            name,
            category,
            quantity,
            unit,
            price,
            description
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7
          )
          RETURNING *
          `,
          [
            sku,
            name,
            category,
            quantity,
            unit,
            price,
            description || null,
          ]
        );


      const product =
        result.rows[0];

      await clearProductCache();


      res.status(201).json({

        message:
          "Thêm sản phẩm thành công",

        product,

      });

    } catch (error) {

      console.error(
        "POST /api/products error:",
        error
      );


      // Duplicate SKU
      if (
        error.code === "23505"
      ) {

        return res.status(409).json({
          error:
            "SKU đã tồn tại",
        });

      }


      res.status(500).json({
        error:
          "Không thể thêm sản phẩm",
      });

    }

  }
);

app.put(
  "/api/products/:id",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {

    try {

      const { id } =
        req.params;


      const {
        sku,
        name,
        category,
        quantity,
        unit,
        price,
        description,
      } = req.body;

      if (
        !sku ||
        !name ||
        !category ||
        quantity === undefined ||
        !unit ||
        price === undefined
      ) {

        return res.status(400).json({
          error:
            "Vui lòng nhập đầy đủ thông tin sản phẩm",
        });

      }


      const result =
        await pool.query(
          `
          UPDATE products
          SET
            sku = $1,
            name = $2,
            category = $3,
            quantity = $4,
            unit = $5,
            price = $6,
            description = $7,
            updated_at = NOW()
          WHERE id = $8
          RETURNING *
          `,
          [
            sku,
            name,
            category,
            quantity,
            unit,
            price,
            description || null,
            id,
          ]
        );


      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          error:
            "Không tìm thấy sản phẩm",
        });

      }


      const product =
        result.rows[0];


      await clearProductCache();


      res.json({

        message:
          "Cập nhật sản phẩm thành công",

        product,

      });

    } catch (error) {

      console.error(
        "PUT /api/products/:id error:",
        error
      );


      if (
        error.code === "23505"
      ) {

        return res.status(409).json({
          error:
            "SKU đã tồn tại",
        });

      }


      res.status(500).json({
        error:
          "Không thể cập nhật sản phẩm",
      });

    }

  }
);

app.delete(
  "/api/products/:id",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {

    try {

      const { id } =
        req.params;


      const result =
        await pool.query(
          `
          DELETE FROM products
          WHERE id = $1
          RETURNING *
          `,
          [id]
        );


      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          error:
            "Không tìm thấy sản phẩm",
        });

      }


      const product =
        result.rows[0];


      await clearProductCache();


      res.json({

        message:
          "Xóa sản phẩm thành công",

        product,

      });

    } catch (error) {

      console.error(
        "DELETE /api/products/:id error:",
        error
      );


      res.status(500).json({
        error:
          "Không thể xóa sản phẩm",
      });

    }

  }
);

async function startServer() {

  try {

    await pool.query(
      "SELECT 1"
    );

    console.log(
      "PostgreSQL connected"
    );

    connectRedis();

    app.listen(
      PORT,
      "0.0.0.0",
      () => {

        console.log(
          `Backend listening on port ${PORT}`
        );

      }
    );

  } catch (error) {

    console.error(
      "Cannot start backend:",
      error
    );

    process.exit(1);

  }

}


startServer();
