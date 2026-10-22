
const Database = require("better-sqlite3");

const db = new Database("omnimun.db");

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT,
 email TEXT UNIQUE,
 password TEXT,
 google_id TEXT,
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS projects(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER,
 name TEXT,
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS chats(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER,
 project_id INTEGER,
 title TEXT,
 content TEXT,
 pinned INTEGER DEFAULT 0,
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS library(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER,
 filename TEXT,
 filepath TEXT,
 pinned INTEGER DEFAULT 0,
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);

module.exports = db;
