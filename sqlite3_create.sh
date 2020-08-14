mkdir -p db
cd db
sqlite3 data.sqlite "

CREATE TABLE IF NOT EXISTS user (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE,
  encoded_password TEXT,
  left_salt TEXT,
  right_salt TEXT,
  scrypt_n INTEGER,
  scrypt_r INTEGER,
  scrypt_p INTEGER,
  created_time INTEGER
);

CREATE TABLE IF NOT EXISTS user_session (
  user_id TEXT PRIMARY KEY,
  session_token TEXT,
  created_time INTEGER
);

"
