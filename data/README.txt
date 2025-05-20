Create the database with the schema:

CREATE TABLE activities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    activity TEXT NOT NULL,
    reflection TEXT,
    status TEXT,
    timestamp TEXT
);
