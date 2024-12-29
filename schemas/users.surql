DEFINE TABLE OVERWRITE users SCHEMAFULL;

DEFINE FIELD OVERWRITE username ON users TYPE string;
DEFINE INDEX OVERWRITE unique_username ON users FIELDS username UNIQUE;

DEFINE FIELD OVERWRITE password_hash ON users TYPE string;
DEFINE FIELD OVERWRITE user_permissions ON users TYPE array<string>;
DEFINE FIELD OVERWRITE bio ON users TYPE option<string>;
DEFINE FIELD OVERWRITE avatar_url ON users TYPE option<string> ASSERT $value.is_url();
DEFINE FIELD OVERWRITE display_name ON users TYPE option<string>;